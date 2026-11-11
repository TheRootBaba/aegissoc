import uuid
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Path, Query, Response, status
from fastapi.exceptions import RequestValidationError
from pydantic import ValidationError
from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.orm import Session

from app.core.security import require_roles
from app.db.session import get_db
from app.models import SecurityEvent
from app.schemas.events import (
    BulkEventIngest,
    BulkEventIngestResponse,
    SecurityEventCreate,
    SecurityEventRead,
)
from app.services.event_normalizer import normalize_event
from app.services.wazuh_adapter import normalize_wazuh_alert

router = APIRouter(
    prefix="/api/v1/events", tags=["events"],
    dependencies=[Depends(require_roles("admin", "analyst", "read_only"))],
)




def _persist_event(db: Session, payload: SecurityEventCreate) -> tuple[str, uuid.UUID]:
    """Insert once per (source, external_id), safely under concurrent retries.

    PostgreSQL is the production database and SQLite backs the isolated test
    suite. Both support ON CONFLICT DO NOTHING, so a replay racing another
    request cannot turn an otherwise successful ingest into a 500 response.
    """
    values = payload.model_dump()
    dialect = db.get_bind().dialect.name

    if dialect == "postgresql":
        statement = pg_insert(SecurityEvent).values(**values)
    elif dialect == "sqlite":
        statement = sqlite_insert(SecurityEvent).values(**values)
    else:
        if payload.external_id:
            existing_id = db.scalar(
                select(SecurityEvent.id).where(
                    SecurityEvent.source == payload.source,
                    SecurityEvent.external_id == payload.external_id,
                )
            )
            if existing_id is not None:
                return "duplicate", existing_id
        event = SecurityEvent(**values)
        db.add(event)
        db.flush()
        return "accepted", event.id

    event_id = db.scalar(
        statement.on_conflict_do_nothing(
            index_elements=[SecurityEvent.source, SecurityEvent.external_id]
        ).returning(SecurityEvent.id)
    )
    if event_id is not None:
        return "accepted", event_id

    existing_id = db.scalar(
        select(SecurityEvent.id).where(
            SecurityEvent.source == payload.source,
            SecurityEvent.external_id == payload.external_id,
        )
    )
    if existing_id is None:
        raise RuntimeError("Event insert conflicted but the existing event was not found")
    return "duplicate", existing_id


def _require_aware(value: datetime | None, parameter: str) -> datetime | None:
    if value is not None and (value.tzinfo is None or value.utcoffset() is None):
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=f"{parameter} must include a timezone offset")
    return value


@router.post("", response_model=SecurityEventRead, status_code=status.HTTP_201_CREATED,
             dependencies=[Depends(require_roles("admin", "analyst"))])
def ingest_event(payload: SecurityEventCreate, response: Response, db: Session = Depends(get_db)):
    outcome, event_id = _persist_event(db, payload)
    db.commit()
    if outcome == "duplicate":
        response.status_code = status.HTTP_200_OK
    return db.get(SecurityEvent, event_id)


@router.post("/ingest/{source}", response_model=SecurityEventRead, status_code=status.HTTP_201_CREATED,
             dependencies=[Depends(require_roles("admin", "analyst"))])
def ingest_normalized_event(payload: dict[str, Any], response: Response,
                            source: str = Path(min_length=1, max_length=80), db: Session = Depends(get_db)):
    try:
        normalized = normalize_wazuh_alert(payload) if source.lower() == "wazuh" else normalize_event(payload, source=source)
    except ValidationError as exc:
        raise RequestValidationError(exc.errors()) from exc
    except (ValueError, TypeError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    outcome, event_id = _persist_event(db, normalized)
    db.commit()
    if outcome == "duplicate":
        response.status_code = status.HTTP_200_OK
    return db.get(SecurityEvent, event_id)


@router.post(
    "/ingest/{source}/bulk",
    response_model=BulkEventIngestResponse,
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(require_roles("admin", "analyst"))],
)
def ingest_event_batch(
    batch: BulkEventIngest,
    source: str = Path(min_length=1, max_length=80),
    db: Session = Depends(get_db),
):
    """Normalize and ingest up to 500 source events with per-record outcomes.

    Valid records are committed together. Invalid records are reported by
    index without discarding valid siblings; duplicate source IDs resolve to
    the original event ID and do not create extra rows.
    """
    results = []
    accepted = duplicates = rejected = 0

    for index, raw_event in enumerate(batch.events):
        try:
            normalized = (
                normalize_wazuh_alert(raw_event)
                if source.lower() == "wazuh"
                else normalize_event(raw_event, source=source)
            )
            outcome, event_id = _persist_event(db, normalized)
            results.append({"index": index, "status": outcome, "event_id": event_id})
            if outcome == "accepted":
                accepted += 1
            else:
                duplicates += 1
        except (ValidationError, ValueError, TypeError) as exc:
            rejected += 1
            results.append({"index": index, "status": "rejected", "error": str(exc)})

    db.commit()
    return {
        "received": len(batch.events),
        "accepted": accepted,
        "duplicates": duplicates,
        "rejected": rejected,
        "results": results,
    }


@router.get("", response_model=list[SecurityEventRead])
def list_events(
    severity: str | None = Query(default=None, pattern="^(low|medium|high|critical|info)$"),
    source: str | None = Query(default=None, min_length=1, max_length=80),
    event_type: str | None = Query(default=None, min_length=1, max_length=120),
    hostname: str | None = Query(default=None, min_length=1, max_length=255),
    source_ip: str | None = Query(default=None, min_length=1, max_length=45),
    external_id: str | None = Query(default=None, min_length=1, max_length=128),
    start_time: datetime | None = Query(default=None, description="Inclusive event-time lower bound; must include a timezone"),
    end_time: datetime | None = Query(default=None, description="Inclusive event-time upper bound; must include a timezone"),
    limit: int = Query(default=50, ge=1, le=200), offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
):
    start_time = _require_aware(start_time, "start_time")
    end_time = _require_aware(end_time, "end_time")
    if start_time and end_time and start_time > end_time:
        raise HTTPException(status_code=422, detail="start_time must be earlier than or equal to end_time")
    statement = select(SecurityEvent)
    for column, value in ((SecurityEvent.severity, severity), (SecurityEvent.source, source),
                          (SecurityEvent.event_type, event_type), (SecurityEvent.hostname, hostname),
                          (SecurityEvent.source_ip, source_ip), (SecurityEvent.external_id, external_id)):
        if value is not None:
            statement = statement.where(column == value)
    if start_time is not None:
        statement = statement.where(SecurityEvent.timestamp >= start_time)
    if end_time is not None:
        statement = statement.where(SecurityEvent.timestamp <= end_time)
    statement = statement.order_by(SecurityEvent.timestamp.desc(), SecurityEvent.id.desc()).offset(offset).limit(limit)
    return list(db.scalars(statement).all())


@router.get("/stats")
def event_stats(db: Session = Depends(get_db)):
    total = db.scalar(select(func.count()).select_from(SecurityEvent)) or 0
    severity_rows = db.execute(select(SecurityEvent.severity, func.count()).group_by(SecurityEvent.severity)).all()
    source_rows = db.execute(select(SecurityEvent.source, func.count()).group_by(SecurityEvent.source)).all()
    return {"total_events": total, "by_severity": {key: count for key, count in severity_rows},
            "by_source": {key: count for key, count in source_rows}}


@router.get("/{event_id}", response_model=SecurityEventRead)
def get_event(event_id: uuid.UUID, db: Session = Depends(get_db)):
    event = db.get(SecurityEvent, event_id)
    if event is None:
        raise HTTPException(status_code=404, detail="Event not found")
    return event
