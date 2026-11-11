import uuid
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Path, Query, Response, status
from fastapi.exceptions import RequestValidationError
from pydantic import ValidationError
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.security import require_roles
from app.db.session import get_db
from app.models import SecurityEvent
from app.schemas.events import SecurityEventCreate, SecurityEventRead
from app.services.event_normalizer import normalize_event
from app.services.wazuh_adapter import normalize_wazuh_alert

router = APIRouter(
    prefix="/api/v1/events", tags=["events"],
    dependencies=[Depends(require_roles("admin", "analyst", "read_only"))],
)


def _require_aware(value: datetime | None, parameter: str) -> datetime | None:
    if value is not None and (value.tzinfo is None or value.utcoffset() is None):
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=f"{parameter} must include a timezone offset")
    return value


@router.post("", response_model=SecurityEventRead, status_code=status.HTTP_201_CREATED,
             dependencies=[Depends(require_roles("admin", "analyst"))])
def ingest_event(payload: SecurityEventCreate, response: Response, db: Session = Depends(get_db)):
    if payload.external_id:
        existing = db.scalar(select(SecurityEvent).where(SecurityEvent.source == payload.source, SecurityEvent.external_id == payload.external_id))
        if existing is not None:
            response.status_code = status.HTTP_200_OK
            return existing
    event = SecurityEvent(**payload.model_dump())
    db.add(event)
    db.commit()
    db.refresh(event)
    return event


@router.post("/ingest/{source}", response_model=SecurityEventRead, status_code=status.HTTP_201_CREATED,
             dependencies=[Depends(require_roles("admin", "analyst"))])
def ingest_normalized_event(payload: dict[str, Any], response: Response,
                            source: str = Path(min_length=1, max_length=80), db: Session = Depends(get_db)):
    try:
        normalized = normalize_wazuh_alert(payload) if source.lower() == "wazuh" else normalize_event(payload, source=source)
    except ValidationError as exc:
        raise RequestValidationError(exc.errors()) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    if normalized.external_id:
        existing = db.scalar(select(SecurityEvent).where(SecurityEvent.source == normalized.source, SecurityEvent.external_id == normalized.external_id))
        if existing is not None:
            response.status_code = status.HTTP_200_OK
            return existing
    event = SecurityEvent(**normalized.model_dump())
    db.add(event)
    db.commit()
    db.refresh(event)
    return event


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
