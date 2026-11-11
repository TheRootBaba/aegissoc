import uuid
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Path, Query, status
from fastapi.exceptions import RequestValidationError
from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models import SecurityEvent
from app.schemas.events import SecurityEventCreate, SecurityEventRead
from app.services.event_normalizer import normalize_event

router = APIRouter(prefix="/api/v1/events", tags=["events"])


def _require_aware(value: datetime | None, parameter: str) -> datetime | None:
    """Reject ambiguous local timestamps in event-search boundaries."""
    if value is not None and (value.tzinfo is None or value.utcoffset() is None):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"{parameter} must include a timezone offset",
        )
    return value


@router.post("", response_model=SecurityEventRead, status_code=status.HTTP_201_CREATED)
def ingest_event(payload: SecurityEventCreate, db: Session = Depends(get_db)):
    """Persist one validated security event."""
    event = SecurityEvent(**payload.model_dump())
    db.add(event)
    db.commit()
    db.refresh(event)
    return event


@router.post("/ingest/{source}", response_model=SecurityEventRead, status_code=status.HTTP_201_CREATED)
def ingest_normalized_event(
    payload: dict[str, Any],
    source: str = Path(min_length=1, max_length=80),
    db: Session = Depends(get_db),
):
    """Normalize a source-specific JSON event, then persist the canonical event."""
    try:
        normalized = normalize_event(payload, source=source)
    except ValidationError as exc:
        # Treat source-payload validation like normal FastAPI request validation.
        raise RequestValidationError(exc.errors()) from exc
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
    start_time: datetime | None = Query(default=None, description="Inclusive event-time lower bound; must include a timezone"),
    end_time: datetime | None = Query(default=None, description="Inclusive event-time upper bound; must include a timezone"),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
):
    """Search events using exact-match filters and bounded offset pagination."""
    start_time = _require_aware(start_time, "start_time")
    end_time = _require_aware(end_time, "end_time")
    if start_time and end_time and start_time > end_time:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="start_time must be earlier than or equal to end_time",
        )

    statement = select(SecurityEvent)
    filters = (
        (SecurityEvent.severity, severity),
        (SecurityEvent.source, source),
        (SecurityEvent.event_type, event_type),
        (SecurityEvent.hostname, hostname),
        (SecurityEvent.source_ip, source_ip),
    )
    for column, value in filters:
        if value is not None:
            statement = statement.where(column == value)
    if start_time is not None:
        statement = statement.where(SecurityEvent.timestamp >= start_time)
    if end_time is not None:
        statement = statement.where(SecurityEvent.timestamp <= end_time)

    # UUID tie-breaking keeps page boundaries deterministic for equal timestamps.
    statement = statement.order_by(
        SecurityEvent.timestamp.desc(),
        SecurityEvent.id.desc(),
    ).offset(offset).limit(limit)
    return list(db.scalars(statement).all())


@router.get("/{event_id}", response_model=SecurityEventRead)
def get_event(event_id: uuid.UUID, db: Session = Depends(get_db)):
    """Retrieve one event by its identifier."""
    event = db.get(SecurityEvent, event_id)
    if event is None:
        raise HTTPException(status_code=404, detail="Event not found")
    return event
