import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models import SecurityEvent
from app.schemas.events import SecurityEventCreate, SecurityEventRead

router = APIRouter(prefix="/api/v1/events", tags=["events"])


@router.post("", response_model=SecurityEventRead, status_code=status.HTTP_201_CREATED)
def ingest_event(payload: SecurityEventCreate, db: Session = Depends(get_db)):
    event = SecurityEvent(**payload.model_dump())
    db.add(event)
    db.commit()
    db.refresh(event)
    return event


@router.get("", response_model=list[SecurityEventRead])
def list_events(
    severity: str | None = Query(default=None, pattern="^(low|medium|high|critical|info)$"),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
):
    statement = select(SecurityEvent).order_by(SecurityEvent.timestamp.desc())
    if severity:
        statement = statement.where(SecurityEvent.severity == severity)
    statement = statement.offset(offset).limit(limit)
    return list(db.scalars(statement).all())


@router.get("/{event_id}", response_model=SecurityEventRead)
def get_event(event_id: uuid.UUID, db: Session = Depends(get_db)):
    event = db.get(SecurityEvent, event_id)
    if event is None:
        raise HTTPException(status_code=404, detail="Event not found")
    return event
