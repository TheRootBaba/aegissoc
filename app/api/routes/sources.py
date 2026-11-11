from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.security import require_roles
from app.services.audit_chain import append_audit_entry
from app.db.session import get_db
from app.models import SourceRegistry, User
from app.schemas.sources import SourceCreate, SourceRead

router = APIRouter(
    prefix="/api/v1/sources",
    tags=["source inventory"],
    dependencies=[Depends(require_roles("admin", "analyst", "read_only"))],
)

STALE_AFTER_MINUTES = 15


def _serialize(source: SourceRegistry) -> dict:
    """Derive stale/inactive states from observed activity without fabricating health."""
    now = datetime.now(timezone.utc)
    last_success = source.last_successful_event_at
    # SQLite does not preserve timezone metadata on DateTime columns; treat
    # its naive UTC values consistently with PostgreSQL's aware timestamps.
    if last_success is not None and last_success.tzinfo is None:
        last_success = last_success.replace(tzinfo=timezone.utc)
    if source.health_status == "failing":
        health = "failing"
    elif last_success is None:
        health = "inactive"
    elif last_success < now - timedelta(minutes=STALE_AFTER_MINUTES):
        health = "stale"
    else:
        health = source.health_status
    return {
        "source_name": source.source_name,
        "display_name": source.display_name,
        "source_type": source.source_type,
        "description": source.description,
        "health_status": health,
        "last_attempt_at": source.last_attempt_at,
        "last_successful_event_at": last_success,
        "accepted_events": source.accepted_events,
        "duplicate_events": source.duplicate_events,
        "rejected_events": source.rejected_events,
        "created_at": source.created_at,
        "updated_at": source.updated_at,
    }


@router.get("", response_model=list[SourceRead])
def list_sources(db: Session = Depends(get_db)):
    sources = db.scalars(select(SourceRegistry).order_by(SourceRegistry.source_name.asc())).all()
    return [_serialize(source) for source in sources]


@router.post("", response_model=SourceRead, status_code=status.HTTP_201_CREATED,
             dependencies=[Depends(require_roles("admin"))])
def register_source(payload: SourceCreate, db: Session = Depends(get_db), current_user: User = Depends(require_roles("admin"))):
    if db.scalar(select(SourceRegistry.id).where(SourceRegistry.source_name == payload.source_name)):
        raise HTTPException(status_code=409, detail="Source is already registered")
    source = SourceRegistry(
        source_name=payload.source_name,
        display_name=payload.display_name,
        source_type=payload.source_type,
        description=payload.description,
        health_status="inactive",
    )
    db.add(source)
    try:
        append_audit_entry(db, actor=current_user.username, action="source.registered", resource_type="source", resource_id=source.source_name, details={"source_type": source.source_type})
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail="Source is already registered") from exc
    db.refresh(source)
    return _serialize(source)


@router.get("/{source_name}", response_model=SourceRead)
def get_source(source_name: str, db: Session = Depends(get_db)):
    source = db.scalar(select(SourceRegistry).where(SourceRegistry.source_name == source_name))
    if source is None:
        raise HTTPException(status_code=404, detail="Source not found")
    return _serialize(source)
