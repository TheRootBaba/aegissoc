from datetime import datetime, timezone
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models import AlertAuditLog, AlertNote, DetectionAlert
from app.schemas.alert_workflow import (
    AlertAuditRead,
    AlertDetail,
    AlertNoteCreate,
    AlertNoteRead,
    AlertUpdate,
)

router = APIRouter(prefix="/api/v1/alerts", tags=["alerts"])

ALLOWED_TRANSITIONS = {
    "open": {"acknowledged", "false_positive"},
    "acknowledged": {"open", "in_progress", "resolved", "false_positive"},
    "in_progress": {"open", "acknowledged", "resolved", "false_positive"},
    "resolved": {"open"},
    "false_positive": {"open"},
}


def _get_alert(db: Session, alert_id: UUID) -> DetectionAlert:
    alert = db.get(DetectionAlert, alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert


def _audit(db: Session, alert_id: UUID, actor: str, action: str, details: dict) -> None:
    db.add(AlertAuditLog(alert_id=alert_id, actor=actor, action=action, details=details))


@router.get("/{alert_id}", response_model=AlertDetail)
def get_alert(alert_id: UUID, db: Session = Depends(get_db)):
    """Return one alert with lifecycle and assignment metadata."""
    return _get_alert(db, alert_id)


@router.patch("/{alert_id}", response_model=AlertDetail)
def update_alert(alert_id: UUID, payload: AlertUpdate, db: Session = Depends(get_db)):
    """Change alert status and/or assignment, recording each change in its audit trail."""
    alert = _get_alert(db, alert_id)
    changes = {}

    if "status" in payload.model_fields_set and payload.status is not None:
        if payload.status != alert.status and payload.status not in ALLOWED_TRANSITIONS[alert.status]:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Invalid alert transition: {alert.status} -> {payload.status}",
            )
        if payload.status != alert.status:
            previous = alert.status
            alert.status = payload.status
            alert.acknowledged_at = (
                alert.acknowledged_at or datetime.now(timezone.utc)
                if payload.status in {"acknowledged", "in_progress", "resolved"}
                else None
            )
            alert.resolved_at = (
                datetime.now(timezone.utc) if payload.status == "resolved" else None
            )
            changes["status"] = {"from": previous, "to": payload.status}

    if "assigned_to" in payload.model_fields_set:
        previous_assignee = alert.assigned_to
        alert.assigned_to = payload.assigned_to.strip() if payload.assigned_to else None
        if alert.assigned_to != previous_assignee:
            changes["assigned_to"] = {"from": previous_assignee, "to": alert.assigned_to}

    if changes:
        alert.updated_at = datetime.now(timezone.utc)
        _audit(db, alert.id, payload.actor, "alert.updated", changes)
        db.commit()
        db.refresh(alert)
    return alert


@router.post("/{alert_id}/notes", response_model=AlertNoteRead, status_code=status.HTTP_201_CREATED)
def add_alert_note(alert_id: UUID, payload: AlertNoteCreate, db: Session = Depends(get_db)):
    """Append an analyst note and a corresponding immutable audit event."""
    alert = _get_alert(db, alert_id)
    note = AlertNote(alert_id=alert.id, author=payload.author, body=payload.body.strip())
    if not note.body:
        raise HTTPException(status_code=422, detail="Note body must not be blank")
    db.add(note)
    _audit(db, alert.id, payload.author, "note.added", {"note_id": str(note.id)})
    alert.updated_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(note)
    return note


@router.get("/{alert_id}/notes", response_model=list[AlertNoteRead])
def list_alert_notes(
    alert_id: UUID,
    limit: int = Query(default=100, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
):
    _get_alert(db, alert_id)
    statement = (
        select(AlertNote)
        .where(AlertNote.alert_id == alert_id)
        .order_by(AlertNote.created_at.asc(), AlertNote.id.asc())
        .offset(offset)
        .limit(limit)
    )
    return list(db.scalars(statement).all())


@router.get("/{alert_id}/history", response_model=list[AlertAuditRead])
def list_alert_history(
    alert_id: UUID,
    limit: int = Query(default=100, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
):
    _get_alert(db, alert_id)
    statement = (
        select(AlertAuditLog)
        .where(AlertAuditLog.alert_id == alert_id)
        .order_by(AlertAuditLog.created_at.asc(), AlertAuditLog.id.asc())
        .offset(offset)
        .limit(limit)
    )
    return list(db.scalars(statement).all())
