from datetime import datetime, timezone
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.security import get_current_user, require_roles
from app.db.session import get_db
from app.models import CaseAlertLink, CaseNote, DetectionAlert, IncidentCase, SecurityAuditEntry, User
from app.schemas.cases import CaseActivityRead, CaseAlertRead, CaseCreate, CaseDetail, CaseNoteCreate, CaseNoteRead, CaseRead, CaseUpdate
from app.services.audit_chain import append_audit_entry

router = APIRouter(
    prefix="/api/v1/cases",
    tags=["incident-cases"],
    dependencies=[Depends(require_roles("admin", "analyst", "read_only"))],
)

CASE_TRANSITIONS = {
    "open": {"investigating", "closed"},
    "investigating": {"contained", "closed", "open"},
    "contained": {"eradicated", "investigating", "closed"},
    "eradicated": {"recovered", "contained", "closed"},
    "recovered": {"closed", "investigating"},
    "closed": {"investigating"},
}


def _get_case(db: Session, case_id: UUID) -> IncidentCase:
    case = db.get(IncidentCase, case_id)
    if case is None:
        raise HTTPException(status_code=404, detail="Incident case not found")
    return case


def _audit(db: Session, case: IncidentCase, actor: str, action: str, details: dict) -> None:
    append_audit_entry(
        db, actor=actor, action=action, resource_type="incident_case",
        resource_id=str(case.id), details={"case_number": case.case_number, **details},
    )


def _case_detail(db: Session, case: IncidentCase) -> CaseDetail:
    links = db.scalars(
        select(CaseAlertLink).where(CaseAlertLink.case_id == case.id)
        .order_by(CaseAlertLink.linked_at.asc())
    ).all()
    alert_ids = [link.alert_id for link in links]
    alerts = db.scalars(
        select(DetectionAlert).where(DetectionAlert.id.in_(alert_ids))
        .order_by(DetectionAlert.created_at.desc())
    ).all() if alert_ids else []
    notes = db.scalars(
        select(CaseNote).where(CaseNote.case_id == case.id)
        .order_by(CaseNote.created_at.asc(), CaseNote.id.asc())
    ).all()
    timeline = db.scalars(
        select(SecurityAuditEntry).where(
            SecurityAuditEntry.resource_type == "incident_case",
            SecurityAuditEntry.resource_id == str(case.id),
        ).order_by(SecurityAuditEntry.sequence.desc()).limit(100)
    ).all()
    return CaseDetail(
        **CaseRead.model_validate(case).model_dump(),
        alerts=[CaseAlertRead.model_validate(alert) for alert in alerts],
        notes=[CaseNoteRead.model_validate(note) for note in notes],
        timeline=[
            CaseActivityRead(actor=entry.actor, action=entry.action,
                             occurred_at=entry.occurred_at, details=entry.details)
            for entry in timeline
        ],
    )


@router.get("", response_model=list[CaseRead])
def list_cases(
    status_filter: str | None = Query(default=None, alias="status", pattern="^(open|investigating|contained|eradicated|recovered|closed)$"),
    priority: str | None = Query(default=None, pattern="^(p1|p2|p3|p4)$"),
    assignee: str | None = Query(default=None, min_length=1, max_length=120),
    search: str | None = Query(default=None, min_length=1, max_length=200),
    limit: int = Query(default=100, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
):
    statement = select(IncidentCase)
    if status_filter:
        statement = statement.where(IncidentCase.status == status_filter)
    if priority:
        statement = statement.where(IncidentCase.priority == priority)
    if assignee:
        statement = statement.where(IncidentCase.assignee == assignee)
    if search:
        pattern = f"%{search.strip()}%"
        statement = statement.where(
            IncidentCase.title.ilike(pattern) |
            IncidentCase.case_number.ilike(pattern) |
            IncidentCase.description.ilike(pattern)
        )
    return list(db.scalars(
        statement.order_by(IncidentCase.updated_at.desc(), IncidentCase.id.desc())
        .offset(offset).limit(limit)
    ).all())


@router.post("", response_model=CaseRead, status_code=status.HTTP_201_CREATED,
             dependencies=[Depends(require_roles("admin", "analyst"))])
def create_case(
    payload: CaseCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    now = datetime.now(timezone.utc)
    case_id = uuid4()
    case = IncidentCase(
        id=case_id,
        case_number=f"AEG-{now:%Y}-{case_id.hex[:8].upper()}",
        title=payload.title,
        description=payload.description,
        priority=payload.priority,
        severity=payload.severity,
        assignee=payload.assignee,
        tags=payload.tags,
        created_by=current_user.username,
        created_at=now,
        updated_at=now,
    )
    db.add(case)
    _audit(db, case, current_user.username, "case.created", {
        "priority": case.priority, "severity": case.severity,
    })
    db.commit()
    db.refresh(case)
    return case


@router.get("/{case_id}", response_model=CaseDetail)
def get_case(case_id: UUID, db: Session = Depends(get_db)):
    return _case_detail(db, _get_case(db, case_id))


@router.patch("/{case_id}", response_model=CaseRead,
              dependencies=[Depends(require_roles("admin", "analyst"))])
def update_case(
    case_id: UUID,
    payload: CaseUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    case = _get_case(db, case_id)
    changes = {}
    for field in payload.model_fields_set:
        value = getattr(payload, field)
        if field == "title" and value is not None:
            value = value.strip()
            if not value:
                raise HTTPException(status_code=422, detail="Case title must not be blank")
        if field == "assignee" and value:
            value = value.strip() or None
        if field == "tags" and value is not None:
            value = list(dict.fromkeys(tag.strip().lower() for tag in value if tag.strip()))
        previous = getattr(case, field)
        if previous != value:
            changes[field] = {"from": previous, "to": value}
            setattr(case, field, value)
    if "status" in changes:
        previous, next_status = changes["status"]["from"], changes["status"]["to"]
        if next_status not in CASE_TRANSITIONS[previous]:
            raise HTTPException(status_code=409, detail=f"Invalid case transition: {previous} -> {next_status}")
        case.closed_at = datetime.now(timezone.utc) if next_status == "closed" else None
    if changes:
        case.updated_at = datetime.now(timezone.utc)
        _audit(db, case, current_user.username, "case.updated", changes)
        db.commit()
        db.refresh(case)
    return case


@router.post("/{case_id}/alerts/{alert_id}", status_code=status.HTTP_201_CREATED,
             dependencies=[Depends(require_roles("admin", "analyst"))])
def link_alert(
    case_id: UUID, alert_id: UUID, db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    case = _get_case(db, case_id)
    alert = db.get(DetectionAlert, alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    existing = db.scalar(select(CaseAlertLink).where(
        CaseAlertLink.case_id == case.id, CaseAlertLink.alert_id == alert.id
    ))
    if existing:
        raise HTTPException(status_code=409, detail="Alert is already linked to this case")
    link = CaseAlertLink(case_id=case.id, alert_id=alert.id, linked_by=current_user.username)
    db.add(link)
    case.updated_at = datetime.now(timezone.utc)
    _audit(db, case, current_user.username, "case.alert_linked", {"alert_id": str(alert.id)})
    db.commit()
    return {"case_id": str(case.id), "alert_id": str(alert.id), "linked": True}


@router.delete("/{case_id}/alerts/{alert_id}", status_code=status.HTTP_204_NO_CONTENT,
               dependencies=[Depends(require_roles("admin", "analyst"))])
def unlink_alert(
    case_id: UUID, alert_id: UUID, db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    case = _get_case(db, case_id)
    link = db.scalar(select(CaseAlertLink).where(
        CaseAlertLink.case_id == case.id, CaseAlertLink.alert_id == alert_id
    ))
    if link is None:
        raise HTTPException(status_code=404, detail="Alert link not found")
    db.delete(link)
    case.updated_at = datetime.now(timezone.utc)
    _audit(db, case, current_user.username, "case.alert_unlinked", {"alert_id": str(alert_id)})
    db.commit()
    return None


@router.post("/{case_id}/notes", response_model=CaseNoteRead, status_code=status.HTTP_201_CREATED,
             dependencies=[Depends(require_roles("admin", "analyst"))])
def add_case_note(
    case_id: UUID, payload: CaseNoteCreate, db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    case = _get_case(db, case_id)
    note = CaseNote(case_id=case.id, author=current_user.username, body=payload.body.strip())
    db.add(note)
    db.flush()
    case.updated_at = datetime.now(timezone.utc)
    _audit(db, case, current_user.username, "case.note_added", {"note_id": str(note.id)})
    db.commit()
    db.refresh(note)
    return note
