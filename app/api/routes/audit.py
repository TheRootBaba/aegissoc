from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.security import require_roles
from app.db.session import get_db
from app.models import SecurityAuditEntry
from app.schemas.audit import AuditChainVerification, SecurityAuditEntryRead
from app.services.audit_chain import verify_audit_chain

router = APIRouter(
    prefix="/api/v1/audit",
    tags=["security audit"],
    dependencies=[Depends(require_roles("admin", "analyst", "read_only"))],
)


@router.get("", response_model=list[SecurityAuditEntryRead])
def list_audit_entries(
    actor: str | None = Query(default=None, min_length=1, max_length=64),
    action: str | None = Query(default=None, min_length=1, max_length=100),
    resource_type: str | None = Query(default=None, min_length=1, max_length=64),
    limit: int = Query(default=100, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
):
    statement = select(SecurityAuditEntry)
    for column, value in (
        (SecurityAuditEntry.actor, actor),
        (SecurityAuditEntry.action, action),
        (SecurityAuditEntry.resource_type, resource_type),
    ):
        if value is not None:
            statement = statement.where(column == value)
    statement = statement.order_by(
        SecurityAuditEntry.sequence.desc()
    ).offset(offset).limit(limit)
    return list(db.scalars(statement).all())


@router.get("/verify", response_model=AuditChainVerification,
            dependencies=[Depends(require_roles("admin"))])
def verify_audit_integrity(db: Session = Depends(get_db)):
    return verify_audit_chain(db)
