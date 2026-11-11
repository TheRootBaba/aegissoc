import hashlib
import hmac
import ipaddress
import json
from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.orm import Session
from app.core.security import get_current_user, require_roles
from app.db.session import get_db
from app.models import ConnectorConfig, IncidentCase, ResponseActionRequest, User
from app.schemas.response_actions import ResponseActionCreate, ResponseActionDecision, ResponseActionRead
from app.services.audit_chain import append_audit_entry
from app.services.integrations import get_adapter
from app.services.secrets import resolve_secret_reference

router = APIRouter(prefix="/api/v1/response-actions", tags=["response-governance"],
                   dependencies=[Depends(require_roles("admin", "analyst", "read_only"))])

def _audit(db, user, action, request, details):
    append_audit_entry(db, actor=user.username, action=action, resource_type="response_action",
                       resource_id=str(request.id), details=details)

@router.get("", response_model=list[ResponseActionRead])
def list_requests(status_filter: str | None = Query(default=None, alias="status",
        pattern="^(pending|approved|rejected|executing|succeeded|failed|canceled|expired)$"),
        case_id: UUID | None = None, limit: int = Query(default=100, ge=1, le=200),
        db: Session = Depends(get_db)):
    statement = select(ResponseActionRequest)
    if status_filter:
        statement = statement.where(ResponseActionRequest.status == status_filter)
    if case_id:
        statement = statement.where(ResponseActionRequest.case_id == case_id)
    return list(db.scalars(statement.order_by(ResponseActionRequest.created_at.desc()).limit(limit)).all())

@router.post("", response_model=ResponseActionRead, status_code=status.HTTP_201_CREATED,
             dependencies=[Depends(require_roles("admin", "analyst"))])
def create_request(payload: ResponseActionCreate, db: Session = Depends(get_db),
                   user: User = Depends(get_current_user)):
    if payload.case_id and db.get(IncidentCase, payload.case_id) is None:
        raise HTTPException(404, "Incident case not found")
    connector = db.scalar(select(ConnectorConfig).where(
        ConnectorConfig.connector_key == payload.connector_key,
        ConnectorConfig.connector_type == "response_webhook",
        ConnectorConfig.enabled.is_(True),
    ))
    if connector is None:
        raise HTTPException(422, "An enabled response_webhook connector is required")
    if payload.action_type == "block_ip":
        try:
            ipaddress.ip_address(payload.target)
        except ValueError as exc:
            raise HTTPException(422, "block_ip target must be a valid IP address") from exc
    if len(payload.parameters) > 20 or len(json.dumps(payload.parameters)) > 4096 or any(
        len(key) > 80 or (isinstance(value, str) and len(value) > 500) or
        any(marker in key.lower() for marker in ("password", "token", "secret", "api_key", "authorization"))
        or not isinstance(value, (str, int, float, bool, type(None)))
        for key, value in payload.parameters.items()
    ):
        raise HTTPException(422, "Action parameters must be flat, non-secret scalar values")
    request = ResponseActionRequest(
        case_id=payload.case_id, connector_key=payload.connector_key,
        action_type=payload.action_type, target=payload.target.strip(),
        parameters=payload.parameters, dry_run=payload.dry_run,
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=payload.expires_in_minutes),
        status="pending", requested_by=user.username,
        idempotency_key=hashlib.sha256(str(uuid4()).encode()).hexdigest(),
    )
    db.add(request)
    db.flush()
    _audit(db, user, "response_action.requested", request,
           {"action_type": request.action_type, "target": request.target, "connector_key": request.connector_key})
    db.commit()
    db.refresh(request)
    return request

@router.post("/{request_id}/approve", response_model=ResponseActionRead,
             dependencies=[Depends(require_roles("admin"))])
def approve(request_id: UUID, payload: ResponseActionDecision, db: Session = Depends(get_db),
            user: User = Depends(get_current_user)):
    request = db.get(ResponseActionRequest, request_id)
    if request is None:
        raise HTTPException(404, "Response action request not found")
    if request.status != "pending":
        raise HTTPException(409, "Only pending requests can be approved")
    if request.requested_by == user.username:
        raise HTTPException(403, "The requester cannot approve their own response action")
    request.status = "approved"
    request.approved_by = user.username
    request.decided_by = user.username
    request.decision_note = payload.note.strip()
    request.decided_at = datetime.now(timezone.utc)
    _audit(db, user, "response_action.approved", request, {"action_type": request.action_type})
    db.commit()
    db.refresh(request)
    return request

@router.post("/{request_id}/reject", response_model=ResponseActionRead,
             dependencies=[Depends(require_roles("admin"))])
def reject(request_id: UUID, payload: ResponseActionDecision, db: Session = Depends(get_db),
           user: User = Depends(get_current_user)):
    request = db.get(ResponseActionRequest, request_id)
    if request is None:
        raise HTTPException(404, "Response action request not found")
    if request.status != "pending":
        raise HTTPException(409, "Only pending requests can be rejected")
    request.status = "rejected"
    request.decided_by = user.username
    request.decision_note = payload.note.strip()
    request.decided_at = datetime.now(timezone.utc)
    _audit(db, user, "response_action.rejected", request, {"action_type": request.action_type})
    db.commit()
    db.refresh(request)
    return request

@router.post("/{request_id}/execute", response_model=ResponseActionRead,
             dependencies=[Depends(require_roles("admin"))])
def execute(request_id: UUID, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    request = db.get(ResponseActionRequest, request_id)
    if request is None:
        raise HTTPException(404, "Response action request not found")
    if request.status != "approved":
        raise HTTPException(409, "Only approved requests can be queued for execution")
    if request.execution_status in {"queued", "retry_scheduled", "submitting", "delivered"}:
        return request
    request.execution_status = "queued"
    request.next_attempt_at = datetime.now(timezone.utc)
    request.locked_until = None
    _audit(db, user, "response_action.execution_queued", request,
           {"connector_key": request.connector_key, "idempotency_key": request.idempotency_key})
    db.commit()
    db.refresh(request)
    return request


@router.post("/{request_id}/cancel", response_model=ResponseActionRead,
             dependencies=[Depends(require_roles("admin"))])
def cancel_request(request_id: UUID, payload: ResponseActionDecision,
                   db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    """Cancel an action only while it is still safe to prevent delivery."""
    request = db.scalar(select(ResponseActionRequest).where(
        ResponseActionRequest.id == request_id
    ).with_for_update())
    if request is None:
        raise HTTPException(404, "Response action request not found")
    if request.status not in {"pending", "approved"} or request.execution_status in {
        "submitting", "delivered", "simulated"
    }:
        raise HTTPException(409, "This action can no longer be canceled safely")
    request.status = "canceled"
    request.execution_status = "canceled"
    request.decided_by = user.username
    request.decision_note = payload.note.strip()
    request.decided_at = datetime.now(timezone.utc)
    request.next_attempt_at = None
    request.locked_until = None
    _audit(db, user, "response_action.canceled", request,
           {"execution_status": request.execution_status})
    db.commit()
    db.refresh(request)
    return request
