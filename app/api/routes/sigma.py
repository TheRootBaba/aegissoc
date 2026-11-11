from datetime import datetime, timezone
from types import SimpleNamespace
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.orm import Session
from app.core.security import get_current_user, require_roles
from app.db.session import get_db
from app.models import SigmaRule
from app.schemas.sigma import SigmaImportRequest, SigmaRuleRead, SigmaTestRequest, SigmaRunRequest, SigmaRunRead
from app.services.audit_chain import append_audit_entry
from app.services.sigma_engine import parse_sigma_document, rule_matches, run_sigma_rules

router = APIRouter(prefix="/api/v1/sigma", tags=["sigma-detection"],
                   dependencies=[Depends(require_roles("admin", "analyst", "read_only"))])

@router.get("/rules", response_model=list[SigmaRuleRead])
def list_rules(enabled: bool | None = None, limit: int = Query(default=100, ge=1, le=200), db: Session = Depends(get_db)):
    statement = select(SigmaRule)
    if enabled is not None:
        statement = statement.where(SigmaRule.enabled.is_(enabled))
    return list(db.scalars(statement.order_by(SigmaRule.updated_at.desc()).limit(limit)).all())

@router.post("/rules/import", response_model=SigmaRuleRead, status_code=status.HTTP_201_CREATED,
             dependencies=[Depends(require_roles("admin"))])
def import_rule(payload: SigmaImportRequest, db: Session = Depends(get_db), user=Depends(get_current_user)):
    try:
        parsed = parse_sigma_document(payload.sigma_yaml)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    if db.get(SigmaRule, parsed["rule_id"]):
        raise HTTPException(409, "Sigma rule ID already exists")
    rule = SigmaRule(**parsed, enabled=payload.enabled, created_by=user.username)
    db.add(rule)
    db.flush()
    append_audit_entry(db, actor=user.username, action="sigma_rule.imported", resource_type="sigma_rule",
                       resource_id=rule.rule_id, details={"enabled": rule.enabled, "level": rule.level})
    db.commit()
    db.refresh(rule)
    return rule

@router.patch("/rules/{rule_id}/enabled", response_model=SigmaRuleRead,
              dependencies=[Depends(require_roles("admin"))])
def set_rule_enabled(rule_id: str, enabled: bool, db: Session = Depends(get_db), user=Depends(get_current_user)):
    rule = db.get(SigmaRule, rule_id)
    if rule is None:
        raise HTTPException(404, "Sigma rule not found")
    rule.enabled = enabled
    rule.updated_at = datetime.now(timezone.utc)
    append_audit_entry(db, actor=user.username, action="sigma_rule.toggled", resource_type="sigma_rule",
                       resource_id=rule.rule_id, details={"enabled": enabled})
    db.commit()
    db.refresh(rule)
    return rule

@router.post("/rules/{rule_id}/test", response_model=dict,
             dependencies=[Depends(require_roles("admin", "analyst"))])
def test_rule(rule_id: str, payload: SigmaTestRequest, db: Session = Depends(get_db)):
    rule = db.get(SigmaRule, rule_id)
    if rule is None:
        raise HTTPException(404, "Sigma rule not found")
    sample = SimpleNamespace(
        source=payload.event.get("source"), event_type=payload.event.get("event_type"),
        severity=payload.event.get("severity"), hostname=payload.event.get("hostname"),
        source_ip=payload.event.get("source_ip"), username=payload.event.get("username"),
        message=payload.event.get("message"), raw=payload.event.get("raw", payload.event),
    )
    matched = rule_matches(sample, rule)
    return {"rule_id": rule_id, "matched": matched,
            "reason": "Selector condition matched." if matched else "No selector condition matched."}

@router.post("/run", response_model=SigmaRunRead, dependencies=[Depends(require_roles("admin", "analyst"))])
def run_rules(payload: SigmaRunRequest, db: Session = Depends(get_db), user=Depends(get_current_user)):
    result = run_sigma_rules(db, lookback_minutes=payload.lookback_minutes, limit=payload.limit)
    append_audit_entry(db, actor=user.username, action="sigma_rules.executed", resource_type="sigma_engine", details=result)
    db.commit()
    return result
