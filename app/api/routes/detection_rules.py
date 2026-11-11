from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.security import get_current_user, require_roles
from app.db.session import get_db
from app.models import DetectionRuleConfig, User
from app.schemas.detection_rules import DetectionRuleRead, DetectionRuleUpdate
from app.services.audit_chain import append_audit_entry
from app.services.detection_engine import ATTACK_MAPPINGS

router = APIRouter(
    prefix="/api/v1/detection-rules",
    tags=["detection-rules"],
    dependencies=[Depends(require_roles("admin", "analyst", "read_only"))],
)

RULE_DETAILS = {
    "AUTH-SSH-001": ("SSH brute-force activity", "Repeated SSH authentication failures from one source.", "Brute Force"),
    "AUTH-SSH-002": ("SSH password spraying", "One source attempts authentication against multiple accounts.", "Password Spraying"),
    "AUTH-CHAIN-001": ("Authentication success after failures", "A successful login follows repeated authentication failures.", "Password Guessing"),
    "PRIV-ESC-001": ("Privilege escalation", "An event indicates privilege escalation or a privileged command.", "Abuse Elevation Control Mechanism"),
    "PROC-SUSP-001": ("Suspicious process execution", "A process command matches a suspicious execution indicator.", "Command and Scripting Interpreter"),
}


def _rule_read(config: DetectionRuleConfig) -> DetectionRuleRead:
    title, description, technique_name = RULE_DETAILS[config.rule_id]
    attack = ATTACK_MAPPINGS[config.rule_id]
    return DetectionRuleRead(
        rule_id=config.rule_id,
        title=title,
        description=description,
        attack_tactic=attack["attack_tactic"],
        attack_technique_id=attack["attack_technique_id"],
        attack_technique_name=technique_name,
        enabled=config.enabled,
        severity_override=config.severity_override,
        threshold_override=config.threshold_override,
        updated_by=config.updated_by,
        updated_at=config.updated_at,
    )


@router.get("", response_model=list[DetectionRuleRead])
def list_detection_rules(db: Session = Depends(get_db)):
    configs = db.scalars(select(DetectionRuleConfig).order_by(DetectionRuleConfig.rule_id.asc())).all()
    return [_rule_read(config) for config in configs]


@router.patch("/{rule_id}", response_model=DetectionRuleRead,
              dependencies=[Depends(require_roles("admin"))])
def update_detection_rule(
    rule_id: str,
    payload: DetectionRuleUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    config = db.get(DetectionRuleConfig, rule_id)
    if config is None:
        raise HTTPException(status_code=404, detail="Detection rule not found")
    changes = {}
    for field in payload.model_fields_set:
        value = getattr(payload, field)
        previous = getattr(config, field)
        if previous != value:
            changes[field] = {"from": previous, "to": value}
            setattr(config, field, value)
    if changes:
        config.updated_by = current_user.username
        config.updated_at = datetime.now(timezone.utc)
        append_audit_entry(
            db, actor=current_user.username, action="detection_rule.updated",
            resource_type="detection_rule", resource_id=rule_id, details=changes,
        )
        db.commit()
        db.refresh(config)
    return _rule_read(config)
