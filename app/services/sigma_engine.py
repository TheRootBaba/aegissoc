import fnmatch
import hashlib
import re
from datetime import datetime, timedelta, timezone
import yaml
from sqlalchemy import select
from sqlalchemy.orm import Session
from app.models import DetectionAlert, SecurityEvent, SigmaRule

LEVELS = {"informational": "info", "low": "low", "medium": "medium", "high": "high", "critical": "critical"}
FIELD_MAP = {
    "source": "source", "event_type": "event_type", "severity": "severity",
    "hostname": "hostname", "host.name": "hostname", "source.ip": "source_ip",
    "source_ip": "source_ip", "user.name": "username", "username": "username",
    "message": "message",
}

def parse_sigma_document(source: str) -> dict:
    try:
        document = yaml.safe_load(source)
    except yaml.YAMLError as exc:
        raise ValueError("Sigma document is not valid YAML") from exc
    if not isinstance(document, dict):
        raise ValueError("Sigma document must be a YAML mapping")
    if any(key not in document for key in ("title", "logsource", "detection", "level")):
        raise ValueError("Sigma document requires title, logsource, detection and level")
    if not isinstance(document["title"], str) or not document["title"].strip():
        raise ValueError("Sigma title must be a non-empty string")
    level = str(document["level"]).lower()
    if level not in LEVELS:
        raise ValueError("Unsupported Sigma level")
    detection = document["detection"]
    if not isinstance(detection, dict) or not isinstance(detection.get("condition"), str):
        raise ValueError("Sigma detection must contain a string condition")
    selectors = {key: value for key, value in detection.items() if key != "condition"}
    if not selectors or not all(isinstance(value, dict) and value for value in selectors.values()):
        raise ValueError("Sigma selectors must be non-empty mappings")
    condition = re.sub(r"\s+", " ", detection["condition"].strip())
    if re.fullmatch(r"[A-Za-z0-9_ ]+", condition) is None or re.search(r"\bnot\b", condition, re.I):
        raise ValueError("Condition supports selector names joined by AND/OR only")
    names = re.split(r"\s+(?:and|or)\s+", condition, flags=re.I)
    if any(name not in selectors for name in names):
        raise ValueError("Sigma condition references an unknown selector")
    for selector in selectors.values():
        for field, expected in selector.items():
            base, separator, modifier = str(field).partition("|")
            if not base or (separator and modifier not in {"contains", "startswith", "endswith"}):
                raise ValueError("Unsupported Sigma field modifier")
            if not isinstance(expected, (str, int, float, bool, list)):
                raise ValueError("Sigma field values must be scalar or a list")
    tags = document.get("tags", [])
    if not isinstance(tags, list):
        raise ValueError("Sigma tags must be a list")
    return {
        "rule_id": str(document.get("id") or hashlib.sha256(source.encode()).hexdigest()[:32]),
        "title": document["title"].strip()[:255],
        "description": str(document.get("description") or "")[:4000],
        "level": level,
        "status": str(document.get("status") or "experimental")[:24],
        "detection": selectors,
        "condition": condition,
        "logsource": document["logsource"] if isinstance(document["logsource"], dict) else {},
        "tags": [str(tag)[:120] for tag in tags[:50]],
        "sigma_yaml": source,
    }

def _nested_value(event, field: str):
    mapped = FIELD_MAP.get(field.lower())
    if mapped:
        return getattr(event, mapped, None)
    candidate = event.raw if isinstance(event.raw, dict) else {}
    for part in field.split("."):
        if not isinstance(candidate, dict):
            return None
        match = next((key for key in candidate if key.lower() == part.lower()), None)
        if match is None:
            return None
        candidate = candidate[match]
    return candidate

def _matches_value(actual, expected, modifier: str) -> bool:
    values = actual if isinstance(actual, list) else [actual]
    expected_values = expected if isinstance(expected, list) else [expected]
    for value in values:
        if value is None:
            continue
        for wanted in expected_values:
            left, right = str(value).lower(), str(wanted).lower()
            if modifier == "contains" and right in left:
                return True
            if modifier == "startswith" and left.startswith(right):
                return True
            if modifier == "endswith" and left.endswith(right):
                return True
            if not modifier and fnmatch.fnmatchcase(left, right):
                return True
    return False

def selector_matches(event, selector: dict) -> bool:
    for key, expected in selector.items():
        field, _, modifier = str(key).partition("|")
        if not _matches_value(_nested_value(event, field), expected, modifier):
            return False
    return True

def rule_matches(event, rule: SigmaRule) -> bool:
    results = {name: selector_matches(event, selector) for name, selector in rule.detection.items()}
    clauses = re.split(r"\s+(and|or)\s+", rule.condition, flags=re.I)
    result = results[clauses[0]]
    for index in range(1, len(clauses), 2):
        result = (result and results[clauses[index + 1]]) if clauses[index].lower() == "and" else (result or results[clauses[index + 1]])
    return result

def run_sigma_rules(db: Session, *, lookback_minutes: int = 15, limit: int = 1000) -> dict:
    now = datetime.now(timezone.utc)
    events = list(db.scalars(
        select(SecurityEvent).where(SecurityEvent.timestamp >= now - timedelta(minutes=lookback_minutes))
        .order_by(SecurityEvent.timestamp.asc(), SecurityEvent.id.asc()).limit(limit)
    ).all())
    rules = list(db.scalars(select(SigmaRule).where(SigmaRule.enabled.is_(True))).all())
    created = updated = matches = 0
    for rule in rules:
        for event in events:
            if not rule_matches(event, rule):
                continue
            matches += 1
            fingerprint = hashlib.sha256(f"sigma:{rule.rule_id}:{event.id}".encode()).hexdigest()
            alert = db.scalar(select(DetectionAlert).where(DetectionAlert.fingerprint == fingerprint))
            if alert is None:
                alert = DetectionAlert(
                    rule_id="SIGMA:" + rule.rule_id, fingerprint=fingerprint, title=rule.title,
                    description=rule.description or f"Sigma rule {rule.rule_id} matched event {event.id}.",
                    attack_tactic=None, attack_technique_id=None, attack_technique_name=None,
                    severity=LEVELS[rule.level], status="open", source_ip=event.source_ip,
                    hostname=event.hostname, username=event.username, event_count=1,
                    first_seen=event.timestamp, last_seen=event.timestamp,
                    evidence_event_ids=[str(event.id)],
                )
                db.add(alert)
                created += 1
            else:
                alert.last_seen = max(alert.last_seen, event.timestamp)
                alert.event_count = max(alert.event_count, 1)
                updated += 1
    return {"rules_evaluated": len(rules), "events_evaluated": len(events), "matches": matches,
            "alerts_created": created, "alerts_updated": updated}
