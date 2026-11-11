"""Validated Sigma subset execution with correlation rules and evidence-linked alerts."""

import fnmatch
import hashlib
import ipaddress
import json
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
}
_CONDITION_TOKEN = re.compile(
    r"\s*(?:(?P<quant>(?:\d+|all)\s+of\s+[A-Za-z0-9_*]+)|"
    r"(?P<operator>and|or|not)\b|(?P<name>[A-Za-z_][A-Za-z0-9_*]*)|(?P<paren>[()]))",
    re.I,
)


def _parse_correlation(value: object) -> dict:
    if not isinstance(value, dict) or str(value.get("type", "")).lower() != "event_count":
        raise ValueError("Only event_count Sigma correlation is supported")
    rules = value.get("rules")
    if isinstance(rules, str):
        rules = [rules]
    if not isinstance(rules, list) or not rules or len(rules) > 20:
        raise ValueError("Correlation rules must reference between 1 and 20 Sigma rule IDs")
    if not all(isinstance(item, str) and re.fullmatch(r"[A-Za-z0-9_.-]{1,58}", item) for item in rules):
        raise ValueError("Correlation rule references contain an invalid rule ID")
    group_by = value.get("group-by", [])
    if not isinstance(group_by, list) or len(group_by) > 10 or not all(
        isinstance(field, str) and re.fullmatch(r"[A-Za-z0-9_.-]{1,80}", field) for field in group_by
    ):
        raise ValueError("Correlation group-by must contain up to 10 valid event field names")
    timespan = str(value.get("timespan", "5m")).strip().lower()
    match = re.fullmatch(r"(\d+)(s|m|h|d)", timespan)
    if not match:
        raise ValueError("Correlation timespan must use seconds, minutes, hours, or days")
    amount, unit = int(match.group(1)), match.group(2)
    seconds = amount * {"s": 1, "m": 60, "h": 3600, "d": 86400}[unit]
    if not 60 <= seconds <= 7 * 86400:
        raise ValueError("Correlation timespan must be between one minute and seven days")
    condition = value.get("condition")
    if not isinstance(condition, dict) or len(condition) != 1:
        raise ValueError("Correlation condition must contain one gte or gt threshold")
    if "gte" in condition:
        threshold = condition["gte"]
    elif "gt" in condition:
        threshold = int(condition["gt"]) + 1
    else:
        raise ValueError("Correlation condition supports gte or gt")
    if not isinstance(threshold, int) or not 2 <= threshold <= 10000:
        raise ValueError("Correlation event threshold must be between 2 and 10000")
    return {
        "type": "event_count",
        "rules": list(dict.fromkeys(rules)),
        "group_by": group_by,
        "window_minutes": max(1, (seconds + 59) // 60),
        "threshold": threshold,
    }


def _evaluate_condition(condition: str, results: dict[str, bool]) -> bool:
    tokens = []
    position = 0
    while position < len(condition):
        match = _CONDITION_TOKEN.match(condition, position)
        if not match:
            raise ValueError("Sigma condition contains an unsupported token")
        position = match.end()
        if match.group("quant"):
            tokens.append(("quant", match.group("quant")))
        elif match.group("operator"):
            tokens.append((match.group("operator").lower(), match.group("operator").lower()))
        elif match.group("name"):
            tokens.append(("name", match.group("name")))
        else:
            tokens.append((match.group("paren"), match.group("paren")))
    index = 0

    def primary():
        nonlocal index
        if index >= len(tokens):
            raise ValueError("Sigma condition ended unexpectedly")
        kind, value = tokens[index]
        if kind == "not":
            index += 1
            return not primary()
        if kind == "(":
            index += 1
            result = expression()
            if index >= len(tokens) or tokens[index][0] != ")":
                raise ValueError("Sigma condition has an unmatched parenthesis")
            index += 1
            return result
        if kind == "quant":
            index += 1
            count_text, pattern = value.split(" of ", 1)
            names = list(results) if pattern.lower() == "them" else [
                name for name in results if fnmatch.fnmatchcase(name.lower(), pattern.lower())
            ]
            if not names:
                raise ValueError("Sigma quantifier does not match any selector")
            required = len(names) if count_text.lower() == "all" else int(count_text)
            if required < 1 or required > len(names):
                raise ValueError("Sigma quantifier threshold exceeds the matching selector count")
            return sum(bool(results[name]) for name in names) >= required
        if kind == "name":
            index += 1
            if value not in results:
                raise ValueError("Sigma condition references an unknown selector")
            return bool(results[value])
        raise ValueError("Sigma condition expected a selector or parenthesized expression")

    def conjunction():
        nonlocal index
        result = primary()
        while index < len(tokens) and tokens[index][0] == "and":
            index += 1
            right = primary()
            result = result and right
        return result

    def expression():
        nonlocal index
        result = conjunction()
        while index < len(tokens) and tokens[index][0] == "or":
            index += 1
            right = conjunction()
            result = result or right
        return result

    result = expression()
    if index != len(tokens):
        raise ValueError("Sigma condition contains trailing tokens")
    return result


def parse_sigma_document(source: str) -> dict:
    try:
        document = yaml.safe_load(source)
    except yaml.YAMLError as exc:
        raise ValueError("Sigma document is not valid YAML") from exc
    if not isinstance(document, dict):
        raise ValueError("Sigma document must be a YAML mapping")
    if any(key not in document for key in ("title", "logsource", "level")):
        raise ValueError("Sigma document requires title, logsource and level")
    if not isinstance(document["title"], str) or not document["title"].strip():
        raise ValueError("Sigma title must be a non-empty string")
    level = str(document["level"]).lower()
    if level not in LEVELS:
        raise ValueError("Unsupported Sigma level")

    correlation = _parse_correlation(document["correlation"]) if "correlation" in document else None
    detection = document.get("detection")
    if correlation is None and (not isinstance(detection, dict) or not isinstance(detection.get("condition"), str)):
        raise ValueError("Sigma detection must contain a string condition")
    if correlation is not None and detection is None:
        selectors, condition = {}, "correlation"
    else:
        if not isinstance(detection, dict):
            raise ValueError("Sigma detection must be a YAML mapping")
        selectors = {key: value for key, value in detection.items() if key != "condition"}
        if not selectors or not all(isinstance(value, dict) and value for value in selectors.values()):
            raise ValueError("Sigma selectors must be non-empty mappings")
        condition = re.sub(r"\s+", " ", detection["condition"].strip())
        _evaluate_condition(condition, {name: False for name in selectors})

    for selector in selectors.values():
        for field, expected in selector.items():
            parts = str(field).split("|")
            modifiers = set(parts[1:])
            if not parts[0] or not modifiers.issubset({"contains", "startswith", "endswith", "all", "cidr", "exists"}):
                raise ValueError("Unsupported Sigma field modifier")
            if len(modifiers.intersection({"contains", "startswith", "endswith", "cidr", "exists"})) > 1:
                raise ValueError("Sigma field modifiers are incompatible")
            if not isinstance(expected, (str, int, float, bool, list)):
                raise ValueError("Sigma field values must be scalar or a list")
            if isinstance(expected, list) and (not expected or len(expected) > 100):
                raise ValueError("Sigma selector lists must contain between 1 and 100 values")

    rule_id = str(document.get("id") or hashlib.sha256(source.encode()).hexdigest()[:32])
    max_id_length = 56 if correlation else 58
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1," + str(max_id_length) + r"}", rule_id):
        raise ValueError(f"Sigma rule ID must be between 1 and {max_id_length} valid characters")
    tags = document.get("tags", [])
    if not isinstance(tags, list):
        raise ValueError("Sigma tags must be a list")
    logsource = document["logsource"]
    if not isinstance(logsource, dict):
        raise ValueError("Sigma logsource must be a mapping")
    return {
        "rule_id": rule_id,
        "title": document["title"].strip()[:255],
        "description": str(document.get("description") or "")[:4000],
        "level": level,
        "status": str(document.get("status") or "experimental")[:24],
        "detection": selectors,
        "condition": condition,
        "logsource": logsource,
        "tags": [str(tag)[:120] for tag in tags[:50]],
        "sigma_yaml": source,
        "correlation": correlation,
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


def _value_matches(value, wanted, mode: str) -> bool:
    if value is None:
        return False
    if mode == "exists":
        return (value is not None) is bool(wanted) if isinstance(wanted, bool) else value is not None
    if mode == "cidr":
        try:
            return ipaddress.ip_address(str(value)) in ipaddress.ip_network(str(wanted), strict=False)
        except ValueError:
            return False
    left, right = str(value).lower(), str(wanted).lower()
    if mode == "contains":
        return right in left
    if mode == "startswith":
        return left.startswith(right)
    if mode == "endswith":
        return left.endswith(right)
    return fnmatch.fnmatchcase(left, right)


def _matches_value(actual, expected, modifiers: set[str]) -> bool:
    values = actual if isinstance(actual, list) else [actual]
    expected_values = expected if isinstance(expected, list) else [expected]
    mode = next((item for item in ("contains", "startswith", "endswith", "cidr", "exists") if item in modifiers), "")
    if "all" in modifiers:
        return all(any(_value_matches(value, wanted, mode) for value in values) for wanted in expected_values)
    return any(_value_matches(value, wanted, mode) for value in values for wanted in expected_values)


def selector_matches(event, selector: dict) -> bool:
    for key, expected in selector.items():
        parts = str(key).split("|")
        if not _matches_value(_nested_value(event, parts[0]), expected, set(parts[1:])):
            return False
    return True


def rule_matches(event, rule: SigmaRule) -> bool:
    if rule.correlation:
        return False
    results = {name: selector_matches(event, selector) for name, selector in rule.detection.items()}
    return _evaluate_condition(rule.condition, results)


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _upsert_sigma_alert(db: Session, *, rule: SigmaRule, fingerprint: str,
                        evidence: list[SecurityEvent], title: str, description: str) -> tuple[bool, bool]:
    if not evidence:
        return False, False
    ordered = sorted(evidence, key=lambda item: (_utc(item.timestamp), str(item.id)))
    alert = db.scalar(select(DetectionAlert).where(DetectionAlert.fingerprint == fingerprint))
    if alert is None:
        alert = DetectionAlert(
            rule_id=("SIGMA-C:" if rule.correlation else "SIGMA:") + rule.rule_id,
            fingerprint=fingerprint,
            title=title[:255],
            description=description[:4000],
            attack_tactic=None,
            attack_technique_id=None,
            attack_technique_name=None,
            severity=LEVELS[rule.level],
            status="open",
            source_ip=ordered[-1].source_ip,
            hostname=ordered[-1].hostname,
            username=ordered[-1].username,
            event_count=len(ordered),
            first_seen=_utc(ordered[0].timestamp),
            last_seen=_utc(ordered[-1].timestamp),
            evidence_event_ids=[str(item.id) for item in ordered[-100:]],
        )
        db.add(alert)
        # Some worker/test sessions disable autoflush. Persist the alert before
        # returning so subsequent reads in the same transaction can observe it.
        db.flush()
        return True, False
    alert.event_count = len(ordered)
    alert.first_seen = _utc(ordered[0].timestamp)
    alert.last_seen = _utc(ordered[-1].timestamp)
    alert.evidence_event_ids = [str(item.id) for item in ordered[-100:]]
    alert.source_ip = ordered[-1].source_ip
    alert.hostname = ordered[-1].hostname
    alert.username = ordered[-1].username
    return False, True


def _run_correlations(db: Session, rules: list[SigmaRule], events: list[SecurityEvent], now: datetime):
    by_id = {rule.rule_id: rule for rule in rules if not rule.correlation}
    created = updated = matches = 0
    for correlation_rule in (item for item in rules if item.correlation):
        config = correlation_rule.correlation
        referenced = [by_id.get(rule_id) for rule_id in config["rules"]]
        if any(item is None for item in referenced):
            continue
        cutoff = now - timedelta(minutes=config["window_minutes"])
        groups: dict[tuple, list[SecurityEvent]] = {}
        for event in events:
            if _utc(event.timestamp) < cutoff:
                continue
            if not any(rule_matches(event, item) for item in referenced):
                continue
            group = tuple(str(_nested_value(event, field) or "<missing>") for field in config["group_by"])
            groups.setdefault(group, []).append(event)
        for group, evidence in groups.items():
            if len(evidence) < config["threshold"]:
                continue
            matches += 1
            bucket = int(now.timestamp() // (config["window_minutes"] * 60))
            fingerprint_data = json.dumps(
                [correlation_rule.rule_id, group, bucket], separators=(",", ":"), sort_keys=True
            )
            fingerprint = hashlib.sha256(("sigma-correlation:" + fingerprint_data).encode()).hexdigest()
            description = (
                f"Sigma event_count correlation matched {len(evidence)} events in "
                f"{config['window_minutes']} minutes (threshold {config['threshold']})."
            )
            was_created, was_updated = _upsert_sigma_alert(
                db, rule=correlation_rule, fingerprint=fingerprint,
                evidence=evidence, title=correlation_rule.title, description=description,
            )
            created += int(was_created)
            updated += int(was_updated)
    return matches, created, updated


def run_sigma_rules(db: Session, *, lookback_minutes: int = 15, limit: int = 1000) -> dict:
    now = datetime.now(timezone.utc)
    rules = list(db.scalars(
        select(SigmaRule).where(SigmaRule.enabled.is_(True))
        .order_by(SigmaRule.rule_id.asc()).limit(100)
    ).all())
    effective_lookback = max(
        [lookback_minutes] + [
            item.correlation["window_minutes"] for item in rules if item.correlation
        ]
    )
    events = list(db.scalars(
        select(SecurityEvent).where(SecurityEvent.timestamp >= now - timedelta(minutes=effective_lookback))
        .order_by(SecurityEvent.timestamp.asc(), SecurityEvent.id.asc()).limit(limit)
    ).all())
    created = updated = matches = 0
    for rule in rules:
        if rule.correlation:
            continue
        for event in events:
            if not rule_matches(event, rule):
                continue
            matches += 1
            fingerprint = hashlib.sha256(f"sigma:{rule.rule_id}:{event.id}".encode()).hexdigest()
            was_created, was_updated = _upsert_sigma_alert(
                db, rule=rule, fingerprint=fingerprint, evidence=[event],
                title=rule.title,
                description=rule.description or f"Sigma rule {rule.rule_id} matched event {event.id}.",
            )
            created += int(was_created)
            updated += int(was_updated)
    corr_matches, corr_created, corr_updated = _run_correlations(db, rules, events, now)
    return {
        "rules_evaluated": len(rules),
        "rule_ids_evaluated": [rule.rule_id for rule in rules],
        "events_evaluated": len(events),
        "matches": matches + corr_matches,
        "alerts_created": created + corr_created,
        "alerts_updated": updated + corr_updated,
    }
