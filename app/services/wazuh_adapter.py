"""Translate native Wazuh JSON alerts into AegisSOC's canonical event schema.

This adapter intentionally accepts the documented alert envelope rather than
guessing missing timestamps, hosts, or severity. The complete input is retained
for downstream investigation and forensic context.
"""
from collections.abc import Mapping
from typing import Any

from app.schemas.events import SecurityEventCreate


def _path(payload: Mapping[str, Any], *parts: str) -> Any:
    value: Any = payload
    for part in parts:
        if not isinstance(value, Mapping):
            return None
        value = value.get(part)
    return value


def _first(*values: Any) -> Any:
    return next((value for value in values if value not in (None, "")), None)


def _wazuh_severity(level: Any) -> str:
    try:
        numeric = int(level)
    except (TypeError, ValueError) as exc:
        raise ValueError("Wazuh rule.level must be an integer from 0 to 15") from exc
    if not 0 <= numeric <= 15:
        raise ValueError("Wazuh rule.level must be between 0 and 15")
    if numeric <= 3:
        return "info"
    if numeric <= 7:
        return "low"
    if numeric <= 11:
        return "medium"
    if numeric <= 14:
        return "high"
    return "critical"


def normalize_wazuh_alert(payload: Mapping[str, Any]) -> SecurityEventCreate:
    """Convert one Wazuh alert JSON object to a validated canonical event."""
    if not isinstance(payload, Mapping):
        raise TypeError("Wazuh alert must be a JSON object")

    rule = payload.get("rule") if isinstance(payload.get("rule"), Mapping) else {}
    agent = payload.get("agent") if isinstance(payload.get("agent"), Mapping) else {}
    data = payload.get("data") if isinstance(payload.get("data"), Mapping) else {}
    groups = rule.get("groups") or []
    if isinstance(groups, str):
        groups = [groups]
    group_text = " ".join(str(item) for item in groups).lower()
    description = str(rule.get("description") or "")
    full_log = str(_first(payload.get("full_log"), payload.get("message"), description) or "")
    context = f"{group_text} {description} {full_log}".lower()

    is_ssh = any(token in context for token in ("ssh", "sshd"))
    is_auth_failure = any(
        token in context
        for token in ("authentication failed", "authentication failure", "failed password", "invalid user", "login failed", "authentication_failed")
    )
    event_type = "authentication.failure" if is_ssh and is_auth_failure else "wazuh.alert"

    timestamp = _first(payload.get("timestamp"), payload.get("@timestamp"))
    rule_level = _first(rule.get("level"), payload.get("level"))
    severity = _wazuh_severity(rule_level)
    external_id = _first(payload.get("id"), _path(payload, "alert", "id"))

    return SecurityEventCreate.model_validate(
        {
            "source": "wazuh",
            "external_id": str(external_id) if external_id is not None else None,
            "event_type": event_type,
            "severity": severity,
            "timestamp": timestamp,
            "hostname": _first(agent.get("name"), _path(payload, "host", "name")),
            "source_ip": _first(data.get("srcip"), data.get("src_ip"), data.get("source_ip")),
            "username": _first(data.get("dstuser"), data.get("srcuser"), _path(payload, "user", "name")),
            "message": full_log or description or "Wazuh alert",
            "raw": dict(payload),
        }
    )
