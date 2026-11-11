"""Translate common source-specific event envelopes into the AegisSOC contract."""

from collections.abc import Mapping
from typing import Any

from app.schemas.events import SecurityEventCreate


_SEVERITY_ALIASES = {
    "informational": "info",
    "information": "info",
    "notice": "info",
    "warning": "medium",
    "warn": "medium",
    "error": "high",
    "err": "high",
    "fatal": "critical",
}


def _read_path(payload: Mapping[str, Any], path: str) -> Any:
    """Read a dotted field path from nested dictionaries."""
    value: Any = payload
    for part in path.split("."):
        if not isinstance(value, Mapping) or part not in value:
            return None
        value = value[part]
    return value


def _first(payload: Mapping[str, Any], *paths: str) -> Any:
    """Return the first present, non-empty candidate field."""
    for path in paths:
        value = _read_path(payload, path)
        if value is not None and value != "":
            return value
    return None


def normalize_event(
    payload: Mapping[str, Any],
    *,
    source: str | None = None,
) -> SecurityEventCreate:
    """Normalize common aliases and validate the canonical event contract.

    The original payload is retained in raw unless it supplies a dictionary-
    valued raw field. Required fields are never guessed.
    """
    if not isinstance(payload, Mapping):
        raise TypeError("payload must be a mapping")

    severity = _first(payload, "severity", "event.severity", "level")
    if isinstance(severity, str):
        severity = _SEVERITY_ALIASES.get(severity.strip().lower(), severity.strip().lower())

    supplied_raw = payload.get("raw")
    raw = supplied_raw if isinstance(supplied_raw, dict) else dict(payload)

    normalized = {
        "source": source or _first(payload, "source", "source_name", "observer.name"),
        "event_type": _first(payload, "event_type", "event.action", "event.type", "type", "action"),
        "severity": severity,
        "timestamp": _first(payload, "timestamp", "@timestamp", "time", "event.created"),
        "hostname": _first(payload, "hostname", "host.name", "agent.name"),
        "source_ip": _first(payload, "source_ip", "src_ip", "source.ip", "client.ip"),
        "username": _first(payload, "username", "user.name", "user"),
        "external_id": _first(payload, "external_id", "event.id", "id"),
        "message": _first(payload, "message", "full_log", "event.original"),
        "raw": raw,
    }
    return SecurityEventCreate.model_validate(normalized)
