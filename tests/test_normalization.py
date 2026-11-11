from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from app.services.event_normalizer import normalize_event


def test_normalizer_maps_nested_fields_and_severity_aliases():
    source_payload = {
        "@timestamp": "2026-11-11T12:00:00Z",
        "event": {"action": "authentication.failure", "severity": "warning"},
        "host": {"name": "linux-lab-01"},
        "src_ip": "192.0.2.44",
        "user": {"name": "analyst"},
        "message": "SSH login rejected",
    }

    event = normalize_event(source_payload, source="syslog-lab")

    assert event.source == "syslog-lab"
    assert event.event_type == "authentication.failure"
    assert event.severity == "medium"
    assert event.timestamp == datetime(2026, 11, 11, 12, 0, tzinfo=timezone.utc)
    assert event.hostname == "linux-lab-01"
    assert event.source_ip == "192.0.2.44"
    assert event.username == "analyst"
    assert event.message == "SSH login rejected"
    assert event.raw == source_payload


def test_normalizer_accepts_severity_alias_and_explicit_raw():
    event = normalize_event(
        {
            "timestamp": "2026-11-11T12:00:00Z",
            "event_type": "process.started",
            "severity": "informational",
            "source_ip": "192.0.2.8",
            "message": "Process started",
            "raw": {"original": "source record"},
        },
        source="endpoint-agent",
    )

    assert event.severity == "info"
    assert event.source_ip == "192.0.2.8"
    assert event.raw == {"original": "source record"}


def test_normalizer_requires_timestamp_and_does_not_invent_one():
    with pytest.raises(ValidationError):
        normalize_event(
            {
                "event_type": "authentication.failure",
                "severity": "high",
                "message": "Failed login",
            },
            source="syslog",
        )


def test_normalizer_rejects_unknown_severity():
    with pytest.raises(ValidationError):
        normalize_event(
            {
                "timestamp": "2026-11-11T12:00:00Z",
                "event_type": "authentication.failure",
                "severity": "urgent-ish",
                "message": "Failed login",
            },
            source="syslog",
        )
