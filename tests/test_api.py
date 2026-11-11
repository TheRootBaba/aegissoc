from datetime import datetime, timedelta, timezone
from uuid import UUID

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.base import Base
from app.db.session import get_db
from app.main import app
from app import models  # noqa: F401


@pytest.fixture()
def client():
    test_engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    TestingSessionLocal = sessionmaker(bind=test_engine, autoflush=False, autocommit=False)
    Base.metadata.create_all(bind=test_engine)

    def override_get_db():
        db = TestingSessionLocal()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()
    Base.metadata.drop_all(bind=test_engine)


def sample_event(**overrides):
    payload = {
        "source": "pytest",
        "event_type": "authentication.failure",
        "severity": "medium",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "hostname": "lab-linux-01",
        "source_ip": "192.0.2.10",
        "username": "test-user",
        "message": "Synthetic failed login event",
        "raw": {"synthetic": True, "attempt": 1},
    }
    payload.update(overrides)
    return payload


def test_liveness(client):
    response = client.get("/health/live")
    assert response.status_code == 200
    assert response.json()["status"] == "alive"


def test_request_id_is_generated_and_returned(client):
    response = client.get("/health/live", headers={"X-Request-ID": "caller-controlled-value"})
    request_id = response.headers["X-Request-ID"]
    assert response.status_code == 200
    assert str(UUID(request_id)) == request_id
    assert request_id != "caller-controlled-value"


def test_ingest_and_retrieve_event(client):
    created = client.post("/api/v1/events", json=sample_event())
    assert created.status_code == 201
    event_id = created.json()["id"]

    fetched = client.get(f"/api/v1/events/{event_id}")
    assert fetched.status_code == 200
    assert fetched.json()["event_type"] == "authentication.failure"
    assert fetched.json()["raw"]["synthetic"] is True


def test_filter_events_by_severity(client):
    client.post("/api/v1/events", json=sample_event())
    response = client.get("/api/v1/events?severity=high")
    assert response.status_code == 200
    assert response.json() == []


def test_reject_timestamp_without_timezone(client):
    payload = sample_event()
    payload["timestamp"] = "2026-01-01T10:00:00"
    response = client.post("/api/v1/events", json=payload)
    assert response.status_code == 422


def test_event_pagination_is_bounded(client):
    response = client.get("/api/v1/events?limit=201")
    assert response.status_code == 422


def test_event_search_supports_exact_filters(client):
    client.post("/api/v1/events", json=sample_event())
    client.post(
        "/api/v1/events",
        json=sample_event(
            source="wazuh-lab",
            event_type="process.started",
            severity="low",
            hostname="workstation-02",
            source_ip="192.0.2.20",
        ),
    )
    response = client.get(
        "/api/v1/events?source=wazuh-lab&event_type=process.started&hostname=workstation-02"
    )
    assert response.status_code == 200
    assert len(response.json()) == 1
    assert response.json()[0]["source_ip"] == "192.0.2.20"


def test_event_search_supports_inclusive_time_range(client):
    now = datetime.now(timezone.utc)
    client.post("/api/v1/events", json=sample_event(timestamp=(now - timedelta(hours=2)).isoformat()))
    client.post("/api/v1/events", json=sample_event(timestamp=now.isoformat()))
    client.post("/api/v1/events", json=sample_event(timestamp=(now + timedelta(hours=2)).isoformat()))
    response = client.get(
        "/api/v1/events",
        params={
            "start_time": (now - timedelta(minutes=1)).isoformat(),
            "end_time": (now + timedelta(minutes=1)).isoformat(),
        },
    )
    assert response.status_code == 200
    assert len(response.json()) == 1


def test_event_search_rejects_naive_or_reversed_time_range(client):
    naive = client.get("/api/v1/events?start_time=2026-01-01T10:00:00")
    reversed_range = client.get(
        "/api/v1/events?start_time=2026-01-02T10:00:00Z&end_time=2026-01-01T10:00:00Z"
    )
    assert naive.status_code == 422
    assert reversed_range.status_code == 422


def test_normalized_ingest_endpoint_maps_source_payload(client):
    response = client.post(
        "/api/v1/events/ingest/syslog-lab",
        json={
            "@timestamp": "2026-11-11T12:00:00Z",
            "event": {"action": "authentication.failure", "severity": "warning"},
            "host": {"name": "linux-lab-01"},
            "src_ip": "192.0.2.44",
            "user": {"name": "analyst"},
            "message": "SSH login rejected",
        },
    )

    assert response.status_code == 201
    assert response.json()["source"] == "syslog-lab"
    assert response.json()["event_type"] == "authentication.failure"
    assert response.json()["severity"] == "medium"
    assert response.json()["hostname"] == "linux-lab-01"
    assert response.json()["source_ip"] == "192.0.2.44"
    assert response.json()["raw"]["event"]["action"] == "authentication.failure"


def test_normalized_ingest_rejects_invalid_source_payload_with_422(client):
    response = client.post(
        "/api/v1/events/ingest/syslog-lab",
        json={
            "event_type": "authentication.failure",
            "severity": "high",
            "message": "Timestamp intentionally omitted",
        },
    )

    assert response.status_code == 422


from datetime import datetime, timedelta, timezone


def test_detection_run_endpoint_creates_alert_and_alert_api_returns_evidence(client):
    now = datetime.now(timezone.utc)
    for attempt in range(5):
        response = client.post(
            "/api/v1/events",
            json=sample_event(
                timestamp=(now - timedelta(seconds=attempt)).isoformat(),
                message=f"Synthetic SSH login rejected, attempt {attempt + 1}",
            ),
        )
        assert response.status_code == 201

    detected = client.post(
        "/api/v1/detections/run",
        json={"window_minutes": 10, "threshold": 5},
    )

    assert detected.status_code == 200
    body = detected.json()
    assert body["rule_id"] == "AUTH-SSH-001"
    assert body["events_evaluated"] == 5
    assert body["alerts_created"] == 1
    assert len(body["alerts"][0]["evidence_event_ids"]) == 5

    listed = client.get("/api/v1/alerts?severity=medium")
    assert listed.status_code == 200
    assert len(listed.json()) == 1
    assert listed.json()[0]["source_ip"] == "192.0.2.10"


def test_detection_run_validates_threshold_and_window(client):
    invalid_threshold = client.post(
        "/api/v1/detections/run",
        json={"window_minutes": 10, "threshold": 1},
    )
    invalid_window = client.post(
        "/api/v1/detections/run",
        json={"window_minutes": 2000, "threshold": 5},
    )

    assert invalid_threshold.status_code == 422
    assert invalid_window.status_code == 422


def test_detection_engine_reports_both_ssh_rules_for_password_spray(client):
    now = datetime.now(timezone.utc)
    for attempt in range(5):
        client.post(
            "/api/v1/events",
            json=sample_event(
                timestamp=(now - timedelta(seconds=attempt)).isoformat(),
                username=f"account-{attempt}",
                message="SSH authentication failure",
            ),
        )

    response = client.post(
        "/api/v1/detections/run",
        json={"window_minutes": 10, "threshold": 5},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["rules_evaluated"] == ["AUTH-SSH-001", "AUTH-SSH-002"]
    assert {alert["rule_id"] for alert in body["alerts"]} == {
        "AUTH-SSH-001",
        "AUTH-SSH-002",
    }



def test_alert_lifecycle_assignment_notes_and_audit_history(client):
    now = datetime.now(timezone.utc)
    for attempt in range(5):
        client.post(
            "/api/v1/events",
            json=sample_event(
                timestamp=(now - timedelta(seconds=attempt)).isoformat(),
                message=f"SSH authentication failure attempt {attempt + 1}",
            ),
        )
    detected = client.post("/api/v1/detections/run", json={"window_minutes": 10, "threshold": 5})
    alert_id = detected.json()["alerts"][0]["id"]

    assigned = client.patch(
        f"/api/v1/alerts/{alert_id}",
        json={"actor": "analyst-01", "assigned_to": "analyst-01", "status": "acknowledged"},
    )
    assert assigned.status_code == 200
    assert assigned.json()["status"] == "acknowledged"
    assert assigned.json()["assigned_to"] == "analyst-01"
    assert assigned.json()["acknowledged_at"] is not None

    note = client.post(
        f"/api/v1/alerts/{alert_id}/notes",
        json={"author": "analyst-01", "body": "Confirmed this is a synthetic SSH test."},
    )
    assert note.status_code == 201
    assert note.json()["body"] == "Confirmed this is a synthetic SSH test."
    assert note.json()["id"] != ""

    notes = client.get(f"/api/v1/alerts/{alert_id}/notes")
    history = client.get(f"/api/v1/alerts/{alert_id}/history")
    assert len(notes.json()) == 1
    assert [entry["action"] for entry in history.json()] == ["alert.updated", "note.added"]
    assert history.json()[0]["details"]["status"]["to"] == "acknowledged"

    resolved = client.patch(
        f"/api/v1/alerts/{alert_id}",
        json={"actor": "analyst-01", "status": "resolved"},
    )
    assert resolved.status_code == 200
    assert resolved.json()["status"] == "resolved"
    assert resolved.json()["resolved_at"] is not None


def test_alert_lifecycle_rejects_invalid_transition_and_empty_update(client):
    now = datetime.now(timezone.utc)
    for attempt in range(5):
        client.post(
            "/api/v1/events",
            json=sample_event(
                timestamp=(now - timedelta(seconds=attempt)).isoformat(),
                message=f"SSH authentication failure attempt {attempt + 1}",
            ),
        )
    alert_id = client.post(
        "/api/v1/detections/run",
        json={"window_minutes": 10, "threshold": 5},
    ).json()["alerts"][0]["id"]

    invalid = client.patch(
        f"/api/v1/alerts/{alert_id}",
        json={"actor": "analyst-01", "status": "resolved"},
    )
    empty = client.patch(f"/api/v1/alerts/{alert_id}", json={"actor": "analyst-01"})
    assert invalid.status_code == 409
    assert empty.status_code == 422
    assert client.get(f"/api/v1/alerts/{alert_id}").json()["status"] == "open"


def test_alert_notes_validate_content_and_alert_existence(client):
    missing = client.post(
        "/api/v1/alerts/00000000-0000-0000-0000-000000000000/notes",
        json={"author": "analyst-01", "body": "This alert does not exist."},
    )
    assert missing.status_code == 404
