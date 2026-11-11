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
