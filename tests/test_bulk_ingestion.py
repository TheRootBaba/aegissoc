from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.base import Base
from app.db.session import get_db
from app.main import app


@pytest.fixture()
def bulk_client():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    testing_sessions = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    Base.metadata.create_all(bind=engine)

    def override_get_db():
        db = testing_sessions()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.pop(get_db, None)
    Base.metadata.drop_all(bind=engine)
    engine.dispose()


def source_event(external_id: str, **overrides):
    payload = {
        "id": external_id,
        "@timestamp": datetime.now(timezone.utc).isoformat(),
        "event": {"action": "authentication.failure", "severity": "warning"},
        "host": {"name": "linux-lab-01"},
        "src_ip": "192.0.2.44",
        "user": {"name": "analyst"},
        "message": "Synthetic SSH authentication failure",
    }
    payload.update(overrides)
    return payload


def test_bulk_ingest_reports_partial_success_and_deduplicates_replays(bulk_client):
    first = source_event("sensor-001")
    replay = source_event("sensor-001", message="Changed replay must not overwrite original")
    second = source_event("sensor-002")
    invalid = {"event": {"action": "authentication.failure"}, "message": "Timestamp missing"}

    response = bulk_client.post(
        "/api/v1/events/ingest/lab-sensor/bulk",
        json={"events": [first, replay, invalid, second]},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["received"] == 4
    assert body["accepted"] == 2
    assert body["duplicates"] == 1
    assert body["rejected"] == 1
    assert [item["status"] for item in body["results"]] == [
        "accepted", "duplicate", "rejected", "accepted"
    ]
    assert body["results"][0]["event_id"] == body["results"][1]["event_id"]
    assert body["results"][2]["index"] == 2
    assert bulk_client.get("/api/v1/events/stats").json()["total_events"] == 2

    original = bulk_client.get(
        f"/api/v1/events/{body['results'][0]['event_id']}"
    ).json()
    assert original["message"] == "Synthetic SSH authentication failure"
    assert original["external_id"] == "sensor-001"


def test_single_event_ingestion_uses_the_same_race_safe_idempotency_contract(bulk_client):
    payload = {
        "source": "direct-sensor",
        "event_type": "process.started",
        "severity": "low",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "external_id": "event-42",
        "message": "Synthetic process start",
        "raw": {"synthetic": True},
    }

    first = bulk_client.post("/api/v1/events", json=payload)
    replay = bulk_client.post(
        "/api/v1/events",
        json={**payload, "message": "Replay must not replace the first event"},
    )

    assert first.status_code == 201
    assert replay.status_code == 200
    assert replay.json()["id"] == first.json()["id"]
    assert replay.json()["message"] == "Synthetic process start"
    assert bulk_client.get("/api/v1/events/stats").json()["total_events"] == 1


@pytest.mark.parametrize(
    "events",
    [
        [],
        [{"id": "too-many"}] * 501,
    ],
)
def test_bulk_ingest_rejects_empty_or_oversized_batches(bulk_client, events):
    response = bulk_client.post(
        "/api/v1/events/ingest/lab-sensor/bulk",
        json={"events": events},
    )
    assert response.status_code == 422
    assert bulk_client.get("/api/v1/events/stats").json()["total_events"] == 0


def test_bulk_ingest_can_report_all_records_rejected_without_creating_rows(bulk_client):
    response = bulk_client.post(
        "/api/v1/events/ingest/lab-sensor/bulk",
        json={"events": [{"severity": "do-not-echo-this-value"}]},
    )

    assert response.status_code == 200
    assert response.json()["accepted"] == 0
    assert response.json()["duplicates"] == 0
    assert response.json()["rejected"] == 1
    assert "do-not-echo-this-value" not in response.json()["results"][0]["error"]
    assert bulk_client.get("/api/v1/events/stats").json()["total_events"] == 0
