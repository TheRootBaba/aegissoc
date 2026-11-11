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
    # Mirror the defaults inserted by Alembic revision 0010 in the isolated test DB.
    from app.models import DetectionRuleConfig, RetentionPolicy, Workspace
    seed_session = TestingSessionLocal()
    default_workspace = Workspace(slug='default', name='Default Workspace', is_active=True)
    seed_session.info['workspace_id'] = str(default_workspace.id)
    seed_session.add_all([
        default_workspace,
        RetentionPolicy(data_kind="events", retention_days=90, enabled=True, preserve_active_evidence=True, updated_by="system"),
        RetentionPolicy(data_kind="executions", retention_days=180, enabled=True, preserve_active_evidence=True, updated_by="system"),
        RetentionPolicy(data_kind="jobs", retention_days=90, enabled=True, preserve_active_evidence=False, updated_by="system"),
        *[
            DetectionRuleConfig(rule_id=rule_id, enabled=True, updated_by="system")
            for rule_id in ("AUTH-SSH-001", "AUTH-SSH-002", "AUTH-CHAIN-001", "PRIV-ESC-001", "PROC-SUSP-001")
        ],
    ])
    seed_session.commit()
    seed_session.close()
    app.state.testing_session_factory = TestingSessionLocal

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
    app.state.testing_session_factory = None
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
    assert body["rules_evaluated"] == [
        "AUTH-SSH-001", "AUTH-SSH-002", "AUTH-CHAIN-001", "PRIV-ESC-001", "PROC-SUSP-001",
    ]
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



def test_analyst_dashboard_and_static_assets_are_served(client):
    dashboard = client.get("/dashboard")
    script = client.get("/static/app.js")
    stylesheet = client.get("/static/styles.css")

    assert dashboard.status_code == 200
    assert "AegisSOC" in dashboard.text
    assert "/static/app.js" in dashboard.text
    assert script.status_code == 200
    assert "/api/v1/detections/run" in script.text
    assert stylesheet.status_code == 200


def wazuh_alert(**overrides):
    payload = {
        "id": "1710000000.12345",
        "timestamp": "2026-11-11T12:30:00Z",
        "rule": {
            "id": "5710",
            "level": 10,
            "description": "sshd: authentication failed",
            "groups": ["authentication_failed", "sshd"],
        },
        "agent": {"id": "007", "name": "ubuntu-wazuh-01"},
        "data": {"srcip": "198.51.100.24", "dstuser": "root"},
        "full_log": "Nov 11 sshd[123]: Failed password for root from 198.51.100.24 port 22",
    }
    payload.update(overrides)
    return payload


def test_wazuh_adapter_normalizes_native_alert_and_preserves_raw(client):
    response = client.post("/api/v1/events/ingest/wazuh", json=wazuh_alert())
    assert response.status_code == 201
    event = response.json()
    assert event["source"] == "wazuh"
    assert event["external_id"] == "1710000000.12345"
    assert event["event_type"] == "authentication.failure"
    assert event["severity"] == "medium"
    assert event["hostname"] == "ubuntu-wazuh-01"
    assert event["source_ip"] == "198.51.100.24"
    assert event["username"] == "root"
    assert event["raw"]["rule"]["id"] == "5710"
    assert event["raw"]["data"]["srcip"] == "198.51.100.24"


def test_wazuh_ingestion_is_idempotent_for_replayed_alert_ids(client):
    first = client.post("/api/v1/events/ingest/wazuh", json=wazuh_alert())
    replay = client.post("/api/v1/events/ingest/wazuh", json=wazuh_alert())
    listed = client.get("/api/v1/events?source=wazuh")
    assert first.status_code == 201
    assert replay.status_code == 200
    assert replay.json()["id"] == first.json()["id"]
    assert len(listed.json()) == 1


@pytest.mark.parametrize(
    ("level", "expected"),
    [(0, "info"), (3, "info"), (4, "low"), (7, "low"), (8, "medium"), (11, "medium"), (12, "high"), (14, "high"), (15, "critical")],
)
def test_wazuh_rule_level_maps_to_canonical_severity(client, level, expected):
    payload = wazuh_alert(id=f"wazuh-level-{level}")
    payload["rule"]["level"] = level
    response = client.post("/api/v1/events/ingest/wazuh", json=payload)
    assert response.status_code == 201
    assert response.json()["severity"] == expected


def test_wazuh_non_ssh_alert_is_not_misclassified_as_ssh_authentication(client):
    payload = wazuh_alert(id="wazuh-firewall-01")
    payload["rule"]["description"] = "Firewall policy changed"
    payload["rule"]["groups"] = ["firewall", "configuration_changed"]
    payload["full_log"] = "Firewall policy was updated"
    response = client.post("/api/v1/events/ingest/wazuh", json=payload)
    assert response.status_code == 201
    assert response.json()["event_type"] == "wazuh.alert"


@pytest.mark.parametrize("level", [-1, 16, "urgent", None])
def test_wazuh_invalid_rule_level_is_rejected(client, level):
    payload = wazuh_alert(id=f"invalid-level-{level}")
    payload["rule"]["level"] = level
    response = client.post("/api/v1/events/ingest/wazuh", json=payload)
    assert response.status_code == 422


def test_wazuh_missing_timestamp_is_rejected(client):
    payload = wazuh_alert(id="missing-timestamp")
    payload.pop("timestamp")
    response = client.post("/api/v1/events/ingest/wazuh", json=payload)
    assert response.status_code == 422


def test_detection_alerts_include_mitre_attack_mapping(client):
    now = datetime.now(timezone.utc)
    for attempt in range(5):
        payload = sample_event(
            timestamp=(now - timedelta(seconds=attempt)).isoformat(),
            message=f"sshd: Failed password attempt {attempt + 1}",
            username=f"account-{attempt}",
        )
        client.post("/api/v1/events", json=payload)
    run = client.post("/api/v1/detections/run", json={"window_minutes": 10, "threshold": 5})
    assert run.status_code == 200
    mappings = {item["rule_id"]: item for item in run.json()["alerts"]}
    assert mappings["AUTH-SSH-001"]["attack_tactic"] == "Credential Access"
    assert mappings["AUTH-SSH-001"]["attack_technique_id"] == "T1110"
    assert mappings["AUTH-SSH-001"]["attack_technique_name"] == "Brute Force"
    assert mappings["AUTH-SSH-002"]["attack_technique_id"] == "T1110.003"
    detail = client.get(f"/api/v1/alerts/{mappings['AUTH-SSH-002']['id']}")
    assert detail.json()["attack_technique_id"] == "T1110.003"


def test_wazuh_alerts_flow_through_detection_engine_with_attack_mapping(client):
    now = datetime.now(timezone.utc)
    for attempt in range(5):
        payload = wazuh_alert(id=f"wazuh-ssh-{attempt}")
        payload["timestamp"] = (now - timedelta(seconds=attempt)).isoformat()
        payload["data"]["dstuser"] = f"wazuh-user-{attempt}"
        response = client.post("/api/v1/events/ingest/wazuh", json=payload)
        assert response.status_code == 201

    run = client.post("/api/v1/detections/run", json={"window_minutes": 10, "threshold": 5})
    assert run.status_code == 200
    brute_force = next(a for a in run.json()["alerts"] if a["rule_id"] == "AUTH-SSH-001")
    assert brute_force["attack_technique_id"] == "T1110"
    assert brute_force["event_count"] == 5


def test_source_event_id_is_scoped_to_source_name(client):
    first = client.post("/api/v1/events", json=sample_event(source="wazuh-a", external_id="same-id"))
    duplicate = client.post("/api/v1/events", json=sample_event(source="wazuh-a", external_id="same-id"))
    other_source = client.post("/api/v1/events", json=sample_event(source="wazuh-b", external_id="same-id"))
    assert first.status_code == 201
    assert duplicate.status_code == 200
    assert duplicate.json()["id"] == first.json()["id"]
    assert other_source.status_code == 201
    assert other_source.json()["id"] != first.json()["id"]


def test_wazuh_missing_rule_level_is_rejected(client):
    payload = wazuh_alert(id="missing-level")
    payload["rule"].pop("level")
    response = client.post("/api/v1/events/ingest/wazuh", json=payload)
    assert response.status_code == 422


def test_alert_search_filters_by_attack_technique_and_status(client):
    now = datetime.now(timezone.utc)
    for attempt in range(5):
        client.post(
            "/api/v1/events",
            json=sample_event(
                timestamp=(now - timedelta(seconds=attempt)).isoformat(),
                username=f"filter-user-{attempt}",
                message=f"sshd: Failed password attempt {attempt}",
            ),
        )
    run = client.post("/api/v1/detections/run", json={"window_minutes": 10, "threshold": 5})
    brute = next(a for a in run.json()["alerts"] if a["rule_id"] == "AUTH-SSH-001")
    filtered = client.get("/api/v1/alerts", params={"attack_technique_id": "T1110", "status": "open"})
    assert filtered.status_code == 200
    assert [a["id"] for a in filtered.json()] == [brute["id"]]

    wrong = client.get("/api/v1/alerts", params={"attack_technique_id": "T1110.003", "rule_id": "AUTH-SSH-001"})
    assert wrong.status_code == 200
    assert wrong.json() == []


def test_aggregate_stats_report_all_events_and_alerts(client):
    now = datetime.now(timezone.utc)
    for attempt in range(5):
        client.post(
            "/api/v1/events",
            json=sample_event(
                timestamp=(now - timedelta(seconds=attempt)).isoformat(),
                username=f"stats-user-{attempt}",
                message=f"sshd: Failed password attempt {attempt}",
            ),
        )
    client.post("/api/v1/detections/run", json={"window_minutes": 10, "threshold": 5})

    event_stats = client.get("/api/v1/events/stats")
    alert_stats = client.get("/api/v1/alerts/stats")
    assert event_stats.status_code == 200
    assert event_stats.json()["total_events"] == 5
    assert event_stats.json()["by_severity"]["medium"] == 5
    assert alert_stats.status_code == 200
    assert alert_stats.json()["total_alerts"] == 2
    assert alert_stats.json()["by_status"]["open"] == 2
    assert alert_stats.json()["by_severity"]["high"] == 1


def test_event_search_can_filter_by_external_source_identifier(client):
    client.post("/api/v1/events", json=sample_event(external_id="wazuh-alert-lookup"))
    response = client.get("/api/v1/events", params={"external_id": "wazuh-alert-lookup"})
    assert response.status_code == 200
    assert len(response.json()) == 1
    assert response.json()[0]["external_id"] == "wazuh-alert-lookup"


def test_admin_can_create_user_and_user_can_login(client):
    created = client.post("/api/v1/auth/users", json={
        "username": "new-analyst",
        "password": "strong-test-password-2026",
        "role": "analyst",
    })
    assert created.status_code == 201
    assert created.json()["role"] == "analyst"
    assert "password_hash" not in created.json()

    login = client.post("/api/v1/auth/login", json={
        "username": "new-analyst",
        "password": "strong-test-password-2026",
    })
    assert login.status_code == 200
    token = login.json()["access_token"]
    from app.core.security import get_current_user
    app.dependency_overrides.pop(get_current_user, None)
    identity = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert identity.status_code == 200
    assert identity.json()["username"] == "new-analyst"
    assert identity.json()["role"] == "analyst"


def test_read_only_role_cannot_ingest_or_run_detections(client):
    from types import SimpleNamespace
    from app.core.security import get_current_user

    app.dependency_overrides[get_current_user] = lambda: SimpleNamespace(
        id=UUID("00000000-0000-0000-0000-000000000001"),
        username="viewer",
        role="read_only",
        is_active=True,
    )
    ingest = client.post("/api/v1/events", json=sample_event())
    detect = client.post("/api/v1/detections/run", json={"window_minutes": 10, "threshold": 5})
    read = client.get("/api/v1/events")
    assert ingest.status_code == 403
    assert detect.status_code == 403
    assert read.status_code == 200


def test_alert_audit_actor_is_bound_to_authenticated_user(client):
    now = datetime.now(timezone.utc)
    for attempt in range(5):
        client.post("/api/v1/events", json=sample_event(
            timestamp=(now - timedelta(seconds=attempt)).isoformat(),
            message=f"SSH authentication failure {attempt}",
        ))
    alert_id = client.post("/api/v1/detections/run", json={
        "window_minutes": 10, "threshold": 5
    }).json()["alerts"][0]["id"]
    changed = client.patch(f"/api/v1/alerts/{alert_id}", json={
        "actor": "forged-admin-name", "status": "acknowledged"
    })
    history = client.get(f"/api/v1/alerts/{alert_id}/history")
    assert changed.status_code == 200
    assert history.json()[0]["actor"] == "test-admin"


def test_login_returns_generic_failure_and_throttles_repeated_attempts(client):
    from app.core.security import clear_login_rate_limit
    clear_login_rate_limit("testclient")
    payload = {"username": "missing-user", "password": "strong-test-password"}
    for _ in range(5):
        response = client.post("/api/v1/auth/login", json=payload)
        assert response.status_code == 401
        assert response.json()["detail"] == "Invalid username or password"
    limited = client.post("/api/v1/auth/login", json=payload)
    assert limited.status_code == 429
    clear_login_rate_limit("testclient")


def test_source_inventory_tracks_single_and_bulk_ingestion_outcomes(client):
    first = client.post("/api/v1/events/ingest/inventory-lab", json={
        "@timestamp": datetime.now(timezone.utc).isoformat(),
        "event": {"action": "process.started", "severity": "info"},
        "host": {"name": "sensor-01"},
        "id": "inventory-event-1",
        "message": "Synthetic process start",
    })
    assert first.status_code == 201

    batch = {"events": [
        {
            "@timestamp": datetime.now(timezone.utc).isoformat(),
            "event": {"action": "network.connection", "severity": "low"},
            "host": {"name": "sensor-01"},
            "id": "inventory-event-2",
            "message": "Synthetic connection",
        },
        {
            "@timestamp": datetime.now(timezone.utc).isoformat(),
            "event": {"action": "network.connection", "severity": "low"},
            "host": {"name": "sensor-01"},
            "id": "inventory-event-2",
            "message": "Replay of the previous event",
        },
        {"id": "invalid-record", "message": "Missing timestamp and event severity"},
    ]}
    result = client.post("/api/v1/events/ingest/inventory-lab/bulk", json=batch)
    assert result.status_code == 200
    assert result.json()["accepted"] == 1
    assert result.json()["duplicates"] == 1
    assert result.json()["rejected"] == 1

    inventory = client.get("/api/v1/sources")
    assert inventory.status_code == 200
    source = next(item for item in inventory.json() if item["source_name"] == "inventory-lab")
    assert source["health_status"] == "healthy"
    assert source["accepted_events"] == 2
    assert source["duplicate_events"] == 1
    assert source["rejected_events"] == 1
    assert source["last_attempt_at"] is not None
    assert source["last_successful_event_at"] is not None

    detail = client.get("/api/v1/sources/inventory-lab")
    assert detail.status_code == 200
    assert detail.json()["source_name"] == "inventory-lab"


def test_source_registration_is_admin_only_and_rejects_duplicates(client):
    created = client.post("/api/v1/sources", json={
        "source_name": "registered-edr",
        "display_name": "Endpoint Detection",
        "source_type": "endpoint",
        "description": "Synthetic endpoint telemetry source",
    })
    assert created.status_code == 201
    assert created.json()["health_status"] == "inactive"

    duplicate = client.post("/api/v1/sources", json={
        "source_name": "registered-edr",
        "display_name": "Duplicate source",
        "source_type": "generic",
    })
    assert duplicate.status_code == 409

    invalid = client.post("/api/v1/sources", json={
        "source_name": "not a safe source name",
        "display_name": "Invalid",
    })
    assert invalid.status_code == 422


def test_source_inventory_reports_failed_and_unknown_sources(client):
    rejected = client.post("/api/v1/events/ingest/broken-sensor/bulk", json={
        "events": [{"id": "bad", "message": "missing required fields"}]
    })
    assert rejected.status_code == 200
    source = client.get("/api/v1/sources/broken-sensor")
    assert source.status_code == 200
    assert source.json()["health_status"] == "failing"
    assert source.json()["rejected_events"] == 1
    assert client.get("/api/v1/sources/does-not-exist").status_code == 404


def test_read_only_users_can_view_sources_but_cannot_register_them(client):
    from types import SimpleNamespace
    from uuid import UUID
    from app.core.security import get_current_user
    from app.main import app

    app.dependency_overrides[get_current_user] = lambda: SimpleNamespace(
        id=UUID("00000000-0000-0000-0000-000000000099"),
        username="viewer",
        role="read_only",
        is_active=True,
    )
    listed = client.get("/api/v1/sources")
    created = client.post("/api/v1/sources", json={
        "source_name": "viewer-source",
        "display_name": "Viewer Source",
        "source_type": "generic",
    })
    assert listed.status_code == 200
    assert created.status_code == 403


def test_investigation_query_combines_text_filters_time_and_aggregation(client):
    now = datetime.now(timezone.utc)
    client.post("/api/v1/events", json=sample_event(
        source="edr-lab", severity="high", username="alice",
        message="Suspicious powershell execution",
        timestamp=(now - timedelta(minutes=2)).isoformat(),
    ))
    client.post("/api/v1/events", json=sample_event(
        source="edr-lab", severity="high", username="bob",
        message="Suspicious script execution",
        timestamp=(now - timedelta(minutes=1)).isoformat(),
    ))
    client.post("/api/v1/events", json=sample_event(
        source="wazuh", severity="low", username="alice",
        message="Routine service start",
        timestamp=now.isoformat(),
    ))

    response = client.post("/api/v1/events/query", json={
        "search": "suspicious",
        "filters": [
            {"field": "severity", "operator": "eq", "value": "high"},
            {"field": "source", "operator": "starts_with", "value": "edr"},
        ],
        "start_time": (now - timedelta(minutes=5)).isoformat(),
        "end_time": now.isoformat(),
        "group_by": "username",
        "limit": 10,
    })
    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 2
    assert {event["username"] for event in body["events"]} == {"alice", "bob"}
    assert {item["value"] for item in body["aggregations"]} == {"alice", "bob"}
    assert sum(item["count"] for item in body["aggregations"]) == 2


def test_investigation_query_supports_in_exists_and_pagination(client):
    client.post("/api/v1/events", json=sample_event(source="wazuh", username="root"))
    client.post("/api/v1/events", json=sample_event(source="edr", username=None))
    response = client.post("/api/v1/events/query", json={
        "filters": [
            {"field": "source", "operator": "in", "value": ["wazuh", "edr"]},
            {"field": "username", "operator": "exists", "value": True},
        ],
        "limit": 1,
    })
    assert response.status_code == 200
    assert response.json()["total"] == 1
    assert len(response.json()["events"]) == 1


def test_investigation_query_rejects_unknown_fields_and_invalid_time_windows(client):
    unknown = client.post("/api/v1/events/query", json={
        "filters": [{"field": "raw.password", "operator": "eq", "value": "secret"}]
    })
    naive = client.post("/api/v1/events/query", json={
        "start_time": "2026-11-11T10:00:00",
    })
    reversed_range = client.post("/api/v1/events/query", json={
        "start_time": "2026-11-12T10:00:00Z",
        "end_time": "2026-11-11T10:00:00Z",
    })
    too_many_filters = client.post("/api/v1/events/query", json={
        "filters": [{"field": "source", "operator": "eq", "value": "x"}] * 21,
    })
    assert unknown.status_code == 422
    assert naive.status_code == 422
    assert reversed_range.status_code == 422
    assert too_many_filters.status_code == 422


def test_event_field_discovery_returns_bounded_facets(client):
    client.post("/api/v1/events", json=sample_event(source="edr-lab"))
    response = client.get("/api/v1/events/fields")
    assert response.status_code == 200
    body = response.json()
    assert "contains" in body["operators"]
    source = next(field for field in body["fields"] if field["name"] == "source")
    assert source["distinct_values"][0]["value"] == "edr-lab"
    assert source["distinct_values"][0]["count"] == 1


def test_saved_investigation_queries_are_persistent_and_deduplicated(client):
    payload = {
        "name": "High severity endpoint activity",
        "description": "High severity endpoint events",
        "query": {
            "filters": [{"field": "severity", "operator": "eq", "value": "high"}],
            "group_by": "source",
            "limit": 50,
        },
        "is_shared": True,
    }
    created = client.post("/api/v1/events/saved-queries", json=payload)
    assert created.status_code == 201
    assert created.json()["created_by"] == "test-admin"
    assert created.json()["query"]["filters"][0]["value"] == "high"

    duplicate = client.post("/api/v1/events/saved-queries", json=payload)
    assert duplicate.status_code == 409
    listed = client.get("/api/v1/events/saved-queries")
    assert listed.status_code == 200
    assert [item["id"] for item in listed.json()] == [created.json()["id"]]

    deleted = client.delete(f"/api/v1/events/saved-queries/{created.json()['id']}")
    assert deleted.status_code == 204
    assert client.get("/api/v1/events/saved-queries").json() == []


def test_read_only_analyst_cannot_create_saved_queries(client):
    from types import SimpleNamespace
    from app.core.security import get_current_user

    app.dependency_overrides[get_current_user] = lambda: SimpleNamespace(
        id=UUID("00000000-0000-0000-0000-000000000055"),
        username="viewer",
        role="read_only",
        is_active=True,
    )
    response = client.post("/api/v1/events/saved-queries", json={
        "name": "Not permitted",
        "query": {},
    })
    assert response.status_code == 403


def test_detection_correlates_repeated_failures_with_later_success(client):
    now = datetime.now(timezone.utc)
    for attempt in range(5):
        created = client.post("/api/v1/events", json=sample_event(
            event_type="authentication.failure",
            timestamp=(now - timedelta(seconds=10 - attempt)).isoformat(),
            username="compromised-user",
            message=f"Windows logon failure {attempt + 1}",
        ))
        assert created.status_code == 201
    success = client.post("/api/v1/events", json=sample_event(
        event_type="authentication.success",
        timestamp=now.isoformat(),
        username="compromised-user",
        message="Successful interactive logon",
    ))
    assert success.status_code == 201

    run = client.post("/api/v1/detections/run", json={"window_minutes": 10, "threshold": 5})
    assert run.status_code == 200
    alert = next(item for item in run.json()["alerts"] if item["rule_id"] == "AUTH-CHAIN-001")
    assert alert["severity"] == "high"
    assert alert["attack_technique_id"] == "T1110.001"
    assert alert["event_count"] == 6
    assert len(alert["evidence_event_ids"]) == 6


def test_detection_flags_privilege_escalation_event(client):
    now = datetime.now(timezone.utc)
    created = client.post("/api/v1/events", json=sample_event(
        event_type="privilege.escalation",
        severity="high",
        username="lab-user",
        message="User added to local administrators group",
        timestamp=now.isoformat(),
    ))
    assert created.status_code == 201
    run = client.post("/api/v1/detections/run", json={"window_minutes": 10, "threshold": 5})
    alert = next(item for item in run.json()["alerts"] if item["rule_id"] == "PRIV-ESC-001")
    assert alert["attack_technique_id"] == "T1548"
    assert alert["evidence_event_ids"] == [created.json()["id"]]


def test_detection_flags_suspicious_encoded_powershell_process(client):
    now = datetime.now(timezone.utc)
    created = client.post("/api/v1/events", json=sample_event(
        event_type="process.started",
        severity="medium",
        username="lab-user",
        message="powershell.exe -NoProfile -EncodedCommand SQBFAFgA",
        timestamp=now.isoformat(),
    ))
    assert created.status_code == 201
    run = client.post("/api/v1/detections/run", json={"window_minutes": 10, "threshold": 5})
    alert = next(item for item in run.json()["alerts"] if item["rule_id"] == "PROC-SUSP-001")
    assert alert["attack_technique_id"] == "T1059"
    assert created.json()["id"] in alert["evidence_event_ids"]


def test_authentication_success_before_failures_does_not_trigger_chain_rule(client):
    now = datetime.now(timezone.utc)
    client.post("/api/v1/events", json=sample_event(
        event_type="authentication.success",
        timestamp=(now - timedelta(minutes=1)).isoformat(),
        username="lab-user",
        message="Successful login",
    ))
    for attempt in range(5):
        client.post("/api/v1/events", json=sample_event(
            event_type="authentication.failure",
            timestamp=(now - timedelta(seconds=5 - attempt)).isoformat(),
            username="lab-user",
            message=f"Failed login {attempt}",
        ))
    run = client.post("/api/v1/detections/run", json={"window_minutes": 10, "threshold": 5})
    assert run.status_code == 200
    assert "AUTH-CHAIN-001" not in {item["rule_id"] for item in run.json()["alerts"]}


def test_cross_event_detection_refreshes_one_stable_alert_on_replay(client):
    now = datetime.now(timezone.utc)
    for attempt in range(5):
        client.post("/api/v1/events", json=sample_event(
            event_type="authentication.failure",
            timestamp=(now - timedelta(seconds=6 - attempt)).isoformat(),
            username="stable-user",
            message=f"Repeated authentication failure {attempt}",
        ))
    client.post("/api/v1/events", json=sample_event(
        event_type="authentication.success",
        timestamp=now.isoformat(),
        username="stable-user",
        message="Authentication succeeded",
    ))
    first = client.post("/api/v1/detections/run", json={"window_minutes": 10, "threshold": 5})
    second = client.post("/api/v1/detections/run", json={"window_minutes": 10, "threshold": 5})
    first_alert = next(item for item in first.json()["alerts"] if item["rule_id"] == "AUTH-CHAIN-001")
    second_alert = next(item for item in second.json()["alerts"] if item["rule_id"] == "AUTH-CHAIN-001")
    assert first.json()["alerts_created"] == 1
    assert second.json()["alerts_created"] == 0
    assert second.json()["alerts_updated"] == 1
    assert first_alert["id"] == second_alert["id"]


def test_detection_schedule_crud_and_execution_history(client):
    created = client.post("/api/v1/detection-schedules", json={
        "name": "Five-minute lab detection",
        "interval_seconds": 300,
        "window_minutes": 10,
        "threshold": 5,
    })
    assert created.status_code == 201
    schedule = created.json()
    assert schedule["enabled"] is True
    assert schedule["last_status"] is None

    duplicate = client.post("/api/v1/detection-schedules", json={
        "name": "Five-minute lab detection",
        "interval_seconds": 600,
    })
    assert duplicate.status_code == 409

    updated = client.patch(
        f"/api/v1/detection-schedules/{schedule['id']}",
        json={"enabled": False, "interval_seconds": 600},
    )
    assert updated.status_code == 200
    assert updated.json()["enabled"] is False
    assert updated.json()["interval_seconds"] == 600
    assert client.get(f"/api/v1/detection-schedules/{schedule['id']}/executions").json() == []

    deleted = client.delete(f"/api/v1/detection-schedules/{schedule['id']}")
    assert deleted.status_code == 204
    assert client.get("/api/v1/detection-schedules").json() == []


def test_scheduler_worker_executes_due_schedule_and_persists_result(client):
    from app.models import DetectionSchedule
    from app.services.detection_scheduler import run_due_schedules_once

    now = datetime.now(timezone.utc)
    created = client.post("/api/v1/detection-schedules", json={
        "name": "Due SSH detector",
        "interval_seconds": 300,
        "window_minutes": 10,
        "threshold": 5,
    })
    schedule_id = created.json()["id"]
    for attempt in range(5):
        response = client.post("/api/v1/events", json=sample_event(
            timestamp=(now - timedelta(seconds=5 - attempt)).isoformat(),
            message=f"SSH authentication failure {attempt}",
        ))
        assert response.status_code == 201

    with app.state.testing_session_factory() as db:
        schedule = db.get(DetectionSchedule, UUID(schedule_id))
        schedule.next_run_at = now - timedelta(seconds=1)
        db.commit()
        assert run_due_schedules_once(db, now=now) == 1

    executions = client.get(f"/api/v1/detection-schedules/{schedule_id}/executions")
    assert executions.status_code == 200
    assert len(executions.json()) == 1
    execution = executions.json()[0]
    assert execution["status"] == "success"
    assert execution["events_evaluated"] == 5
    assert execution["alerts_created"] == 1

    refreshed = client.get("/api/v1/detection-schedules").json()[0]
    assert refreshed["last_status"] == "success"
    assert refreshed["consecutive_failures"] == 0


def test_scheduler_failure_is_recorded_and_retried_without_leaking_exception_text(client):
    from app.models import DetectionSchedule
    from app.services.detection_scheduler import run_due_schedules_once

    now = datetime.now(timezone.utc)
    created = client.post("/api/v1/detection-schedules", json={
        "name": "Invalid legacy detector",
        "interval_seconds": 300,
        "window_minutes": 10,
        "threshold": 5,
    })
    schedule_id = UUID(created.json()["id"])
    with app.state.testing_session_factory() as db:
        schedule = db.get(DetectionSchedule, schedule_id)
        schedule.threshold = 1
        schedule.next_run_at = now - timedelta(seconds=1)
        db.commit()
        assert run_due_schedules_once(db, now=now) == 0

    execution = client.get(f"/api/v1/detection-schedules/{schedule_id}/executions").json()[0]
    assert execution["status"] == "failed"
    assert execution["error"] == "Detection execution failed (ValueError)"
    refreshed = client.get("/api/v1/detection-schedules").json()[0]
    assert refreshed["consecutive_failures"] == 1
    assert refreshed["last_status"] == "failed"
    assert datetime.fromisoformat(refreshed["next_run_at"]) > now


def test_detection_schedule_is_admin_only_and_validates_interval(client):
    from types import SimpleNamespace
    from app.core.security import get_current_user

    app.dependency_overrides[get_current_user] = lambda: SimpleNamespace(
        id=UUID("00000000-0000-0000-0000-000000000077"),
        username="viewer",
        role="read_only",
        is_active=True,
    )
    denied = client.post("/api/v1/detection-schedules", json={"name": "Viewer schedule"})
    assert denied.status_code == 403

    app.dependency_overrides[get_current_user] = lambda: SimpleNamespace(
        id=UUID("00000000-0000-0000-0000-000000000078"),
        username="admin",
        role="admin",
        is_active=True,
    )
    invalid = client.post("/api/v1/detection-schedules", json={
        "name": "Too frequent", "interval_seconds": 30,
    })
    assert invalid.status_code == 422


def test_global_audit_chain_records_operator_actions_and_verifies(client):
    created_user = client.post("/api/v1/auth/users", json={
        "username": "audited-analyst",
        "password": "strong-audit-password-2026",
        "role": "analyst",
    })
    assert created_user.status_code == 201
    created_source = client.post("/api/v1/sources", json={
        "source_name": "audited-edr",
        "display_name": "Audited Endpoint",
        "source_type": "endpoint",
    })
    assert created_source.status_code == 201

    entries = client.get("/api/v1/audit", params={"actor": "test-admin"})
    assert entries.status_code == 200
    assert [item["sequence"] for item in entries.json()] == [2, 1]
    assert {item["action"] for item in entries.json()} == {"user.created", "source.registered"}
    assert entries.json()[0]["previous_hash"] == entries.json()[1]["entry_hash"]

    verification = client.get("/api/v1/audit/verify")
    assert verification.status_code == 200
    assert verification.json()["valid"] is True
    assert verification.json()["checked_entries"] == 2
    assert verification.json()["head_sequence"] == 2


def test_audit_verification_detects_record_tampering(client):
    from app.models import SecurityAuditEntry

    created = client.post("/api/v1/auth/users", json={
        "username": "tamper-test-user",
        "password": "strong-audit-password-2026",
        "role": "analyst",
    })
    assert created.status_code == 201
    before = client.get("/api/v1/audit/verify")
    assert before.json()["valid"] is True

    with app.state.testing_session_factory() as db:
        entry = db.query(SecurityAuditEntry).filter_by(sequence=1).one()
        entry.details = {"role": "administrator", "tampered": True}
        db.commit()

    after = client.get("/api/v1/audit/verify")
    assert after.status_code == 200
    assert after.json()["valid"] is False
    assert after.json()["first_invalid_sequence"] == 1


def test_empty_audit_chain_verifies_and_read_only_cannot_verify(client):
    empty = client.get("/api/v1/audit/verify")
    assert empty.status_code == 200
    assert empty.json()["valid"] is True
    assert empty.json()["checked_entries"] == 0

    from types import SimpleNamespace
    from app.core.security import get_current_user
    app.dependency_overrides[get_current_user] = lambda: SimpleNamespace(
        id=UUID("00000000-0000-0000-0000-000000000066"),
        username="viewer",
        role="read_only",
        is_active=True,
    )
    listed = client.get("/api/v1/audit")
    verified = client.get("/api/v1/audit/verify")
    assert listed.status_code == 200
    assert verified.status_code == 403

def test_operations_metrics_and_health_endpoints(client):
    health = client.get("/api/v1/operations/health")
    metrics = client.get("/api/v1/operations/metrics")
    policies = client.get("/api/v1/operations/retention")
    assert health.status_code == 200
    assert health.json()["status"] == "operational"
    assert metrics.status_code == 200
    assert metrics.json()["events"]["total"] == 0
    assert metrics.json()["detection_executions"]["failed_last_24_hours"] == 0
    assert policies.status_code == 200
    assert {item["data_kind"] for item in policies.json()} == {"events", "executions", "jobs"}


def test_admin_can_update_retention_policy_and_action_is_audited(client):
    updated = client.put("/api/v1/operations/retention/events", json={
        "retention_days": 45,
        "enabled": True,
        "preserve_active_evidence": True,
    })
    assert updated.status_code == 200
    assert updated.json()["retention_days"] == 45
    audit = client.get("/api/v1/audit?action=retention.policy_updated")
    assert audit.status_code == 200
    assert audit.json()[0]["resource_id"] == "events"


def test_retention_cleanup_preserves_active_alert_evidence(client):
    from app.models import DetectionAlert, SecurityEvent
    factory = app.state.testing_session_factory
    db = factory()
    try:
        now = datetime.now(timezone.utc)
        protected = SecurityEvent(
            source="retention-test", event_type="authentication.failure",
            severity="high", timestamp=now - timedelta(days=200),
            message="Evidence linked to an active alert", raw={},
        )
        expired = SecurityEvent(
            source="retention-test", event_type="process.started",
            severity="low", timestamp=now - timedelta(days=200),
            message="Unreferenced expired event", raw={},
        )
        db.add_all([protected, expired])
        db.flush()
        alert = DetectionAlert(
            rule_id="RETENTION-TEST", fingerprint="retention-test-fingerprint",
            title="Active investigation", description="Evidence retention test",
            severity="high", status="open", event_count=1,
            first_seen=now, last_seen=now,
            evidence_event_ids=[str(protected.id)],
        )
        db.add(alert)
        db.commit()
        protected_id, expired_id = protected.id, expired.id
    finally:
        db.close()

    from app.services.retention import run_retention_cleanup
    db = factory()
    try:
        result = run_retention_cleanup(db, now=datetime.now(timezone.utc), batch_size=100)
        assert result["status"] == "success"
        assert db.get(SecurityEvent, protected_id) is not None
        assert db.get(SecurityEvent, expired_id) is None
    finally:
        db.close()


def test_connector_registry_validates_external_credentials_and_routes_ingest(client):
    created = client.post("/api/v1/connectors", json={
        "connector_key": "syslog-prod",
        "connector_type": "syslog",
        "display_name": "Production Syslog",
        "config": {"host": "syslog.example.internal", "port": 514, "transport": "udp"},
        "enabled": True,
    })
    assert created.status_code == 201
    connector_id = created.json()["id"]
    checked = client.post(f"/api/v1/connectors/{connector_id}/check")
    assert checked.status_code == 200
    assert checked.json()["configuration_valid"] is True
    assert "does not claim endpoint connectivity" in checked.json()["message"]

    ingested = client.post("/api/v1/events/ingest/syslog-prod", json={
        "@timestamp": datetime.now(timezone.utc).isoformat(),
        "event": {"action": "process.started", "severity": "info"},
        "host": {"name": "syslog-sensor-01"},
        "message": "Synthetic syslog event",
    })
    assert ingested.status_code == 201
    assert ingested.json()["source"] == "syslog-prod"
    observed = client.get("/api/v1/connectors")
    assert observed.json()[0]["health_status"] == "observed"


def test_connector_rejects_inline_secrets_and_invalid_wazuh_configuration(client):
    inline_secret = client.post("/api/v1/connectors", json={
        "connector_key": "bad-connector",
        "connector_type": "generic",
        "display_name": "Bad connector",
        "config": {"api_token": "must-not-be-stored"},
    })
    missing_credential = client.post("/api/v1/connectors", json={
        "connector_key": "wazuh-incomplete",
        "connector_type": "wazuh",
        "display_name": "Incomplete Wazuh",
        "config": {"manager_url": "https://wazuh.example.internal"},
    })
    assert inline_secret.status_code == 422
    assert missing_credential.status_code == 422


def test_retention_preserves_latest_execution_for_each_schedule(client):
    from app.models import DetectionExecution, DetectionSchedule
    from app.services.retention import run_retention_cleanup
    factory = app.state.testing_session_factory
    db = factory()
    try:
        now = datetime.now(timezone.utc)
        schedule = DetectionSchedule(
            name="retention execution test", interval_seconds=300,
            window_minutes=10, threshold=5, enabled=True,
            next_run_at=now, created_by="test-admin",
        )
        db.add(schedule)
        db.flush()
        old = DetectionExecution(
            schedule_id=schedule.id, status="success",
            started_at=now - timedelta(days=250), completed_at=now - timedelta(days=250),
            duration_ms=10, events_evaluated=10, alerts_created=0,
            alerts_updated=0, rules_evaluated=[], error=None,
        )
        latest = DetectionExecution(
            schedule_id=schedule.id, status="success",
            started_at=now - timedelta(days=200), completed_at=now - timedelta(days=200),
            duration_ms=10, events_evaluated=12, alerts_created=0,
            alerts_updated=0, rules_evaluated=[], error=None,
        )
        db.add_all([old, latest])
        db.commit()
        old_id, latest_id = old.id, latest.id
    finally:
        db.close()

    db = factory()
    try:
        run_retention_cleanup(db, now=datetime.now(timezone.utc), batch_size=100)
        assert db.get(DetectionExecution, old_id) is None
        assert db.get(DetectionExecution, latest_id) is not None
    finally:
        db.close()




def test_disabled_connector_cannot_be_bypassed_through_canonical_ingest(client):
    created = client.post("/api/v1/connectors", json={
        "connector_key": "disabled-source",
        "connector_type": "generic",
        "display_name": "Disabled source",
        "config": {},
        "enabled": True,
    })
    assert created.status_code == 201
    connector_id = created.json()["id"]
    disabled = client.patch(f"/api/v1/connectors/{connector_id}", json={"enabled": False})
    assert disabled.status_code == 200
    rejected = client.post("/api/v1/events", json=sample_event(source="disabled-source"))
    assert rejected.status_code == 422
    assert "disabled" in rejected.json()["detail"].lower()


def test_connector_rejects_nested_secret_fields(client):
    response = client.post("/api/v1/connectors", json={
        "connector_key": "nested-secret",
        "connector_type": "generic",
        "display_name": "Nested secret",
        "config": {"auth": {"clientSecret": "not-allowed"}},
    })
    assert response.status_code == 422



def test_incident_case_lifecycle_links_alerts_notes_and_audit_timeline(client):
    now = datetime.now(timezone.utc)
    for attempt in range(5):
        created = client.post("/api/v1/events", json=sample_event(
            timestamp=(now - timedelta(seconds=5 - attempt)).isoformat(),
            message=f"SSH authentication failure {attempt}",
        ))
        assert created.status_code == 201
    detection = client.post("/api/v1/detections/run", json={"window_minutes": 10, "threshold": 5})
    assert detection.status_code == 200
    alert_id = next(item["id"] for item in detection.json()["alerts"] if item["rule_id"] == "AUTH-SSH-001")

    created_case = client.post("/api/v1/cases", json={
        "title": "Repeated SSH access attempts",
        "description": "Investigate authentication activity against the Linux edge host.",
        "priority": "p1",
        "severity": "high",
        "tags": ["credential-access", " SSH ", "credential-access"],
    })
    assert created_case.status_code == 201
    case = created_case.json()
    assert case["case_number"].startswith("AEG-")
    assert case["tags"] == ["credential-access", "ssh"]

    linked = client.post(f"/api/v1/cases/{case['id']}/alerts/{alert_id}")
    assert linked.status_code == 201
    duplicate = client.post(f"/api/v1/cases/{case['id']}/alerts/{alert_id}")
    assert duplicate.status_code == 409

    note = client.post(f"/api/v1/cases/{case['id']}/notes", json={"body": "Validated source IP and preserved event evidence."})
    assert note.status_code == 201
    updated = client.patch(f"/api/v1/cases/{case['id']}", json={"status": "investigating", "assignee": "analyst-1"})
    assert updated.status_code == 200
    assert updated.json()["status"] == "investigating"

    detail = client.get(f"/api/v1/cases/{case['id']}")
    assert detail.status_code == 200
    assert len(detail.json()["alerts"]) == 1
    assert len(detail.json()["notes"]) == 1
    assert {item["action"] for item in detail.json()["timeline"]} >= {
        "case.created", "case.alert_linked", "case.note_added", "case.updated"
    }
    assert client.get("/api/v1/cases?status=investigating&priority=p1").json()[0]["id"] == case["id"]


def test_incident_case_rejects_invalid_transitions_and_read_only_cannot_mutate(client):
    created = client.post("/api/v1/cases", json={"title": "Case transition guard"})
    assert created.status_code == 201
    case_id = created.json()["id"]
    invalid = client.patch(f"/api/v1/cases/{case_id}", json={"status": "recovered"})
    assert invalid.status_code == 409
    assert client.get(f"/api/v1/cases/{case_id}").status_code == 200


def test_detection_rule_governance_controls_engine_enablement_and_tuning(client):
    rules = client.get("/api/v1/detection-rules")
    assert rules.status_code == 200
    assert len(rules.json()) == 5

    disabled = client.patch("/api/v1/detection-rules/AUTH-SSH-001", json={"enabled": False})
    assert disabled.status_code == 200
    assert disabled.json()["enabled"] is False

    now = datetime.now(timezone.utc)
    for attempt in range(5):
        client.post("/api/v1/events", json=sample_event(
            timestamp=(now - timedelta(seconds=5 - attempt)).isoformat(),
            message=f"SSH authentication failure {attempt}",
        ))
    run = client.post("/api/v1/detections/run", json={"window_minutes": 10, "threshold": 5})
    assert run.status_code == 200
    assert "AUTH-SSH-001" not in {item["rule_id"] for item in run.json()["alerts"]}
    assert "AUTH-SSH-001" not in run.json()["rules_evaluated"]

    enabled = client.patch("/api/v1/detection-rules/AUTH-SSH-001", json={
        "enabled": True, "threshold_override": 2, "severity_override": "critical",
    })
    assert enabled.status_code == 200
    rerun = client.post("/api/v1/detections/run", json={"window_minutes": 10, "threshold": 5})
    brute_force = next(item for item in rerun.json()["alerts"] if item["rule_id"] == "AUTH-SSH-001")
    assert brute_force["severity"] == "critical"
    assert brute_force["event_count"] == 5


def test_detection_rule_tuning_is_bounded_and_unknown_rules_are_not_mutable(client):
    invalid = client.patch("/api/v1/detection-rules/AUTH-SSH-001", json={"threshold_override": 1})
    unknown = client.patch("/api/v1/detection-rules/UNKNOWN-001", json={"enabled": False})
    assert invalid.status_code == 422
    assert unknown.status_code == 404

def test_threat_indicator_registry_validation_audit_and_event_matching(client):
    event = client.post("/api/v1/events", json=sample_event(
        source="sensor-a", source_ip="198.51.100.24",
        message="Synthetic SSH authentication failure from 198.51.100.24",
    ))
    assert event.status_code == 201
    created = client.post("/api/v1/threat-intel/indicators", json={
        "indicator_type": "ip", "value": "198.51.100.24", "confidence": 92,
        "severity": "high", "source": "analyst-lab", "description": "Synthetic IOC",
        "tags": ["credential-access"],
    })
    assert created.status_code == 201
    indicator = created.json()
    assert indicator["confidence"] == 92
    duplicate = client.post("/api/v1/threat-intel/indicators", json={
        "indicator_type": "ip", "value": "198.51.100.24", "source": "another-feed",
    })
    assert duplicate.status_code == 409
    matches = client.get("/api/v1/threat-intel/matches")
    assert matches.status_code == 200
    assert any(item["event_id"] == event.json()["id"] for item in matches.json())
    lookup = client.get("/api/v1/threat-intel/lookup?value=198.51.100.24")
    assert len(lookup.json()) == 1
    revoked = client.patch("/api/v1/threat-intel/indicators/" + indicator["id"], json={"status": "revoked"})
    assert revoked.status_code == 200
    assert client.get("/api/v1/threat-intel/lookup?value=198.51.100.24").json() == []
    assert client.get("/api/v1/audit?limit=20").status_code == 200


def test_threat_indicator_rejects_invalid_ip_and_hash_values(client):
    invalid_ip = client.post("/api/v1/threat-intel/indicators", json={
        "indicator_type": "ip", "value": "999.999.999.999", "source": "test-feed",
    })
    invalid_hash = client.post("/api/v1/threat-intel/indicators", json={
        "indicator_type": "hash", "value": "not-a-hash", "source": "test-feed",
    })
    assert invalid_ip.status_code == 422
    assert invalid_hash.status_code == 422


def test_entity_correlation_groups_same_identity_across_sources(client):
    first = client.post("/api/v1/events", json=sample_event(
        source="sensor-alpha", source_ip="203.0.113.77", hostname="edge-01", username="svc-api",
    ))
    second = client.post("/api/v1/events", json=sample_event(
        source="sensor-beta", source_ip="203.0.113.77", hostname="edge-01", username="svc-api",
        event_type="process.started", message="Synthetic process execution",
    ))
    assert first.status_code == second.status_code == 201
    response = client.get("/api/v1/threat-intel/entities?type=ip&min_events=2")
    assert response.status_code == 200
    entity = next(item for item in response.json() if item["value"] == "203.0.113.77")
    assert entity["event_count"] == 2
    assert entity["source_count"] == 2
    assert set(entity["sources"]) == {"sensor-alpha", "sensor-beta"}
    assert len(entity["event_ids"]) == 2


def test_asset_inventory_and_vulnerability_lifecycle(client):
    created = client.post("/api/v1/asset-risk/assets", json={
        "asset_key": "prod-web-01", "hostname": "web-01.internal", "asset_type": "server",
        "environment": "production", "owner": "platform", "criticality": "critical",
        "tags": ["internet-facing", "linux"],
    })
    assert created.status_code == 201
    asset = created.json()
    assert asset["asset_key"] == "prod-web-01"
    assert client.post("/api/v1/asset-risk/assets", json={
        "asset_key": "prod-web-01", "hostname": "duplicate.internal",
    }).status_code == 409

    finding = client.post(f"/api/v1/asset-risk/assets/{asset['id']}/findings", json={
        "vulnerability_id": "cve-2026-12345", "title": "Remote code execution in service",
        "severity": "critical", "source": "lab-scanner", "description": "Synthetic test finding",
    })
    assert finding.status_code == 201
    finding_id = finding.json()["id"]
    assert finding.json()["vulnerability_id"] == "CVE-2026-12345"
    updated = client.patch(f"/api/v1/asset-risk/findings/{finding_id}", json={"status": "in_progress"})
    assert updated.status_code == 200
    assert updated.json()["status"] == "in_progress"
    assert len(client.get(f"/api/v1/asset-risk/assets/{asset['id']}/findings").json()) == 1


def test_response_playbook_tracks_required_steps_and_audits(client):
    case = client.post("/api/v1/cases", json={
        "title": "Synthetic response case", "description": "Playbook integration test",
        "priority": "p2", "severity": "high",
    })
    assert case.status_code == 201
    run = client.post("/api/v1/asset-risk/playbooks", json={
        "case_id": case.json()["id"], "title": "Credential compromise response",
        "steps": [
            {"title": "Validate identity and scope", "required": True},
            {"title": "Preserve authentication evidence", "required": True},
            {"title": "Notify incident owner", "required": False},
        ],
    })
    assert run.status_code == 201
    run_id = run.json()["id"]
    assert run.json()["status"] == "in_progress"

    first = client.patch(f"/api/v1/asset-risk/playbooks/{run_id}/steps/0", json={"completed": True})
    assert first.status_code == 200
    assert first.json()["status"] == "in_progress"
    second = client.patch(f"/api/v1/asset-risk/playbooks/{run_id}/steps/1", json={"completed": True})
    assert second.status_code == 200
    assert second.json()["status"] == "completed"
    assert second.json()["steps"][0]["completed_by"] == "test-admin"
    assert client.patch(f"/api/v1/asset-risk/playbooks/{run_id}/steps/9", json={"completed": True}).status_code == 404


def test_asset_risk_read_endpoints_are_bounded_and_validate_filters(client):
    assert client.get("/api/v1/asset-risk/assets?limit=201").status_code == 422
    assert client.get("/api/v1/asset-risk/assets?status=unknown").status_code == 422
    assert client.get("/api/v1/asset-risk/playbooks?limit=0").status_code == 422


def test_oidc_routes_are_not_exposed_when_sso_is_disabled(client):
    assert client.get('/api/v1/auth/oidc/login').status_code == 404
    assert client.get('/api/v1/auth/oidc/callback').status_code == 404


def test_auth_methods_report_oidc_disabled_by_default(client):
    response = client.get('/api/v1/auth/methods')
    assert response.status_code == 200
    assert response.json() == {'local_password': True, 'oidc_enabled': False}
