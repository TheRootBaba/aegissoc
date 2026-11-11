from datetime import datetime, timezone
from types import SimpleNamespace
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from app import models
from app.core.security import get_current_user
from app.db.base import Base
from app.db.session import get_db
from app.main import app
from app.models import ConnectorConfig, ManagedAsset, SecurityEvent, ThreatIndicator, Workspace
from app.services.integrations import get_adapter
from app.services.sigma_engine import parse_sigma_document, rule_matches

@pytest.fixture
def isolated_db():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    factory = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    Base.metadata.create_all(bind=engine)
    session = factory()
    default_workspace = Workspace(slug='default', name='Default Workspace', is_active=True)
    session.add(default_workspace)
    session.commit()
    session.info['workspace_id'] = str(default_workspace.id)
    yield session
    session.close()
    Base.metadata.drop_all(bind=engine)
    engine.dispose()

@pytest.fixture
def api_client(isolated_db):
    def override_db():
        yield isolated_db
    app.dependency_overrides[get_db] = override_db
    with TestClient(app) as client:
        yield client
    app.dependency_overrides.pop(get_db, None)

def test_http_poll_adapter_requires_explicit_host_allowlist():
    adapter = get_adapter("http_poll")
    valid = {"endpoint": "https://collector.example/events", "allowed_hosts": ["collector.example"], "interval_seconds": 60}
    assert adapter.validate_config(valid).valid
    assert not adapter.validate_config({**valid, "allowed_hosts": ["other.example"]}).valid
    assert not adapter.validate_config({**valid, "endpoint": "http://collector.example/events"}).valid
    assert not adapter.validate_config({**valid, "endpoint": "https://user:pass@collector.example/events"}).valid

def test_sigma_subset_parses_and_matches_nested_event_fields():
    source = """title: Suspicious PowerShell
id: test-powershell-001
status: test
description: Detects encoded PowerShell command lines.
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    event_type: process.started
    CommandLine|contains: -EncodedCommand
  condition: selection
level: high
tags:
  - attack.execution
"""
    parsed = parse_sigma_document(source)
    rule = SimpleNamespace(**parsed, enabled=True)
    event = SimpleNamespace(
        source="edr", event_type="process.started", severity="medium",
        hostname="workstation-01", source_ip=None, username="analyst",
        message="powershell launched", raw={"CommandLine": "powershell.exe -EncodedCommand abc"},
    )
    assert rule_matches(event, rule)
    event.raw = {"CommandLine": "powershell.exe -NoProfile"}
    assert not rule_matches(event, rule)
    with pytest.raises(ValueError):
        parse_sigma_document("title: broken\\nlevel: critical\\n")

def test_scanner_import_reconciles_assets_and_is_idempotent(api_client):
    asset = api_client.post("/api/v1/asset-risk/assets", json={
        "asset_key": "scan-host-01", "hostname": "scan-host-01.internal", "criticality": "high",
    })
    assert asset.status_code == 201
    payload = {
        "scanner_name": "lab-scanner", "scan_id": "scan-2026-11-11-001",
        "assets": [
            {"asset_key": "scan-host-01", "hostname": "scan-host-01.internal", "findings": [
                {"vulnerability_id": "CVE-2026-12345", "title": "Example RCE", "severity": "critical"},
            ]},
            {"asset_key": "unknown-host", "hostname": "unknown", "findings": [
                {"vulnerability_id": "CVE-2026-12346", "title": "Unknown asset finding", "severity": "high"},
            ]},
        ],
    }
    first = api_client.post("/api/v1/asset-risk/scanner-imports", json=payload)
    assert first.status_code == 200
    assert first.json()["findings_seen"] == 2
    assert first.json()["findings_created"] == 1
    assert first.json()["findings_rejected"] == 1
    replay = api_client.post("/api/v1/asset-risk/scanner-imports", json=payload)
    assert replay.status_code == 200
    assert replay.json() == first.json()
    findings = api_client.get(f"/api/v1/asset-risk/assets/{asset.json()['id']}/findings")
    assert len(findings.json()) == 1

def test_threat_feed_connector_poll_updates_indicator(isolated_db, monkeypatch):
    from app.services import connector_runtime
    connector = ConnectorConfig(
        connector_key="test-feed", connector_type="threat_feed", display_name="Test Feed",
        config={"endpoint": "https://feed.example/iocs", "allowed_hosts": ["feed.example"],
                "interval_seconds": 60, "records_path": "items"},
        enabled=True, health_status="unverified",
    )
    isolated_db.add(connector)
    isolated_db.commit()
    monkeypatch.setattr(connector_runtime, "_read_response", lambda url, headers: {
        "items": [{"type": "ip", "value": "203.0.113.77", "confidence": 90, "severity": "high"}]
    })
    assert connector_runtime.run_due_connectors_once(isolated_db, batch_size=1) == 1
    indicator = isolated_db.query(ThreatIndicator).filter_by(value="203.0.113.77").one()
    assert indicator.confidence == 90
    indicator.status = "revoked"
    isolated_db.get(connector_runtime.ConnectorRuntimeState, connector.id).next_run_at = datetime.now(timezone.utc)
    isolated_db.commit()
    assert connector_runtime.run_due_connectors_once(isolated_db, batch_size=1) == 1
    isolated_db.refresh(indicator)
    assert indicator.status == "revoked"
    assert "feed:test-feed" in indicator.tags

def test_sigma_api_import_test_and_enable(api_client):
    source = """title: SSH Authentication Failure
id: test-ssh-failure
status: test
description: Test SSH failures.
logsource:
  product: linux
detection:
  selection:
    event_type: authentication.failure
    message|contains: failed
  condition: selection
level: medium
"""
    imported = api_client.post("/api/v1/sigma/rules/import", json={"sigma_yaml": source, "enabled": False})
    assert imported.status_code == 201
    tested = api_client.post("/api/v1/sigma/rules/test-ssh-failure/test", json={
        "event": {"event_type": "authentication.failure", "message": "SSH failed password"},
    })
    assert tested.status_code == 200
    assert tested.json()["matched"] is True
    enabled = api_client.patch("/api/v1/sigma/rules/test-ssh-failure/enabled?enabled=true")
    assert enabled.status_code == 200
    assert enabled.json()["enabled"] is True
    ingested = api_client.post("/api/v1/events/ingest/lab-sigma", json={
        "id": "sigma-event-001", "event_type": "authentication.failure", "severity": "medium",
        "timestamp": datetime.now(timezone.utc).isoformat(), "message": "SSH failed password",
    })
    assert ingested.status_code == 201
    run = api_client.post("/api/v1/sigma/run", json={"lookback_minutes": 15, "limit": 100})
    assert run.status_code == 200
    assert run.json()["matches"] == 1
    assert run.json()["alerts_created"] == 1

def test_response_action_requires_approval_then_queues_durable_worker_delivery(api_client, isolated_db, monkeypatch):
    from app.services import response_execution
    connector = api_client.post("/api/v1/connectors", json={
        "connector_key": "approved-webhook", "connector_type": "response_webhook",
        "display_name": "Approved response receiver",
        "config": {"endpoint": "https://response.example/actions", "allowed_hosts": ["response.example"]},
        "enabled": True,
    })
    assert connector.status_code == 201
    request = api_client.post("/api/v1/response-actions", json={
        "connector_key": "approved-webhook", "action_type": "block_ip", "target": "203.0.113.9",
        "parameters": {"duration_minutes": 30},
    })
    assert request.status_code == 201
    request_id = request.json()["id"]
    self_approval = api_client.post(f"/api/v1/response-actions/{request_id}/approve", json={"note": "Approve"})
    assert self_approval.status_code == 403

    app.dependency_overrides[get_current_user] = lambda: SimpleNamespace(
        id=uuid4(), username="second-admin", role="admin", is_active=True
    )
    approved = api_client.post(f"/api/v1/response-actions/{request_id}/approve", json={"note": "Reviewed change window"})
    assert approved.status_code == 200

    class FakeResponse:
        status_code = 202
        headers = {"X-Aegis-Action-Reference": "receiver-action-202"}
        def __enter__(self): return self
        def __exit__(self, *args): return False
    class FakeClient:
        def __enter__(self): return self
        def __exit__(self, *args): return False
        def stream(self, *args, **kwargs): return FakeResponse()
    monkeypatch.setattr(response_execution.httpx, "Client", lambda **kwargs: FakeClient())

    queued = api_client.post(f"/api/v1/response-actions/{request_id}/execute")
    assert queued.status_code == 200
    assert queued.json()["status"] == "approved"
    assert queued.json()["execution_status"] == "queued"
    assert response_execution.run_due_response_actions_once(isolated_db) == 1
    result = api_client.get(f"/api/v1/response-actions?status=succeeded")
    assert result.status_code == 200
    assert result.json()[0]["id"] == request_id
    assert result.json()[0]["execution_attempts"] == 1
    assert result.json()[0]["external_reference"] == "receiver-action-202"
    app.dependency_overrides.pop(get_current_user, None)

def test_http_poll_worker_ingests_events_idempotently(isolated_db, monkeypatch):
    from app.services import connector_runtime
    from app.models import ConnectorRuntimeState
    connector = ConnectorConfig(
        connector_key="edr-poll", connector_type="http_poll", display_name="EDR poll",
        config={"endpoint": "https://edr.example/events", "allowed_hosts": ["edr.example"],
                "interval_seconds": 60, "records_path": "items"},
        enabled=True, health_status="unverified",
    )
    isolated_db.add(connector)
    isolated_db.commit()
    payload = {"items": [{
        "id": "edr-event-001", "event_type": "process.started", "severity": "medium",
        "timestamp": datetime.now(timezone.utc).isoformat(), "hostname": "endpoint-01",
        "message": "A test process started",
    }]}
    monkeypatch.setattr(connector_runtime, "_read_response", lambda url, headers: payload)
    assert connector_runtime.run_due_connectors_once(isolated_db, batch_size=1) == 1
    assert isolated_db.query(SecurityEvent).filter_by(source="edr-poll").count() == 1
    state = isolated_db.get(ConnectorRuntimeState, connector.id)
    state.next_run_at = datetime.now(timezone.utc)
    isolated_db.commit()
    assert connector_runtime.run_due_connectors_once(isolated_db, batch_size=1) == 1
    assert isolated_db.query(SecurityEvent).filter_by(source="edr-poll").count() == 1
    latest = isolated_db.query(connector_runtime.ConnectorExecution).filter_by(connector_id=connector.id).order_by(
        connector_runtime.ConnectorExecution.started_at.desc()
    ).first()
    assert latest.duplicates == 1


def test_connector_worker_records_failure_and_backoff(isolated_db, monkeypatch):
    from app.services import connector_runtime
    connector = ConnectorConfig(
        connector_key="broken-poll", connector_type="http_poll", display_name="Broken poll",
        config={"endpoint": "https://feed.example/items", "allowed_hosts": ["feed.example"],
                "interval_seconds": 30},
        enabled=True, health_status="unverified",
    )
    isolated_db.add(connector)
    isolated_db.commit()
    monkeypatch.setattr(connector_runtime, "_read_response", lambda *args: (_ for _ in ()).throw(TimeoutError()))
    assert connector_runtime.run_due_connectors_once(isolated_db, batch_size=1) == 0
    state = isolated_db.get(connector_runtime.ConnectorRuntimeState, connector.id)
    assert state.consecutive_failures == 1
    assert state.locked_until is None
    assert isolated_db.query(connector_runtime.ConnectorExecution).filter_by(status="failed").count() == 1

def test_native_provider_adapters_validate_tls_and_normalize_indicators():
    misp = get_adapter("misp")
    valid = {
        "endpoint": "https://misp.example/attributes/restSearch",
        "allowed_hosts": ["misp.example"],
        "interval_seconds": 60,
        "credential_ref": "env://MISP_API_KEY",
    }
    assert misp.validate_config(valid).valid
    assert not misp.validate_config({**valid, "endpoint": "http://misp.example/attributes/restSearch"}).valid
    normalized = misp.normalize_indicator({"type": "ip-src|port", "value": "203.0.113.9|443", "to_ids": True})
    assert normalized["type"] == "ip"
    assert normalized["value"] == "203.0.113.9"

    opencti = get_adapter("opencti")
    normalized = opencti.normalize_indicator({
        "node": {
            "pattern": "[domain-name:value = 'malware.example']",
            "confidence": 90,
            "labels": [{"value": "tlp:amber"}],
        }
    })
    assert normalized["type"] == "domain"
    assert normalized["value"] == "malware.example"
    assert normalized["tags"] == ["tlp:amber"]


def test_scanner_export_normalizers_map_vendor_findings_to_managed_asset_contract():
    from app.services.scanner_adapters import normalize_scanner_export

    nessus = normalize_scanner_export("nessus", {
        "info": {"uuid": "scan-nessus-001"},
        "hosts": [{
            "host-fqdn": "db01.example.internal",
            "host-ip": "192.0.2.81",
            "vulnerabilities": [{
                "plugin_id": 12345,
                "plugin_name": "Example remote code execution",
                "severity": 4,
                "cve": ["CVE-2026-12345"],
                "description": "Synthetic scanner fixture",
            }],
        }],
    })
    assert nessus["scanner_name"] == "nessus"
    assert nessus["scan_id"] == "scan-nessus-001"
    assert nessus["assets"][0]["asset_key"] == "db01.example.internal"
    assert nessus["assets"][0]["findings"][0]["vulnerability_id"] == "CVE-2026-12345"
    assert nessus["assets"][0]["findings"][0]["severity"] == "critical"

    qualys = normalize_scanner_export("qualys", {
        "scan_id": "qualys-2026-01",
        "assets": [{
            "host_name": "web01.example.internal",
            "ip": "192.0.2.82",
            "detectionList": [{"qid": 9876, "title": "Outdated package", "severity": 3}],
        }],
    })
    assert qualys["assets"][0]["findings"][0]["vulnerability_id"] == "QID-9876"
    assert qualys["assets"][0]["findings"][0]["severity"] == "high"

def test_sigma_advanced_conditions_and_modifiers():
    source = """title: Encoded PowerShell
id: sigma-advanced-001
logsource:
  product: windows
detection:
  selection_a:
    CommandLine|contains|all:
      - powershell
      - -encodedcommand
  selection_b:
    event_type: process.started
  filter:
    severity: critical
  condition: 1 of selection_* and not filter
level: high
"""
    parsed = parse_sigma_document(source)
    rule = SimpleNamespace(**parsed, enabled=True)
    event = SimpleNamespace(
        source="edr", event_type="process.started", severity="high",
        hostname="win01", source_ip=None, username="analyst",
        message="encoded powershell", raw={"CommandLine": "powershell.exe -EncodedCommand abc"},
    )
    assert rule_matches(event, rule)
    event.severity = "critical"
    assert not rule_matches(event, rule)


def test_sigma_event_count_correlation_creates_grouped_evidence_alert(isolated_db):
    from datetime import datetime, timezone
    from app.models import SigmaRule
    from app.services.sigma_engine import run_sigma_rules

    base = parse_sigma_document("""title: Failed authentication
id: base-auth-failure
logsource:
  service: auth
detection:
  selection:
    event_type: authentication.failure
  condition: selection
level: medium
""")
    correlation = parse_sigma_document("""title: Repeated authentication failures
id: corr-auth-failure
logsource:
  service: auth
correlation:
  type: event_count
  rules:
    - base-auth-failure
  group-by:
    - source_ip
  timespan: 5m
  condition:
    gte: 3
level: high
""")
    isolated_db.add_all([
        SigmaRule(**base, enabled=True, created_by="analyst"),
        SigmaRule(**correlation, enabled=True, created_by="analyst"),
    ])
    now = datetime.now(timezone.utc)
    for index in range(3):
        isolated_db.add(SecurityEvent(
            source="auth-sensor", event_type="authentication.failure", severity="medium",
            timestamp=now, source_ip="192.0.2.99", message=f"failed login {index}", raw={},
        ))
    isolated_db.commit()

    result = run_sigma_rules(isolated_db, lookback_minutes=15)
    assert result["rules_evaluated"] == 2
    assert result["matches"] == 4
    alerts = isolated_db.query(models.DetectionAlert).filter(
        models.DetectionAlert.rule_id == "SIGMA-C:corr-auth-failure"
    ).all()
    assert len(alerts) == 1
    assert alerts[0].event_count == 3
    assert len(alerts[0].evidence_event_ids) == 3

def test_misp_connector_poll_uses_native_attribute_normalization(isolated_db, monkeypatch):
    from app.services import connector_runtime

    monkeypatch.setenv("MISP_RUNTIME_KEY", "fixture-misp-key")
    connector = ConnectorConfig(
        connector_key="misp-native",
        connector_type="misp",
        display_name="MISP fixture",
        config={
            "endpoint": "https://misp.example/attributes/restSearch",
            "allowed_hosts": ["misp.example"],
            "interval_seconds": 60,
            "page_size": 100,
        },
        credential_ref="env://MISP_RUNTIME_KEY",
        enabled=True,
        health_status="unverified",
    )
    isolated_db.add(connector)
    isolated_db.commit()
    calls = []
    def fake_read(url, headers, **kwargs):
        calls.append((url, headers, kwargs))
        return {"response": {"Attribute": [{
            "type": "ip-src|port", "value": "203.0.113.121|443",
            "to_ids": True, "comment": "synthetic MISP fixture",
        }]}}
    monkeypatch.setattr(connector_runtime, "_read_response", fake_read)
    assert connector_runtime.run_due_connectors_once(isolated_db, batch_size=1) == 1
    indicator = isolated_db.query(ThreatIndicator).filter_by(value="203.0.113.121").one()
    assert indicator.indicator_type == "ip"
    assert indicator.confidence == 80
    assert calls[0][1]["X-MISP-Auth"] == "fixture-misp-key"
    assert calls[0][2]["method"] == "POST"
    assert calls[0][2]["json_body"]["returnFormat"] == "json"


def test_secret_resolver_supports_environment_and_rejects_unmounted_files(monkeypatch):
    from app.services.secrets import resolve_secret_reference

    monkeypatch.setenv("AEGIS_SECRET_FIXTURE", "secret-value")
    assert resolve_secret_reference("env://AEGIS_SECRET_FIXTURE") == "secret-value"
    with pytest.raises(ValueError):
        resolve_secret_reference("file:///tmp/aegis-secret")
    with pytest.raises(ValueError):
        resolve_secret_reference("https://example.invalid/secret")
