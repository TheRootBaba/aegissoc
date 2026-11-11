from datetime import datetime, timedelta, timezone

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.base import Base
from app.models import DetectionAlert, SecurityEvent, Workspace
from app.services.detection_engine import run_ssh_brute_force_detection


def _session():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine)
    db = factory()
    workspace = Workspace(slug='default', name='Default Workspace', is_active=True)
    db.add(workspace)
    db.commit()
    db.info['workspace_id'] = str(workspace.id)
    return db


def _event(db, *, now, source_ip="192.0.2.50", hostname="ssh-lab", username="root",
           event_type="authentication.failure", message="SSH login rejected"):
    event = SecurityEvent(
        source="synthetic-lab",
        event_type=event_type,
        severity="medium",
        timestamp=now,
        hostname=hostname,
        source_ip=source_ip,
        username=username,
        message=message,
        raw={"synthetic": True},
    )
    db.add(event)
    db.flush()
    return event


def test_ssh_rule_creates_evidence_backed_alert_at_threshold():
    db = _session()
    now = datetime.now(timezone.utc)
    events = [_event(db, now=now - timedelta(seconds=i)) for i in range(5)]
    db.commit()

    result = run_ssh_brute_force_detection(db, threshold=5, now=now)

    assert result["events_evaluated"] == 5
    assert result["alerts_created"] == 1
    alert = result["alerts"][0]
    assert alert.rule_id == "AUTH-SSH-001"
    assert alert.severity == "medium"
    assert alert.event_count == 5
    assert set(alert.evidence_event_ids) == {str(event.id) for event in events}
    assert db.query(DetectionAlert).count() == 1
    db.close()


def test_ssh_rule_does_not_alert_below_threshold_or_for_non_ssh():
    db = _session()
    now = datetime.now(timezone.utc)
    for _ in range(4):
        _event(db, now=now)
    for _ in range(6):
        _event(db, now=now, source_ip="192.0.2.60", message="Console login rejected")
    db.commit()

    result = run_ssh_brute_force_detection(db, threshold=5, now=now)

    assert result["alerts_created"] == 0
    assert result["alerts"] == []
    db.close()


def test_ssh_rule_deduplicates_repeated_runs_and_refreshes_evidence():
    db = _session()
    now = datetime.now(timezone.utc)
    for _ in range(5):
        _event(db, now=now)
    db.commit()

    first = run_ssh_brute_force_detection(db, threshold=5, now=now)
    _event(db, now=now + timedelta(seconds=1))
    db.commit()
    second = run_ssh_brute_force_detection(
        db, threshold=5, now=now + timedelta(seconds=1)
    )

    assert first["alerts_created"] == 1
    assert second["alerts_created"] == 0
    assert second["alerts_updated"] == 1
    assert second["alerts"][0].event_count == 6
    assert db.query(DetectionAlert).count() == 1
    db.close()


def test_ssh_rule_ignores_events_outside_rolling_window():
    db = _session()
    now = datetime.now(timezone.utc)
    for _ in range(5):
        _event(db, now=now - timedelta(minutes=20))
    db.commit()

    result = run_ssh_brute_force_detection(db, threshold=5, window_minutes=10, now=now)

    assert result["alerts_created"] == 0
    db.close()


def test_ssh_password_spray_rule_detects_distinct_usernames():
    db = _session()
    now = datetime.now(timezone.utc)
    for index in range(5):
        _event(db, now=now, username=f"user-{index}")
    db.commit()

    result = run_ssh_brute_force_detection(db, threshold=5, now=now)

    rule_ids = {alert.rule_id for alert in result["alerts"]}
    assert rule_ids == {"AUTH-SSH-001", "AUTH-SSH-002"}
    spray = next(alert for alert in result["alerts"] if alert.rule_id == "AUTH-SSH-002")
    assert spray.severity == "high"
    assert spray.event_count == 5
    assert len(spray.username.split(", ")) == 5
    db.close()


def test_ssh_brute_force_severity_escalates_at_double_threshold():
    db = _session()
    now = datetime.now(timezone.utc)
    for _ in range(10):
        _event(db, now=now)
    db.commit()

    result = run_ssh_brute_force_detection(db, threshold=5, now=now)

    brute_force = next(alert for alert in result["alerts"] if alert.rule_id == "AUTH-SSH-001")
    assert brute_force.severity == "high"
    db.close()
