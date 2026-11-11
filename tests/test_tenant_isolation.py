from datetime import datetime, timezone
from uuid import uuid4

import pytest

from sqlalchemy import create_engine, delete, select, update
from sqlalchemy.orm import Session

from app.db.base import Base
from app.db.session import set_workspace_context
from app.models import DetectionRuleConfig, SecurityEvent, SigmaRule, Workspace


def _event(source: str, message: str) -> SecurityEvent:
    return SecurityEvent(
        source=source,
        event_type="test.event",
        severity="low",
        timestamp=datetime.now(timezone.utc),
        message=message,
        raw={},
    )


def test_workspace_context_scopes_reads_updates_and_deletes():
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        first = Workspace(slug="tenant-one", name="Tenant One")
        second = Workspace(slug="tenant-two", name="Tenant Two")
        db.add_all([first, second])
        db.flush()
        first_event = _event("sensor-one", "first workspace")
        first_event.workspace_id = first.id
        second_event = _event("sensor-two", "second workspace")
        second_event.workspace_id = second.id
        db.add_all([first_event, second_event])
        db.commit()
        first_id, second_id = first_event.id, second_event.id
        first_workspace_id = first.id

    with Session(engine) as db:
        db.info["workspace_id"] = first_workspace_id
        visible = list(db.scalars(select(SecurityEvent).order_by(SecurityEvent.source)).all())
        assert [item.id for item in visible] == [first_id]

        result = db.execute(
            update(SecurityEvent)
            .where(SecurityEvent.id == second_id)
            .values(message="cross-tenant mutation")
        )
        assert result.rowcount == 0
        result = db.execute(delete(SecurityEvent).where(SecurityEvent.id == second_id))
        assert result.rowcount == 0
        db.commit()

        set_workspace_context(db, second_workspace_id := db.scalar(select(Workspace.id).where(Workspace.slug == "tenant-two")))
        assert [item.id for item in db.scalars(select(SecurityEvent)).all()] == [second_id]
        set_workspace_context(db, first_workspace_id)
        assert db.get(SecurityEvent, second_id) is None
        wrong_workspace_event = _event("forged-source", "must not cross workspace")
        wrong_workspace_event.workspace_id = second_workspace_id
        db.add(wrong_workspace_event)
        with pytest.raises(RuntimeError, match="different workspace"):
            db.flush()
        db.rollback()

    with Session(engine) as db:
        other = db.get(SecurityEvent, second_id)
        assert other is not None
        assert other.message == "second workspace"
    engine.dispose()



def test_detection_governance_and_sigma_rule_ids_are_workspace_scoped():
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        first = Workspace(slug="rules-one", name="Rules One")
        second = Workspace(slug="rules-two", name="Rules Two")
        db.add_all([first, second])
        db.flush()
        for workspace in (first, second):
            db.add(SigmaRule(
                workspace_id=workspace.id,
                rule_id="shared-rule-id",
                title="Workspace-local rule",
                description="",
                level="medium",
                status="test",
                enabled=False,
                detection={"selection": {"event_type": "test.event"}},
                condition="selection",
                logsource={},
                tags=[],
                sigma_yaml="title: Workspace-local rule",
                created_by="test",
            ))
            db.add(DetectionRuleConfig(
                workspace_id=workspace.id,
                rule_id="shared-detection-id",
                enabled=True,
                updated_by="test",
            ))
        db.commit()
        first_id = first.id
        second_id = second.id

    with Session(engine) as db:
        db.info["workspace_id"] = first_id
        assert len(list(db.scalars(select(SigmaRule)).all())) == 1
        assert len(list(db.scalars(select(DetectionRuleConfig)).all())) == 1
        assert db.get(SigmaRule, (second_id, "shared-rule-id")) is None
        assert db.get(DetectionRuleConfig, (second_id, "shared-detection-id")) is None
    engine.dispose()
