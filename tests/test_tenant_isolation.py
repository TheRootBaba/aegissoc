from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import create_engine, delete, select, update
from sqlalchemy.orm import Session

from app.db.base import Base
from app.models import SecurityEvent, Workspace


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

    with Session(engine) as db:
        other = db.get(SecurityEvent, second_id)
        assert other is not None
        assert other.message == "second workspace"
    engine.dispose()
