"""Atomic source inventory counters shared by single and bulk ingestion."""
from datetime import datetime, timezone

from sqlalchemy import case
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.orm import Session

from app.models import SourceRegistry


def record_ingestion(
    db: Session,
    source_name: str,
    *,
    accepted: int,
    duplicates: int,
    rejected: int,
    event_timestamp: datetime | None = None,
) -> None:
    """Atomically upsert one source's request outcome and cumulative counters."""
    now = datetime.now(timezone.utc)
    values = {
        "source_name": source_name,
        "source_type": "wazuh" if source_name.lower() == "wazuh" else "generic",
        "display_name": source_name,
        "description": None,
        "health_status": "healthy" if accepted + duplicates else ("failing" if rejected else "inactive"),
        "last_attempt_at": now,
        "last_successful_event_at": event_timestamp if accepted else None,
        "accepted_events": accepted,
        "duplicate_events": duplicates,
        "rejected_events": rejected,
        "created_at": now,
        "updated_at": now,
    }
    dialect = db.get_bind().dialect.name
    if dialect in {"postgresql", "sqlite"}:
        insert = pg_insert if dialect == "postgresql" else sqlite_insert
        statement = insert(SourceRegistry).values(**values)
        excluded = statement.excluded
        current_success = SourceRegistry.last_successful_event_at
        next_success = case(
            (excluded.last_successful_event_at.is_not(None) & (
                current_success.is_(None) | (excluded.last_successful_event_at > current_success)
            ), excluded.last_successful_event_at),
            else_=current_success,
        )
        next_status = case(
            ((excluded.accepted_events + excluded.duplicate_events) > 0, "healthy"),
            (excluded.rejected_events > 0, "failing"),
            else_=SourceRegistry.health_status,
        )
        db.execute(statement.on_conflict_do_update(
            index_elements=[SourceRegistry.source_name],
            set_={
                "health_status": next_status,
                "last_attempt_at": excluded.last_attempt_at,
                "last_successful_event_at": next_success,
                "accepted_events": SourceRegistry.accepted_events + excluded.accepted_events,
                "duplicate_events": SourceRegistry.duplicate_events + excluded.duplicate_events,
                "rejected_events": SourceRegistry.rejected_events + excluded.rejected_events,
                "updated_at": excluded.updated_at,
            },
        ))
        return

    from sqlalchemy import select
    source = db.scalar(select(SourceRegistry).where(SourceRegistry.source_name == source_name))
    if source is None:
        db.add(SourceRegistry(**values))
        return
    source.last_attempt_at = now
    source.accepted_events += accepted
    source.duplicate_events += duplicates
    source.rejected_events += rejected
    if accepted + duplicates:
        source.health_status = "healthy"
    elif rejected:
        source.health_status = "failing"
    if accepted and event_timestamp and (
        source.last_successful_event_at is None or event_timestamp > source.last_successful_event_at
    ):
        source.last_successful_event_at = event_timestamp
    source.updated_at = now
