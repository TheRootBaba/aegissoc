"""Atomic source inventory counters shared by single and bulk ingestion."""
from datetime import datetime, timezone

from sqlalchemy import case, func, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.orm import Session

from app.models import SecurityEvent, SourceRegistry
from app.db.session import workspace_id_for_session


def record_ingestion(
    db: Session,
    source_name: str,
    *,
    accepted: int,
    duplicates: int,
    rejected: int,
    event_timestamp: datetime | None = None,
    source_type: str | None = None,
    display_name: str | None = None,
) -> None:
    """Atomically upsert one source's request outcome and cumulative counters."""
    now = datetime.now(timezone.utc)
    workspace_id = workspace_id_for_session(db)
    if event_timestamp is None:
        event_timestamp = db.scalar(
            select(func.max(SecurityEvent.timestamp)).where(
                SecurityEvent.workspace_id == workspace_id,
                SecurityEvent.source == source_name,
            )
        )
    values = {
        "workspace_id": workspace_id,
        "source_name": source_name,
        "source_type": source_type or ("wazuh" if source_name.lower() == "wazuh" else "generic"),
        "display_name": display_name or source_name,
        "description": None,
        "health_status": "healthy" if accepted + duplicates else ("failing" if rejected else "inactive"),
        "last_attempt_at": now,
        "last_successful_event_at": event_timestamp,
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
            index_elements=[SourceRegistry.workspace_id, SourceRegistry.source_name],
            set_={
                "health_status": next_status,
                "source_type": case((excluded.source_type != "generic", excluded.source_type), else_=SourceRegistry.source_type),
                "display_name": case((SourceRegistry.display_name == SourceRegistry.source_name, excluded.display_name), else_=SourceRegistry.display_name),
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
        if source_type and source_type != "generic":
            source.source_type = source_type
        if display_name and source.display_name == source.source_name:
            source.display_name = display_name
    elif rejected:
        source.health_status = "failing"
    if (accepted or duplicates) and event_timestamp and (
        source.last_successful_event_at is None or event_timestamp > source.last_successful_event_at
    ):
        source.last_successful_event_at = event_timestamp
    source.updated_at = now
