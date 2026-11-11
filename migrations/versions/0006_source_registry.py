"""Create source inventory, counters, and seed existing event producers."""
from datetime import datetime, timezone
from uuid import uuid4

from alembic import op
import sqlalchemy as sa

revision = "0006_source_registry"
down_revision = "0005_auth_users"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "source_registry",
        sa.Column("id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("source_name", sa.String(length=80), nullable=False),
        sa.Column("source_type", sa.String(length=32), nullable=False, server_default="generic"),
        sa.Column("display_name", sa.String(length=120), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("health_status", sa.String(length=16), nullable=False, server_default="inactive"),
        sa.Column("last_attempt_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_successful_event_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("accepted_events", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("duplicate_events", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("rejected_events", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_source_registry_source_name", "source_registry", ["source_name"], unique=True)
    op.create_index("ix_source_registry_health_status", "source_registry", ["health_status"])
    op.create_index("ix_source_registry_last_attempt_at", "source_registry", ["last_attempt_at"])
    op.create_index("ix_source_registry_last_successful_event_at", "source_registry", ["last_successful_event_at"])

    # Preserve visibility for producers that already have canonical events.
    # Historical retries/rejections are unknowable, so only persisted events are
    # counted as accepted and the unavailable historical outcomes start at zero.
    connection = op.get_bind()
    events = sa.table(
        "security_events",
        sa.column("source", sa.String(length=80)),
        sa.column("timestamp", sa.DateTime(timezone=True)),
        sa.column("created_at", sa.DateTime(timezone=True)),
    )
    registry = sa.table(
        "source_registry",
        sa.column("id", sa.Uuid(as_uuid=True)),
        sa.column("source_name", sa.String(length=80)),
        sa.column("source_type", sa.String(length=32)),
        sa.column("display_name", sa.String(length=120)),
        sa.column("description", sa.Text()),
        sa.column("health_status", sa.String(length=16)),
        sa.column("last_attempt_at", sa.DateTime(timezone=True)),
        sa.column("last_successful_event_at", sa.DateTime(timezone=True)),
        sa.column("accepted_events", sa.Integer()),
        sa.column("duplicate_events", sa.Integer()),
        sa.column("rejected_events", sa.Integer()),
        sa.column("created_at", sa.DateTime(timezone=True)),
        sa.column("updated_at", sa.DateTime(timezone=True)),
    )
    existing_sources = connection.execute(
        sa.select(
            events.c.source,
            sa.func.count().label("event_count"),
            sa.func.max(events.c.created_at).label("last_attempt"),
            sa.func.max(events.c.timestamp).label("last_event"),
        ).group_by(events.c.source)
    ).all()
    for source_name, event_count, last_attempt, last_event in existing_sources:
        observed_at = last_attempt or datetime.now(timezone.utc)
        connection.execute(sa.insert(registry).values(
            id=uuid4(),
            source_name=source_name,
            source_type="wazuh" if source_name.lower() == "wazuh" else "generic",
            display_name=source_name,
            description=None,
            health_status="healthy",
            last_attempt_at=observed_at,
            last_successful_event_at=last_event,
            accepted_events=event_count,
            duplicate_events=0,
            rejected_events=0,
            created_at=observed_at,
            updated_at=observed_at,
        ))


def downgrade() -> None:
    op.drop_index("ix_source_registry_last_successful_event_at", table_name="source_registry")
    op.drop_index("ix_source_registry_last_attempt_at", table_name="source_registry")
    op.drop_index("ix_source_registry_health_status", table_name="source_registry")
    op.drop_index("ix_source_registry_source_name", table_name="source_registry")
    op.drop_table("source_registry")
