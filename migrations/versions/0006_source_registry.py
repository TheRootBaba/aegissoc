"""Create source inventory and ingestion-health counters."""
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
        sa.UniqueConstraint("source_name", name="uq_source_registry_source_name"),
    )
    op.create_index("ix_source_registry_source_name", "source_registry", ["source_name"])
    op.create_index("ix_source_registry_health_status", "source_registry", ["health_status"])
    op.create_index("ix_source_registry_last_attempt_at", "source_registry", ["last_attempt_at"])
    op.create_index("ix_source_registry_last_successful_event_at", "source_registry", ["last_successful_event_at"])


def downgrade() -> None:
    op.drop_index("ix_source_registry_last_successful_event_at", table_name="source_registry")
    op.drop_index("ix_source_registry_last_attempt_at", table_name="source_registry")
    op.drop_index("ix_source_registry_health_status", table_name="source_registry")
    op.drop_index("ix_source_registry_source_name", table_name="source_registry")
    op.drop_table("source_registry")
