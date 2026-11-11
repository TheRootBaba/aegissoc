"""Persist recurring detection schedules and execution history."""
from alembic import op
import sqlalchemy as sa

revision = "0008_detection_schedules"
down_revision = "0007_saved_event_queries"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "detection_schedules",
        sa.Column("id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("name", sa.String(length=100), nullable=False),
        sa.Column("interval_seconds", sa.Integer(), nullable=False),
        sa.Column("window_minutes", sa.Integer(), nullable=False),
        sa.Column("threshold", sa.Integer(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("next_run_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_status", sa.String(length=16), nullable=True),
        sa.Column("last_error", sa.String(length=500), nullable=True),
        sa.Column("consecutive_failures", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("locked_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_by", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("created_by", "name", name="uq_detection_schedules_owner_name"),
    )
    op.create_index("ix_detection_schedules_enabled", "detection_schedules", ["enabled"])
    op.create_index("ix_detection_schedules_next_run_at", "detection_schedules", ["next_run_at"])
    op.create_index("ix_detection_schedules_locked_until", "detection_schedules", ["locked_until"])
    op.create_index("ix_detection_schedules_created_by", "detection_schedules", ["created_by"])

    op.create_table(
        "detection_executions",
        sa.Column("id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("schedule_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("duration_ms", sa.Integer(), nullable=False),
        sa.Column("events_evaluated", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("alerts_created", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("alerts_updated", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("rules_evaluated", sa.JSON(), nullable=False),
        sa.Column("error", sa.String(length=500), nullable=True),
        sa.ForeignKeyConstraint(["schedule_id"], ["detection_schedules.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_detection_executions_schedule_id", "detection_executions", ["schedule_id"])
    op.create_index("ix_detection_executions_status", "detection_executions", ["status"])


def downgrade() -> None:
    op.drop_index("ix_detection_executions_status", table_name="detection_executions")
    op.drop_index("ix_detection_executions_schedule_id", table_name="detection_executions")
    op.drop_table("detection_executions")
    op.drop_index("ix_detection_schedules_created_by", table_name="detection_schedules")
    op.drop_index("ix_detection_schedules_locked_until", table_name="detection_schedules")
    op.drop_index("ix_detection_schedules_next_run_at", table_name="detection_schedules")
    op.drop_index("ix_detection_schedules_enabled", table_name="detection_schedules")
    op.drop_table("detection_schedules")
