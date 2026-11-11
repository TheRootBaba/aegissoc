"""Add alert assignment, lifecycle, notes, and audit history.

Revision ID: 0003_alert_investigation
Revises: 0002_detection_alerts
"""
from alembic import op
import sqlalchemy as sa

revision = "0003_alert_investigation"
down_revision = "0002_detection_alerts"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("detection_alerts", sa.Column("assigned_to", sa.String(length=120), nullable=True))
    op.add_column("detection_alerts", sa.Column("acknowledged_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("detection_alerts", sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column(
        "detection_alerts",
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_detection_alerts_assigned_to", "detection_alerts", ["assigned_to"])
    op.create_table(
        "alert_notes",
        sa.Column("id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("alert_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("author", sa.String(length=120), nullable=False),
        sa.Column("body", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["alert_id"], ["detection_alerts.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_alert_notes_alert_id", "alert_notes", ["alert_id"])
    op.create_table(
        "alert_audit_logs",
        sa.Column("id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("alert_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("actor", sa.String(length=120), nullable=False),
        sa.Column("action", sa.String(length=64), nullable=False),
        sa.Column("details", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["alert_id"], ["detection_alerts.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_alert_audit_logs_alert_id", "alert_audit_logs", ["alert_id"])


def downgrade() -> None:
    op.drop_table("alert_audit_logs")
    op.drop_table("alert_notes")
    op.drop_index("ix_detection_alerts_assigned_to", table_name="detection_alerts")
    op.drop_column("detection_alerts", "updated_at")
    op.drop_column("detection_alerts", "resolved_at")
    op.drop_column("detection_alerts", "acknowledged_at")
    op.drop_column("detection_alerts", "assigned_to")
