"""Create persistent detection alerts.

Revision ID: 0002_detection_alerts
Revises: 0001_security_events
"""
from alembic import op
import sqlalchemy as sa

revision = "0002_detection_alerts"
down_revision = "0001_security_events"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "detection_alerts",
        sa.Column("id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("rule_id", sa.String(length=64), nullable=False),
        sa.Column("fingerprint", sa.String(length=64), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("source_ip", sa.String(length=45), nullable=True),
        sa.Column("hostname", sa.String(length=255), nullable=True),
        sa.Column("username", sa.String(length=255), nullable=True),
        sa.Column("event_count", sa.Integer(), nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("evidence_event_ids", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("fingerprint", name="uq_detection_alerts_fingerprint"),
    )
    for column in ("rule_id", "severity", "status", "source_ip", "hostname"):
        op.create_index(f"ix_detection_alerts_{column}", "detection_alerts", [column])


def downgrade() -> None:
    op.drop_table("detection_alerts")
