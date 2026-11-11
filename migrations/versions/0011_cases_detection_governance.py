"""Add incident case management and detection rule governance."""

from datetime import datetime, timezone
import uuid

from alembic import op
import sqlalchemy as sa

revision = "0011_cases_detection_governance"
down_revision = "0010_operations_connectors"
branch_labels = None
depends_on = None


RULES = (
    "AUTH-SSH-001",
    "AUTH-SSH-002",
    "AUTH-CHAIN-001",
    "PRIV-ESC-001",
    "PROC-SUSP-001",
)


def upgrade() -> None:
    op.create_table(
        "incident_cases",
        sa.Column("id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("case_number", sa.String(32), nullable=False),
        sa.Column("title", sa.String(200), nullable=False),
        sa.Column("description", sa.Text(), nullable=False, server_default=""),
        sa.Column("status", sa.String(24), nullable=False, server_default="open"),
        sa.Column("priority", sa.String(8), nullable=False, server_default="p2"),
        sa.Column("severity", sa.String(16), nullable=False, server_default="medium"),
        sa.Column("assignee", sa.String(120), nullable=True),
        sa.Column("tags", sa.JSON(), nullable=False),
        sa.Column("created_by", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("closed_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("case_number", name="uq_incident_cases_case_number"),
    )
    for column in ("case_number", "status", "priority", "severity", "assignee"):
        op.create_index(f"ix_incident_cases_{column}", "incident_cases", [column])

    op.create_table(
        "case_alert_links",
        sa.Column("id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("case_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("alert_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("linked_by", sa.String(64), nullable=False),
        sa.Column("linked_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["case_id"], ["incident_cases.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["alert_id"], ["detection_alerts.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("case_id", "alert_id", name="uq_case_alert_links_case_alert"),
    )
    op.create_index("ix_case_alert_links_case_id", "case_alert_links", ["case_id"])
    op.create_index("ix_case_alert_links_alert_id", "case_alert_links", ["alert_id"])

    op.create_table(
        "case_notes",
        sa.Column("id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("case_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("author", sa.String(64), nullable=False),
        sa.Column("body", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["case_id"], ["incident_cases.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_case_notes_case_id", "case_notes", ["case_id"])

    op.create_table(
        "detection_rule_configs",
        sa.Column("rule_id", sa.String(64), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("severity_override", sa.String(16), nullable=True),
        sa.Column("threshold_override", sa.Integer(), nullable=True),
        sa.Column("updated_by", sa.String(64), nullable=False, server_default="system"),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("rule_id"),
    )
    now = datetime.now(timezone.utc)
    rules = sa.table(
        "detection_rule_configs",
        sa.column("rule_id", sa.String(64)),
        sa.column("enabled", sa.Boolean()),
        sa.column("severity_override", sa.String(16)),
        sa.column("threshold_override", sa.Integer()),
        sa.column("updated_by", sa.String(64)),
        sa.column("updated_at", sa.DateTime(timezone=True)),
    )
    op.bulk_insert(rules, [
        {"rule_id": rule_id, "enabled": True, "severity_override": None,
         "threshold_override": None, "updated_by": "system", "updated_at": now}
        for rule_id in RULES
    ])


def downgrade() -> None:
    op.drop_table("detection_rule_configs")
    op.drop_index("ix_case_notes_case_id", table_name="case_notes")
    op.drop_table("case_notes")
    op.drop_index("ix_case_alert_links_alert_id", table_name="case_alert_links")
    op.drop_index("ix_case_alert_links_case_id", table_name="case_alert_links")
    op.drop_table("case_alert_links")
    for column in ("assignee", "severity", "priority", "status", "case_number"):
        op.drop_index(f"ix_incident_cases_{column}", table_name="incident_cases")
    op.drop_table("incident_cases")
