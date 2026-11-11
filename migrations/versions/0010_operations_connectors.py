"""Add retention policies, operational job history, and connector registry."""

from datetime import datetime, timezone

from alembic import op
import sqlalchemy as sa

revision = "0010_operations_connectors"
down_revision = "0009_audit_chain"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "retention_policies",
        sa.Column("id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("data_kind", sa.String(32), nullable=False),
        sa.Column("retention_days", sa.Integer(), nullable=False, server_default="90"),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("preserve_active_evidence", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("updated_by", sa.String(64), nullable=False, server_default="system"),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("data_kind", name="uq_retention_policies_data_kind"),
    )
    op.create_table(
        "operational_job_runs",
        sa.Column("id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("job_name", sa.String(64), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("records_affected", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("error_type", sa.String(120), nullable=True),
        sa.Column("details", sa.JSON(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    for column in ("job_name", "status", "started_at"):
        op.create_index(f"ix_operational_job_runs_{column}", "operational_job_runs", [column])
    op.create_table(
        "connector_configs",
        sa.Column("id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("connector_key", sa.String(80), nullable=False),
        sa.Column("connector_type", sa.String(32), nullable=False),
        sa.Column("display_name", sa.String(120), nullable=False),
        sa.Column("config", sa.JSON(), nullable=False),
        sa.Column("credential_ref", sa.String(255), nullable=True),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("health_status", sa.String(24), nullable=False, server_default="unverified"),
        sa.Column("last_checked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_success_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_error_type", sa.String(120), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("connector_key", name="uq_connector_configs_connector_key"),
    )
    op.create_index("ix_connector_configs_connector_key", "connector_configs", ["connector_key"])
    op.create_index("ix_connector_configs_connector_type", "connector_configs", ["connector_type"])
    op.create_index("ix_connector_configs_health_status", "connector_configs", ["health_status"])

    now = datetime.now(timezone.utc)
    policies = sa.table(
        "retention_policies",
        sa.column("id", sa.Uuid(as_uuid=True)),
        sa.column("data_kind", sa.String(32)),
        sa.column("retention_days", sa.Integer()),
        sa.column("enabled", sa.Boolean()),
        sa.column("preserve_active_evidence", sa.Boolean()),
        sa.column("updated_by", sa.String(64)),
        sa.column("updated_at", sa.DateTime(timezone=True)),
    )
    import uuid
    op.bulk_insert(policies, [
        {"id": uuid.uuid4(), "data_kind": "events", "retention_days": 90, "enabled": True, "preserve_active_evidence": True, "updated_by": "system", "updated_at": now},
        {"id": uuid.uuid4(), "data_kind": "executions", "retention_days": 180, "enabled": True, "preserve_active_evidence": True, "updated_by": "system", "updated_at": now},
        {"id": uuid.uuid4(), "data_kind": "jobs", "retention_days": 90, "enabled": True, "preserve_active_evidence": False, "updated_by": "system", "updated_at": now},
    ])


def downgrade() -> None:
    op.drop_index("ix_connector_configs_health_status", table_name="connector_configs")
    op.drop_index("ix_connector_configs_connector_type", table_name="connector_configs")
    op.drop_index("ix_connector_configs_connector_key", table_name="connector_configs")
    op.drop_table("connector_configs")
    op.drop_index("ix_operational_job_runs_started_at", table_name="operational_job_runs")
    op.drop_index("ix_operational_job_runs_status", table_name="operational_job_runs")
    op.drop_index("ix_operational_job_runs_job_name", table_name="operational_job_runs")
    op.drop_table("operational_job_runs")
    op.drop_table("retention_policies")
