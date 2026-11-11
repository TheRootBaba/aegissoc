"""Add connector execution, Sigma rules and approved response actions."""
from alembic import op
import sqlalchemy as sa

revision = "0014_runtime_sigma_response"
down_revision = "0013_asset_risk_playbooks"
branch_labels = None
depends_on = None

def upgrade() -> None:
    op.create_table(
        "connector_runtime_states",
        sa.Column("connector_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("next_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("consecutive_failures", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("locked_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("cursor", sa.JSON(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["connector_id"], ["connector_configs.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("connector_id"),
    )
    op.create_index("ix_connector_runtime_states_next_run_at", "connector_runtime_states", ["next_run_at"])
    op.create_index("ix_connector_runtime_states_locked_until", "connector_runtime_states", ["locked_until"])
    op.create_table(
        "connector_executions",
        sa.Column("id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("connector_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("duration_ms", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("records_seen", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("accepted", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("duplicates", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("rejected", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("error_type", sa.String(120), nullable=True),
        sa.ForeignKeyConstraint(["connector_id"], ["connector_configs.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    for col in ("connector_id", "status"):
        op.create_index("ix_connector_executions_" + col, "connector_executions", [col])
    op.create_table(
        "sigma_rules",
        sa.Column("rule_id", sa.String(160), nullable=False),
        sa.Column("title", sa.String(255), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("level", sa.String(16), nullable=False),
        sa.Column("status", sa.String(24), nullable=False, server_default="experimental"),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("detection", sa.JSON(), nullable=False),
        sa.Column("condition", sa.String(255), nullable=False),
        sa.Column("logsource", sa.JSON(), nullable=False),
        sa.Column("tags", sa.JSON(), nullable=False),
        sa.Column("sigma_yaml", sa.Text(), nullable=False),
        sa.Column("created_by", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("rule_id"),
    )
    op.create_index("ix_sigma_rules_level", "sigma_rules", ["level"])
    op.create_index("ix_sigma_rules_enabled", "sigma_rules", ["enabled"])
    op.create_table(
        "scanner_import_runs",
        sa.Column("id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("scanner_name", sa.String(120), nullable=False),
        sa.Column("scan_id", sa.String(160), nullable=False),
        sa.Column("result", sa.JSON(), nullable=False),
        sa.Column("created_by", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("scanner_name", "scan_id", name="uq_scanner_import_runs_scanner_scan"),
    )
    op.create_index("ix_scanner_import_runs_scanner_name", "scanner_import_runs", ["scanner_name"])
    op.create_index("ix_scanner_import_runs_scan_id", "scanner_import_runs", ["scan_id"])
    op.create_table(
        "response_action_requests",
        sa.Column("id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("case_id", sa.Uuid(as_uuid=True), nullable=True),
        sa.Column("connector_key", sa.String(80), nullable=False),
        sa.Column("action_type", sa.String(32), nullable=False),
        sa.Column("target", sa.String(255), nullable=False),
        sa.Column("parameters", sa.JSON(), nullable=False),
        sa.Column("status", sa.String(20), nullable=False, server_default="pending"),
        sa.Column("requested_by", sa.String(64), nullable=False),
        sa.Column("approved_by", sa.String(64), nullable=True),
        sa.Column("decision_note", sa.String(500), nullable=True),
        sa.Column("execution_status", sa.String(24), nullable=True),
        sa.Column("response_code", sa.Integer(), nullable=True),
        sa.Column("result_summary", sa.String(500), nullable=True),
        sa.Column("idempotency_key", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("executed_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["case_id"], ["incident_cases.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("idempotency_key", name="uq_response_action_requests_idempotency_key"),
    )
    for col in ("case_id", "connector_key", "status"):
        op.create_index("ix_response_action_requests_" + col, "response_action_requests", [col])

def downgrade() -> None:
    op.drop_index("ix_scanner_import_runs_scan_id", table_name="scanner_import_runs")
    op.drop_index("ix_scanner_import_runs_scanner_name", table_name="scanner_import_runs")
    op.drop_table("scanner_import_runs")
    for col in ("status", "connector_key", "case_id"):
        op.drop_index("ix_response_action_requests_" + col, table_name="response_action_requests")
    op.drop_table("response_action_requests")
    op.drop_index("ix_sigma_rules_enabled", table_name="sigma_rules")
    op.drop_index("ix_sigma_rules_level", table_name="sigma_rules")
    op.drop_table("sigma_rules")
    for col in ("status", "connector_id"):
        op.drop_index("ix_connector_executions_" + col, table_name="connector_executions")
    op.drop_table("connector_executions")
    op.drop_index("ix_connector_runtime_states_locked_until", table_name="connector_runtime_states")
    op.drop_index("ix_connector_runtime_states_next_run_at", table_name="connector_runtime_states")
    op.drop_table("connector_runtime_states")
