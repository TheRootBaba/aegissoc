"""Add managed asset risk and auditable response playbook runs."""
from alembic import op
import sqlalchemy as sa

revision = "0013_asset_risk_playbooks"
down_revision = "0012_threat_intel_correlation"
branch_labels = None
depends_on = None

def upgrade() -> None:
    op.create_table(
        "managed_assets",
        sa.Column("id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("asset_key", sa.String(160), nullable=False),
        sa.Column("hostname", sa.String(255), nullable=False),
        sa.Column("asset_type", sa.String(32), nullable=False, server_default="server"),
        sa.Column("environment", sa.String(32), nullable=False, server_default="unknown"),
        sa.Column("owner", sa.String(120), nullable=True),
        sa.Column("criticality", sa.String(16), nullable=False, server_default="medium"),
        sa.Column("status", sa.String(16), nullable=False, server_default="active"),
        sa.Column("tags", sa.JSON(), nullable=False),
        sa.Column("notes", sa.Text(), nullable=False, server_default=""),
        sa.Column("created_by", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("asset_key", name="uq_managed_assets_asset_key"),
    )
    for col in ("asset_key", "hostname", "environment", "owner", "criticality", "status"):
        op.create_index("ix_managed_assets_" + col, "managed_assets", [col])
    op.create_table(
        "vulnerability_findings",
        sa.Column("id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("asset_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("vulnerability_id", sa.String(64), nullable=False),
        sa.Column("title", sa.String(200), nullable=False),
        sa.Column("severity", sa.String(16), nullable=False),
        sa.Column("status", sa.String(20), nullable=False, server_default="open"),
        sa.Column("source", sa.String(120), nullable=False),
        sa.Column("description", sa.Text(), nullable=False, server_default=""),
        sa.Column("discovered_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("due_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["asset_id"], ["managed_assets.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("asset_id", "vulnerability_id", name="uq_vulnerability_findings_asset_vuln"),
    )
    for col in ("asset_id", "vulnerability_id", "severity", "status", "discovered_at"):
        op.create_index("ix_vulnerability_findings_" + col, "vulnerability_findings", [col])
    op.create_table(
        "response_playbook_runs",
        sa.Column("id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("case_id", sa.Uuid(as_uuid=True), nullable=True),
        sa.Column("title", sa.String(160), nullable=False),
        sa.Column("status", sa.String(20), nullable=False, server_default="in_progress"),
        sa.Column("steps", sa.JSON(), nullable=False),
        sa.Column("created_by", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["case_id"], ["incident_cases.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    for col in ("case_id", "status"):
        op.create_index("ix_response_playbook_runs_" + col, "response_playbook_runs", [col])

def downgrade() -> None:
    for col in ("status", "case_id"):
        op.drop_index("ix_response_playbook_runs_" + col, table_name="response_playbook_runs")
    op.drop_table("response_playbook_runs")
    for col in ("discovered_at", "status", "severity", "vulnerability_id", "asset_id"):
        op.drop_index("ix_vulnerability_findings_" + col, table_name="vulnerability_findings")
    op.drop_table("vulnerability_findings")
    for col in ("status", "criticality", "owner", "environment", "hostname", "asset_key"):
        op.drop_index("ix_managed_assets_" + col, table_name="managed_assets")
    op.drop_table("managed_assets")
