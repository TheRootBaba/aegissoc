"""Add curated threat indicators for IOC enrichment."""
from alembic import op
import sqlalchemy as sa
revision = "0012_threat_intel_correlation"
down_revision = "0011_cases_detection_governance"
branch_labels = None
depends_on = None

def upgrade() -> None:
    op.create_table("threat_indicators",
        sa.Column("id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("indicator_type", sa.String(16), nullable=False),
        sa.Column("value", sa.String(255), nullable=False),
        sa.Column("confidence", sa.Integer(), nullable=False, server_default="50"),
        sa.Column("severity", sa.String(16), nullable=False, server_default="medium"),
        sa.Column("status", sa.String(16), nullable=False, server_default="active"),
        sa.Column("source", sa.String(120), nullable=False),
        sa.Column("description", sa.String(500), nullable=False, server_default=""),
        sa.Column("tags", sa.JSON(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_by", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("indicator_type", "value", name="uq_threat_indicators_type_value"))
    for name, col in [("indicator_type","indicator_type"),("value","value"),("status","status"),("expires_at","expires_at")]:
        op.create_index("ix_threat_indicators_"+name, "threat_indicators", [col])

def downgrade() -> None:
    for name in ("expires_at","status","value","indicator_type"):
        op.drop_index("ix_threat_indicators_"+name, table_name="threat_indicators")
    op.drop_table("threat_indicators")
