"""Add Wazuh source idempotency and MITRE ATT&CK alert metadata.

Revision ID: 0004_wazuh_attack_metadata
Revises: 0003_alert_investigation
"""
from alembic import op
import sqlalchemy as sa

revision = "0004_wazuh_attack_metadata"
down_revision = "0003_alert_investigation"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("security_events", sa.Column("external_id", sa.String(length=128), nullable=True))
    op.create_unique_constraint(
        "uq_security_events_source_external_id",
        "security_events",
        ["source", "external_id"],
    )
    op.add_column("detection_alerts", sa.Column("attack_tactic", sa.String(length=120), nullable=True))
    op.add_column("detection_alerts", sa.Column("attack_technique_id", sa.String(length=32), nullable=True))
    op.add_column("detection_alerts", sa.Column("attack_technique_name", sa.String(length=160), nullable=True))
    op.create_index("ix_detection_alerts_attack_tactic", "detection_alerts", ["attack_tactic"])
    op.create_index("ix_detection_alerts_attack_technique_id", "detection_alerts", ["attack_technique_id"])


def downgrade() -> None:
    op.drop_index("ix_detection_alerts_attack_technique_id", table_name="detection_alerts")
    op.drop_index("ix_detection_alerts_attack_tactic", table_name="detection_alerts")
    op.drop_column("detection_alerts", "attack_technique_name")
    op.drop_column("detection_alerts", "attack_technique_id")
    op.drop_column("detection_alerts", "attack_tactic")
    op.drop_constraint("uq_security_events_source_external_id", "security_events", type_="unique")
    op.drop_column("security_events", "external_id")
