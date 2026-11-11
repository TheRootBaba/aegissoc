"""Create global tamper-evident security audit chain."""
from datetime import datetime, timezone

from alembic import op
import sqlalchemy as sa

revision = "0009_audit_chain"
down_revision = "0008_detection_schedules"
branch_labels = None
depends_on = None

GENESIS_HASH = "0" * 64


def upgrade() -> None:
    op.create_table(
        "audit_chain_state",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("head_sequence", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("head_hash", sa.String(length=64), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "security_audit_entries",
        sa.Column("id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("sequence", sa.BigInteger(), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("actor", sa.String(length=64), nullable=False),
        sa.Column("action", sa.String(length=100), nullable=False),
        sa.Column("resource_type", sa.String(length=64), nullable=False),
        sa.Column("resource_id", sa.String(length=128), nullable=True),
        sa.Column("details", sa.JSON(), nullable=False),
        sa.Column("previous_hash", sa.String(length=64), nullable=False),
        sa.Column("entry_hash", sa.String(length=64), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("sequence", name="uq_security_audit_entries_sequence"),
    )
    op.create_index("ix_security_audit_entries_sequence", "security_audit_entries", ["sequence"])
    op.create_index("ix_security_audit_entries_occurred_at", "security_audit_entries", ["occurred_at"])
    op.create_index("ix_security_audit_entries_actor", "security_audit_entries", ["actor"])
    op.create_index("ix_security_audit_entries_action", "security_audit_entries", ["action"])
    op.create_index("ix_security_audit_entries_resource_type", "security_audit_entries", ["resource_type"])

    state = sa.table(
        "audit_chain_state",
        sa.column("id", sa.Integer()),
        sa.column("head_sequence", sa.BigInteger()),
        sa.column("head_hash", sa.String(length=64)),
        sa.column("updated_at", sa.DateTime(timezone=True)),
    )
    op.get_bind().execute(sa.insert(state).values(
        id=1, head_sequence=0, head_hash=GENESIS_HASH,
        updated_at=datetime.now(timezone.utc),
    ))


def downgrade() -> None:
    op.drop_index("ix_security_audit_entries_resource_type", table_name="security_audit_entries")
    op.drop_index("ix_security_audit_entries_action", table_name="security_audit_entries")
    op.drop_index("ix_security_audit_entries_actor", table_name="security_audit_entries")
    op.drop_index("ix_security_audit_entries_occurred_at", table_name="security_audit_entries")
    op.drop_index("ix_security_audit_entries_sequence", table_name="security_audit_entries")
    op.drop_table("security_audit_entries")
    op.drop_table("audit_chain_state")
