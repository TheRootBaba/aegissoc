"""Add durable response action attempts, leases, and reconciliation metadata."""

from alembic import op
import sqlalchemy as sa

revision = "0017_response_execution"
down_revision = "0016_tenant_isolation"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("response_action_requests", sa.Column("execution_attempts", sa.Integer(), nullable=False, server_default="0"))
    op.add_column("response_action_requests", sa.Column("next_attempt_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("response_action_requests", sa.Column("locked_until", sa.DateTime(timezone=True), nullable=True))
    op.add_column("response_action_requests", sa.Column("last_error_type", sa.String(120), nullable=True))
    op.add_column("response_action_requests", sa.Column("external_reference", sa.String(160), nullable=True))
    op.create_index("ix_response_action_requests_next_attempt_at", "response_action_requests", ["next_attempt_at"])
    op.create_index("ix_response_action_requests_locked_until", "response_action_requests", ["locked_until"])


def downgrade() -> None:
    op.drop_index("ix_response_action_requests_locked_until", table_name="response_action_requests")
    op.drop_index("ix_response_action_requests_next_attempt_at", table_name="response_action_requests")
    op.drop_column("response_action_requests", "external_reference")
    op.drop_column("response_action_requests", "last_error_type")
    op.drop_column("response_action_requests", "locked_until")
    op.drop_column("response_action_requests", "next_attempt_at")
    op.drop_column("response_action_requests", "execution_attempts")
