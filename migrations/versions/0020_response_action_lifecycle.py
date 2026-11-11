"""Add response-action expiry and dry-run isolation."""

from alembic import op
import sqlalchemy as sa

revision = "0020_response_action_lifecycle"
down_revision = "0019_sigma_correlation"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("response_action_requests", sa.Column(
        "dry_run", sa.Boolean(), nullable=False, server_default=sa.false()
    ))
    op.add_column("response_action_requests", sa.Column(
        "expires_at", sa.DateTime(timezone=True), nullable=True
    ))
    op.create_index(
        "ix_response_action_requests_expires_at",
        "response_action_requests",
        ["expires_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_response_action_requests_expires_at", table_name="response_action_requests")
    op.drop_column("response_action_requests", "expires_at")
    op.drop_column("response_action_requests", "dry_run")
