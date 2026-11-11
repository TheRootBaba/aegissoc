"""Add normalized Sigma correlation metadata."""

from alembic import op
import sqlalchemy as sa

revision = "0019_sigma_correlation"
down_revision = "0018_oidc_identities"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("sigma_rules", sa.Column("correlation", sa.JSON(), nullable=True))


def downgrade() -> None:
    op.drop_column("sigma_rules", "correlation")
