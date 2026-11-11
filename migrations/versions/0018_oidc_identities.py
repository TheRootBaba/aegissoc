"""Add pre-provisioned OpenID Connect identity mappings."""

from alembic import op
import sqlalchemy as sa

revision = "0018_oidc_identities"
down_revision = "0017_response_execution"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "external_identities",
        sa.Column("id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("issuer", sa.String(255), nullable=False),
        sa.Column("subject", sa.String(255), nullable=False),
        sa.Column("user_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("issuer", "subject", name="uq_external_identities_issuer_subject"),
    )
    op.create_index("ix_external_identities_issuer", "external_identities", ["issuer"])
    op.create_index("ix_external_identities_user_id", "external_identities", ["user_id"])


def downgrade() -> None:
    op.drop_index("ix_external_identities_user_id", table_name="external_identities")
    op.drop_index("ix_external_identities_issuer", table_name="external_identities")
    op.drop_table("external_identities")
