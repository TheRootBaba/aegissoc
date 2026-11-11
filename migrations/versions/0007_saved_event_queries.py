"""Persist reusable analyst investigation queries."""
from alembic import op
import sqlalchemy as sa

revision = "0007_saved_event_queries"
down_revision = "0006_source_registry"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "saved_event_queries",
        sa.Column("id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("name", sa.String(length=100), nullable=False),
        sa.Column("description", sa.String(length=500), nullable=True),
        sa.Column("query", sa.JSON(), nullable=False),
        sa.Column("is_shared", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("created_by", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("created_by", "name", name="uq_saved_event_queries_owner_name"),
    )
    op.create_index(
        "ix_saved_event_queries_created_by", "saved_event_queries", ["created_by"]
    )


def downgrade() -> None:
    op.drop_index("ix_saved_event_queries_created_by", table_name="saved_event_queries")
    op.drop_table("saved_event_queries")
