"""Create the initial security event store.

Revision ID: 0001_security_events
Revises:
Create Date: 2026-11-11

This is a baseline migration. Existing Phase 1 installations may already have
this table from SQLAlchemy create_all(), so the upgrade is intentionally
idempotent for that table. The baseline is not downgraded because doing so
could destroy events in databases that predate Alembic.
"""
from alembic import op
import sqlalchemy as sa

revision = "0001_security_events"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    if sa.inspect(bind).has_table("security_events"):
        return

    op.create_table(
        "security_events",
        sa.Column("id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("source", sa.String(length=80), nullable=False),
        sa.Column("event_type", sa.String(length=120), nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("hostname", sa.String(length=255), nullable=True),
        sa.Column("source_ip", sa.String(length=45), nullable=True),
        sa.Column("username", sa.String(length=255), nullable=True),
        sa.Column("message", sa.Text(), nullable=False),
        sa.Column("raw", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    for column in ("source", "event_type", "severity", "timestamp", "hostname", "source_ip", "username"):
        op.create_index(f"ix_security_events_{column}", "security_events", [column])


def downgrade() -> None:
    raise RuntimeError(
        "The initial schema baseline is intentionally irreversible. "
        "Back up and migrate data explicitly before changing the baseline."
    )
