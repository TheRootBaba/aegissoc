"""Create workspace identity and backfill existing users into the default workspace."""

from datetime import datetime, timezone
import uuid

from alembic import op
import sqlalchemy as sa

revision = "0015_workspace_identity"
down_revision = "0014_runtime_sigma_response"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "workspaces",
        sa.Column("id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("slug", sa.String(80), nullable=False),
        sa.Column("name", sa.String(160), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("slug", name="uq_workspaces_slug"),
    )

    op.create_table(
        "workspace_memberships",
        sa.Column("id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("workspace_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("user_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("role", sa.String(16), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["workspace_id"], ["workspaces.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("workspace_id", "user_id", name="uq_workspace_memberships_workspace_user"),
    )
    op.create_index("ix_workspace_memberships_workspace_id", "workspace_memberships", ["workspace_id"])
    op.create_index("ix_workspace_memberships_user_id", "workspace_memberships", ["user_id"])

    workspace_id = uuid.uuid4()
    now = datetime.now(timezone.utc)
    bind = op.get_bind()
    workspaces = sa.table(
        "workspaces",
        sa.column("id", sa.Uuid(as_uuid=True)),
        sa.column("slug", sa.String(80)),
        sa.column("name", sa.String(160)),
        sa.column("is_active", sa.Boolean()),
        sa.column("created_at", sa.DateTime(timezone=True)),
    )
    bind.execute(
        workspaces.insert().values(
            id=workspace_id,
            slug="default",
            name="Default Workspace",
            is_active=True,
            created_at=now,
        )
    )

    users = sa.table(
        "users",
        sa.column("id", sa.Uuid(as_uuid=True)),
        sa.column("role", sa.String(16)),
        sa.column("is_active", sa.Boolean()),
    )
    memberships = sa.table(
        "workspace_memberships",
        sa.column("id", sa.Uuid(as_uuid=True)),
        sa.column("workspace_id", sa.Uuid(as_uuid=True)),
        sa.column("user_id", sa.Uuid(as_uuid=True)),
        sa.column("role", sa.String(16)),
        sa.column("is_active", sa.Boolean()),
        sa.column("created_at", sa.DateTime(timezone=True)),
    )
    for user_id, role, is_active in bind.execute(sa.select(users.c.id, users.c.role, users.c.is_active)):
        bind.execute(
            memberships.insert().values(
                id=uuid.uuid4(),
                workspace_id=workspace_id,
                user_id=user_id,
                role=role,
                is_active=is_active,
                created_at=now,
            )
        )


def downgrade() -> None:
    op.drop_index("ix_workspace_memberships_user_id", table_name="workspace_memberships")
    op.drop_index("ix_workspace_memberships_workspace_id", table_name="workspace_memberships")
    op.drop_table("workspace_memberships")
    op.drop_table("workspaces")
