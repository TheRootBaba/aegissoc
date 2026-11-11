"""Workspace-aware execution helpers for privileged background workers."""

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.session import set_workspace_context
from app.models import Workspace


def active_workspace_ids(db: Session) -> list:
    """Enumerate active workspaces using the explicit worker RLS context."""
    db.info.pop('workspace_id', None)
    db.info.pop('user_id', None)
    set_workspace_context(db, None, worker=True)
    return list(db.scalars(
        select(Workspace.id).where(Workspace.is_active.is_(True)).order_by(Workspace.id.asc())
    ).all())


def activate_workspace(db: Session, workspace_id) -> None:
    set_workspace_context(db, workspace_id, worker=True)
