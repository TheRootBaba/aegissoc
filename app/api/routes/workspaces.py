from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.security import get_current_user, require_roles
from app.db.session import get_db
from app.models import User, Workspace, WorkspaceMembership

router = APIRouter(
    prefix="/api/v1/workspaces",
    tags=["workspaces"],
    dependencies=[Depends(require_roles("admin", "analyst", "read_only"))],
)


def _workspace_read(workspace: Workspace, role: str) -> dict:
    return {
        "id": str(workspace.id),
        "slug": workspace.slug,
        "name": workspace.name,
        "role": role,
        "created_at": workspace.created_at,
    }


@router.get("")
def list_workspaces(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list[dict]:
    """List only active workspace memberships belonging to the authenticated user."""
    rows = db.execute(
        select(Workspace, WorkspaceMembership.role)
        .join(WorkspaceMembership, WorkspaceMembership.workspace_id == Workspace.id)
        .where(
            WorkspaceMembership.user_id == current_user.id,
            WorkspaceMembership.is_active.is_(True),
            Workspace.is_active.is_(True),
        )
        .order_by(Workspace.name.asc(), Workspace.id.asc())
    ).all()
    return [_workspace_read(workspace, role) for workspace, role in rows]


@router.get("/{workspace_id}")
def get_workspace(
    workspace_id: UUID,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    """Resolve a workspace only when the caller has an active membership."""
    row = db.execute(
        select(Workspace, WorkspaceMembership.role)
        .join(WorkspaceMembership, WorkspaceMembership.workspace_id == Workspace.id)
        .where(
            Workspace.id == workspace_id,
            WorkspaceMembership.user_id == current_user.id,
            WorkspaceMembership.is_active.is_(True),
            Workspace.is_active.is_(True),
        )
    ).first()
    if row is None:
        raise HTTPException(status_code=404, detail="Workspace not found")
    workspace, role = row
    return _workspace_read(workspace, role)
