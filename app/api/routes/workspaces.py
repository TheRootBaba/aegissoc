from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.security import get_current_user, require_roles
from app.db.session import get_db, set_workspace_context
from app.models import User, Workspace, WorkspaceMembership, RetentionPolicy
from app.schemas.workspaces import WorkspaceCreate, WorkspaceMemberCreate
from app.services.audit_chain import append_audit_entry

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

@router.post("", status_code=201)
def create_workspace(
    payload: WorkspaceCreate,
    current_user: User = Depends(require_roles("admin")),
    db: Session = Depends(get_db),
) -> dict:
    existing = db.scalar(select(Workspace.id).where(Workspace.slug == payload.slug))
    if existing is not None:
        raise HTTPException(status_code=409, detail="Workspace slug already exists")
    workspace = Workspace(slug=payload.slug, name=payload.name.strip(), is_active=True)
    db.add(workspace)
    try:
        db.flush()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail="Workspace slug already exists") from exc
    set_workspace_context(
        db, workspace.id, user_id=current_user.id,
        manage_memberships=True, manage_workspaces=True,
    )
    db.add(WorkspaceMembership(
        workspace_id=workspace.id, user_id=current_user.id, role="admin", is_active=True,
    ))
    db.add_all([
        RetentionPolicy(workspace_id=workspace.id, data_kind="events", retention_days=90, enabled=True, preserve_active_evidence=True, updated_by=current_user.username),
        RetentionPolicy(workspace_id=workspace.id, data_kind="executions", retention_days=90, enabled=True, preserve_active_evidence=True, updated_by=current_user.username),
        RetentionPolicy(workspace_id=workspace.id, data_kind="jobs", retention_days=30, enabled=True, preserve_active_evidence=True, updated_by=current_user.username),
    ])
    append_audit_entry(
        db, actor=current_user.username, action="workspace.created",
        resource_type="workspace", resource_id=str(workspace.id),
        details={"slug": workspace.slug, "name": workspace.name},
    )
    db.commit()
    return _workspace_read(workspace, "admin")


@router.post("/{workspace_id}/memberships", status_code=201)
def add_workspace_member(
    workspace_id: UUID,
    payload: WorkspaceMemberCreate,
    current_user: User = Depends(require_roles("admin")),
    db: Session = Depends(get_db),
) -> dict:
    if db.info.get("workspace_id") != workspace_id:
        raise HTTPException(status_code=404, detail="Workspace not found")
    user = db.scalar(select(User).where(User.username == payload.username))
    if user is None:
        raise HTTPException(status_code=404, detail="User account not found")
    membership = db.scalar(select(WorkspaceMembership).where(
        WorkspaceMembership.workspace_id == workspace_id,
        WorkspaceMembership.user_id == user.id,
    ))
    if membership is not None:
        if membership.is_active:
            raise HTTPException(status_code=409, detail="User is already an active workspace member")
        membership.is_active = True
        membership.role = payload.role
    else:
        membership = WorkspaceMembership(
            workspace_id=workspace_id, user_id=user.id, role=payload.role, is_active=True,
        )
        db.add(membership)
    db.flush()
    append_audit_entry(
        db, actor=current_user.username, action="workspace.member_added",
        resource_type="workspace_membership", resource_id=str(membership.id),
        details={"workspace_id": str(workspace_id), "username": user.username, "role": payload.role},
    )
    db.commit()
    return {
        "id": str(membership.id), "user_id": str(user.id),
        "username": user.username, "role": membership.role,
        "is_active": membership.is_active, "created_at": membership.created_at,
    }


@router.get("/{workspace_id}/memberships")
def list_workspace_members(
    workspace_id: UUID,
    _admin: User = Depends(require_roles("admin")),
    db: Session = Depends(get_db),
) -> list[dict]:
    if db.info.get("workspace_id") != workspace_id:
        raise HTTPException(status_code=404, detail="Workspace not found")
    rows = db.execute(
        select(WorkspaceMembership, User.username)
        .join(User, User.id == WorkspaceMembership.user_id)
        .where(WorkspaceMembership.workspace_id == workspace_id)
        .order_by(User.username.asc())
    ).all()
    return [{
        "id": str(membership.id), "user_id": str(membership.user_id),
        "username": username, "role": membership.role,
        "is_active": membership.is_active, "created_at": membership.created_at,
    } for membership, username in rows]
