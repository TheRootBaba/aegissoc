from uuid import UUID

from sqlalchemy import create_engine, event, select, text
from sqlalchemy.orm import Session, sessionmaker, with_loader_criteria

from app.core.config import settings
from app.db.base import Base
from app import models as _models

connect_args = {"check_same_thread": False} if settings.database_url.startswith("sqlite") else {}
engine = create_engine(settings.database_url, pool_pre_ping=True, connect_args=connect_args)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


def set_workspace_context(db: Session, workspace_id: UUID | str | None, *,
                          user_id: UUID | str | None = None, worker: bool = False, manage_memberships: bool = False, manage_workspaces: bool = False) -> None:
    """Bind the current transaction and future transactions to one workspace."""
    selected_workspace = UUID(str(workspace_id)) if workspace_id is not None else None
    previous_workspace = db.info.get("workspace_id")
    previous_workspace = UUID(str(previous_workspace)) if previous_workspace is not None else None
    if previous_workspace != selected_workspace:
        if db.new or db.dirty or db.deleted:
            raise RuntimeError("Cannot switch workspace context while the session has pending changes")
        db.expire_all()
    if selected_workspace is None:
        db.info.pop("workspace_id", None)
    else:
        db.info["workspace_id"] = selected_workspace
    db.info["user_id"] = UUID(str(user_id)) if user_id is not None else None
    db.info["worker"] = bool(worker)
    db.info["manage_memberships"] = bool(manage_memberships)
    db.info["manage_workspaces"] = bool(manage_workspaces)
    if db.get_bind().dialect.name == "postgresql":
        db.execute(
            text(
                "SELECT set_config('aegis.workspace_id', :workspace_id, true), "
                "set_config('aegis.user_id', :user_id, true), "
                "set_config('aegis.worker', :worker, true), "
                "set_config('aegis.manage_memberships', :manage_memberships, true), "
                "set_config('aegis.manage_workspaces', :manage_workspaces, true)"
            ),
            {
                "workspace_id": str(db.info.get("workspace_id") or ""),
                "user_id": str(db.info.get("user_id") or ""),
                "worker": "on" if db.info["worker"] else "off",
                "manage_memberships": "on" if db.info["manage_memberships"] else "off",
                "manage_workspaces": "on" if db.info["manage_workspaces"] else "off",
            },
        )

def workspace_id_for_session(db: Session) -> UUID:
    value = db.info.get("workspace_id")
    if value:
        return UUID(str(value))
    if db.get_bind().dialect.name == "postgresql":
        raise RuntimeError("A workspace context is required for tenant-owned writes")
    from app.models import Workspace
    ids = list(db.scalars(select(Workspace.id).where(
        Workspace.slug == "default", Workspace.is_active.is_(True)
    )).all())
    if len(ids) != 1:
        raise RuntimeError("A unique active default workspace is required for unscoped test writes")
    return ids[0]


@event.listens_for(Session, "after_begin")
def _apply_transaction_context(session, transaction, connection):
    if connection.dialect.name != "postgresql":
        return
    connection.execute(
        text(
            "SELECT set_config('aegis.workspace_id', :workspace_id, true), "
            "set_config('aegis.user_id', :user_id, true), "
            "set_config('aegis.worker', :worker, true), "
            "set_config('aegis.manage_memberships', :manage_memberships, true), "
            "set_config('aegis.manage_workspaces', :manage_workspaces, true)"
        ),
        {
            "workspace_id": str(session.info.get("workspace_id") or ""),
            "user_id": str(session.info.get("user_id") or ""),
            "worker": "on" if session.info.get("worker") else "off",
            "manage_memberships": "on" if session.info.get("manage_memberships") else "off",
            "manage_workspaces": "on" if session.info.get("manage_workspaces") else "off",
        },
    )


@event.listens_for(Session, "before_flush")
def _assign_workspace_to_new_records(session, flush_context, instances):
    from app.models import Workspace
    selected = session.info.get("workspace_id")
    selected = UUID(str(selected)) if selected is not None else None
    for instance in session.new:
        if not hasattr(instance, "workspace_id"):
            continue
        current = getattr(instance, "workspace_id", None)
        if selected is not None and current is not None and UUID(str(current)) != selected:
            raise RuntimeError("Refusing to create tenant-owned data for a different workspace")
        if current is not None:
            continue
        value = selected
        if value is None:
            if session.get_bind().dialect.name == "postgresql":
                raise RuntimeError("Refusing to create tenant-owned data without a workspace context")
            ids = list(session.scalars(select(Workspace.id).where(
                Workspace.slug == "default", Workspace.is_active.is_(True)
            )).all())
            if len(ids) != 1:
                raise RuntimeError("A unique active default workspace is required for unscoped test writes")
            value = ids[0]
        instance.workspace_id = UUID(str(value))

    for instance in list(session.dirty) + list(session.deleted):
        if selected is not None and hasattr(instance, "workspace_id"):
            current = getattr(instance, "workspace_id", None)
            if current is None or UUID(str(current)) != selected:
                raise RuntimeError("Refusing to mutate tenant-owned data outside the active workspace")


@event.listens_for(Session, "do_orm_execute")
def _scope_orm_statements(execute_state):
    workspace_id = execute_state.session.info.get("workspace_id")
    if not workspace_id:
        return
    workspace_id = UUID(str(workspace_id))
    if execute_state.is_select:
        statement = execute_state.statement
        for mapper in Base.registry.mappers:
            model = mapper.class_
            if hasattr(model, "workspace_id"):
                statement = statement.options(
                    with_loader_criteria(
                        model,
                        lambda entity, selected=workspace_id: entity.workspace_id == selected,
                        include_aliases=True,
                    )
                )
        execute_state.statement = statement
    elif execute_state.is_update or execute_state.is_delete:
        mapper = execute_state.bind_mapper
        if mapper is not None and hasattr(mapper.class_, "workspace_id"):
            execute_state.statement = execute_state.statement.where(
                mapper.class_.workspace_id == workspace_id
            )


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
