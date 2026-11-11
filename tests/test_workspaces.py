from types import SimpleNamespace
from uuid import uuid4

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.security import get_current_user
from app.db.base import Base
from app.db.session import get_db
from app.main import app
from app.models import User, Workspace, WorkspaceMembership


def test_workspace_listing_and_lookup_are_membership_scoped():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    db = factory()
    user_id = uuid4()
    other_user_id = uuid4()
    user = SimpleNamespace(id=user_id, username="workspace-analyst", role="analyst", is_active=True)
    first = Workspace(slug="alpha", name="Alpha Workspace")
    second = Workspace(slug="bravo", name="Bravo Workspace")
    db.add_all([
        User(id=user_id, username="workspace-analyst", password_hash="test-hash", role="analyst", is_active=True),
        User(id=other_user_id, username="other-analyst", password_hash="test-hash", role="admin", is_active=True),
        first,
        second,
    ])
    db.flush()
    db.add_all([
        WorkspaceMembership(workspace_id=first.id, user_id=user_id, role="analyst", is_active=True),
        WorkspaceMembership(workspace_id=second.id, user_id=other_user_id, role="admin", is_active=True),
    ])
    db.commit()

    previous_user = app.dependency_overrides.get(get_current_user)
    previous_db = app.dependency_overrides.get(get_db)

    def override_db():
        yield db

    app.dependency_overrides[get_current_user] = lambda: user
    app.dependency_overrides[get_db] = override_db
    try:
        with TestClient(app) as client:
            listed = client.get("/api/v1/workspaces")
            assert listed.status_code == 200
            assert [item["slug"] for item in listed.json()] == ["alpha"]
            assert listed.json()[0]["role"] == "analyst"

            allowed = client.get(f"/api/v1/workspaces/{first.id}")
            assert allowed.status_code == 200
            assert allowed.json()["id"] == str(first.id)

            denied = client.get(f"/api/v1/workspaces/{second.id}")
            assert denied.status_code == 404
    finally:
        if previous_user is None:
            app.dependency_overrides.pop(get_current_user, None)
        else:
            app.dependency_overrides[get_current_user] = previous_user
        if previous_db is None:
            app.dependency_overrides.pop(get_db, None)
        else:
            app.dependency_overrides[get_db] = previous_db
        db.close()
        Base.metadata.drop_all(engine)
        engine.dispose()
