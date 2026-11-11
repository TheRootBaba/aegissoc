"""PostgreSQL-only proof that the non-owner runtime role is constrained by RLS."""

import os
from datetime import datetime, timezone
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.exc import DBAPIError


@pytest.mark.skipif(not os.getenv("AEGISSOC_RLS_TEST_URL"), reason="RLS runtime-role URL is not configured")
def test_runtime_role_cannot_read_or_mutate_another_workspace():
    engine = create_engine(os.environ["AEGISSOC_RLS_TEST_URL"])
    with engine.connect() as connection:
        transaction = connection.begin()
        try:
            role = connection.execute(text(
                "SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user"
            )).one()
            assert role.rolsuper is False
            assert role.rolbypassrls is False

            user_one, user_two = uuid4(), uuid4()
            workspace_one, workspace_two = uuid4(), uuid4()
            event_one, event_two = uuid4(), uuid4()
            now = datetime.now(timezone.utc)

            connection.execute(text("SELECT set_config('aegis.worker', 'on', true)"))
            for user_id, username in ((user_one, "rls-user-one"), (user_two, "rls-user-two")):
                connection.execute(text("""
                    INSERT INTO users (id, username, password_hash, role, is_active, created_at)
                    VALUES (:id, :username, 'test-only-hash', 'analyst', true, :created_at)
                """), {"id": user_id, "username": username, "created_at": now})
            for workspace_id, slug in ((workspace_one, "rls-tenant-one"), (workspace_two, "rls-tenant-two")):
                connection.execute(text("""
                    INSERT INTO workspaces (id, slug, name, is_active, created_at)
                    VALUES (:id, :slug, :name, true, :created_at)
                """), {"id": workspace_id, "slug": slug, "name": slug, "created_at": now})
            for workspace_id, user_id in ((workspace_one, user_one), (workspace_two, user_two)):
                connection.execute(text("""
                    INSERT INTO workspace_memberships
                    (id, workspace_id, user_id, role, is_active, created_at)
                    VALUES (:id, :workspace_id, :user_id, 'analyst', true, :created_at)
                """), {"id": uuid4(), "workspace_id": workspace_id, "user_id": user_id, "created_at": now})

            connection.execute(text("SELECT set_config('aegis.worker', 'off', true)"))
            connection.execute(text("SELECT set_config('aegis.user_id', :value, true)"), {"value": str(user_one)})
            connection.execute(text("SELECT set_config('aegis.workspace_id', :value, true)"), {"value": str(workspace_one)})
            assert connection.execute(text("SELECT count(*) FROM workspaces")).scalar_one() == 1
            assert connection.execute(text("SELECT count(*) FROM workspace_memberships")).scalar_one() == 1
            nested = connection.begin_nested()
            with pytest.raises(DBAPIError):
                connection.execute(text("""
                    INSERT INTO workspace_memberships
                    (id, workspace_id, user_id, role, is_active, created_at)
                    VALUES (:id, :workspace_id, :user_id, 'admin', true, :created_at)
                """), {"id": uuid4(), "workspace_id": workspace_two, "user_id": user_one, "created_at": now})
            nested.rollback()
            connection.execute(text("SELECT set_config('aegis.manage_workspaces', 'on', true)"))
            assert connection.execute(text("SELECT count(*) FROM workspace_memberships")).scalar_one() == 1
            assert connection.execute(text("SELECT count(*) FROM workspaces")).scalar_one() == 1
            connection.execute(text("SELECT set_config('aegis.manage_workspaces', 'off', true)"))

            event_values = {
                "source": "rls-fixture", "event_type": "test.event", "severity": "low",
                "timestamp": now, "message": "workspace isolation fixture", "raw": "{}",
                "created_at": now,
            }
            connection.execute(text("""
                INSERT INTO security_events
                (id, workspace_id, source, event_type, severity, timestamp, message, raw, created_at)
                VALUES (:id, :workspace_id, :source, :event_type, :severity, :timestamp, :message,
                        CAST(:raw AS json), :created_at)
            """), {"id": event_one, "workspace_id": workspace_one, **event_values})
            connection.execute(text("SELECT set_config('aegis.user_id', :value, true)"), {"value": str(user_two)})
            connection.execute(text("SELECT set_config('aegis.workspace_id', :value, true)"), {"value": str(workspace_two)})
            connection.execute(text("""
                INSERT INTO security_events
                (id, workspace_id, source, event_type, severity, timestamp, message, raw, created_at)
                VALUES (:id, :workspace_id, :source, :event_type, :severity, :timestamp, :message,
                        CAST(:raw AS json), :created_at)
            """), {"id": event_two, "workspace_id": workspace_two, **event_values})

            connection.execute(text("SELECT set_config('aegis.workspace_id', :value, true)"), {"value": str(workspace_one)})
            visible = connection.execute(text(
                "SELECT id FROM security_events WHERE id IN (:one, :two)"
            ), {"one": event_one, "two": event_two}).scalars().all()
            assert visible == [event_one]
            changed = connection.execute(text(
                "UPDATE security_events SET message = 'cross-tenant mutation' WHERE id = :id"
            ), {"id": event_two})
            assert changed.rowcount == 0

            alert_two = uuid4()
            connection.execute(text("""
                INSERT INTO detection_alerts
                (id, workspace_id, rule_id, fingerprint, title, description, severity, status,
                 event_count, first_seen, last_seen, evidence_event_ids, updated_at, created_at)
                VALUES (:id, :workspace_id, 'rls-trigger-test', :fingerprint, 'fixture', 'fixture',
                        'low', 'open', 1, :now, :now, '[]'::json, :now, :now)
            """), {"id": alert_two, "workspace_id": workspace_two, "fingerprint": str(uuid4()), "now": now})
            connection.execute(text("SELECT set_config('aegis.user_id', :value, true)"), {"value": str(user_one)})
            connection.execute(text("SELECT set_config('aegis.workspace_id', :value, true)"), {"value": str(workspace_one)})
            nested = connection.begin_nested()
            with pytest.raises(DBAPIError):
                connection.execute(text("""
                    INSERT INTO alert_notes (id, workspace_id, alert_id, author, body, created_at)
                    VALUES (:id, :workspace_id, :alert_id, 'rls-test', 'cross-tenant reference', :created_at)
                """), {"id": uuid4(), "workspace_id": workspace_one, "alert_id": alert_two, "created_at": now})
            nested.rollback()

            nested = connection.begin_nested()
            with pytest.raises(DBAPIError):
                connection.execute(text("""
                    INSERT INTO security_events
                    (id, workspace_id, source, event_type, severity, timestamp, message, raw, created_at)
                    VALUES (:id, :workspace_id, :source, :event_type, :severity, :timestamp, :message,
                            CAST(:raw AS json), :created_at)
                """), {"id": uuid4(), "workspace_id": workspace_two, **event_values})
            nested.rollback()

            # Workspace creation uses a dedicated RLS management context,
            # then binds the new workspace before inserting its first member.
            new_workspace = uuid4()
            connection.execute(text("SELECT set_config('aegis.manage_workspaces', 'on', true)"))
            connection.execute(text("""
                INSERT INTO workspaces (id, slug, name, is_active, created_at)
                VALUES (:id, 'rls-created-workspace', 'RLS Created Workspace', true, :created_at)
            """), {"id": new_workspace, "created_at": now})
            connection.execute(text("SELECT set_config('aegis.workspace_id', :value, true)"),
                               {"value": str(new_workspace)})
            connection.execute(text("SELECT set_config('aegis.manage_memberships', 'on', true)"))
            connection.execute(text("""
                INSERT INTO workspace_memberships
                (id, workspace_id, user_id, role, is_active, created_at)
                VALUES (:id, :workspace_id, :user_id, 'admin', true, :created_at)
            """), {"id": uuid4(), "workspace_id": new_workspace, "user_id": user_one, "created_at": now})
            assert connection.execute(text("SELECT count(*) FROM workspaces WHERE id = :id"),
                                      {"id": new_workspace}).scalar_one() == 1
        finally:
            transaction.rollback()
    engine.dispose()
