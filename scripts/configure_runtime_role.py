"""Provision a non-owner, non-superuser PostgreSQL role for the running application."""

import os

import psycopg
from psycopg import sql
from sqlalchemy.engine import make_url


def main() -> None:
    migration_url = os.environ.get("MIGRATION_DATABASE_URL")
    runtime_password = os.environ.get("RUNTIME_DB_PASSWORD")
    runtime_user = os.environ.get("RUNTIME_DB_USER", "aegis_runtime")
    if not migration_url or not runtime_password or len(runtime_password) < 16:
        raise RuntimeError("MIGRATION_DATABASE_URL and a RUNTIME_DB_PASSWORD of at least 16 characters are required")
    parsed = make_url(migration_url)
    if parsed.get_backend_name() != "postgresql" or not parsed.database:
        raise RuntimeError("Runtime role provisioning requires a PostgreSQL migration URL")
    connection_url = parsed.set(drivername="postgresql").render_as_string(hide_password=False)

    with psycopg.connect(connection_url, autocommit=True) as connection:
        connection.execute(sql.SQL(
            "DO $aegis$ BEGIN "
            "IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = {role_literal}) THEN "
            "CREATE ROLE {role} LOGIN PASSWORD {password}; "
            "ELSE ALTER ROLE {role} WITH LOGIN PASSWORD {password}; "
            "END IF; END $aegis$"
        ).format(
            role_literal=sql.Literal(runtime_user),
            role=sql.Identifier(runtime_user),
            password=sql.Literal(runtime_password),
        ))
        connection.execute(sql.SQL(
            "ALTER ROLE {} WITH LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION"
        ).format(sql.Identifier(runtime_user)))
        connection.execute(sql.SQL("GRANT CONNECT ON DATABASE {} TO {}").format(
            sql.Identifier(parsed.database), sql.Identifier(runtime_user)
        ))
        connection.execute(sql.SQL("GRANT USAGE ON SCHEMA public TO {}").format(sql.Identifier(runtime_user)))
        connection.execute(sql.SQL(
            "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO {}"
        ).format(sql.Identifier(runtime_user)))
        connection.execute(sql.SQL(
            "GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA public TO {}"
        ).format(sql.Identifier(runtime_user)))
        connection.execute(sql.SQL(
            "ALTER DEFAULT PRIVILEGES FOR ROLE {} IN SCHEMA public "
            "GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO {}"
        ).format(sql.Identifier(parsed.username or "aegis"), sql.Identifier(runtime_user)))
        connection.execute(sql.SQL(
            "ALTER DEFAULT PRIVILEGES FOR ROLE {} IN SCHEMA public "
            "GRANT USAGE, SELECT, UPDATE ON SEQUENCES TO {}"
        ).format(sql.Identifier(parsed.username or "aegis"), sql.Identifier(runtime_user)))
    print("runtime_role=ready")
    print("runtime_role_superuser=false")
    print("runtime_role_bypassrls=false")


if __name__ == "__main__":
    main()
