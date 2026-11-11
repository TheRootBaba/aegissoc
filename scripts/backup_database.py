"""Create a PostgreSQL custom-format backup and verify a real temporary restore."""

import argparse
import hashlib
import os
import subprocess
import uuid
from datetime import datetime, timezone
from pathlib import Path

import psycopg
from sqlalchemy.engine import make_url


REQUIRED_TABLES = {
    "alembic_version", "security_events", "detection_alerts",
    "security_audit_entries", "source_registry",
}


def _postgres_env(url):
    env = os.environ.copy()
    if url.password:
        env["PGPASSWORD"] = url.password
    return env


def _base_args(url):
    args = []
    if url.host:
        args += ["--host", url.host]
    if url.port:
        args += ["--port", str(url.port)]
    if url.username:
        args += ["--username", url.username]
    return args


def create_backup(output_dir: Path) -> Path:
    database_url = os.environ.get("DATABASE_URL")
    if not database_url:
        raise RuntimeError("DATABASE_URL is required")
    url = make_url(database_url)
    if url.get_backend_name() != "postgresql":
        raise RuntimeError("Backup verification requires PostgreSQL")
    output_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    backup_path = output_dir / f"aegissoc-{stamp}.dump"
    env = _postgres_env(url)
    common = _base_args(url)

    subprocess.run(
        ["pg_dump", *common, "--format=custom", "--no-owner", "--file", str(backup_path), url.database],
        check=True, env=env,
    )
    subprocess.run(
        ["pg_restore", "--list", str(backup_path)],
        check=True, env=env, stdout=subprocess.DEVNULL,
    )

    digest = hashlib.sha256(backup_path.read_bytes()).hexdigest()
    verify_name = f"aegis_restore_verify_{uuid.uuid4().hex[:12]}"
    admin_url = url.set(database="postgres")
    connection_kwargs = {
        "host": admin_url.host,
        "port": admin_url.port or 5432,
        "user": admin_url.username,
        "password": admin_url.password,
        "dbname": "postgres",
    }
    try:
        with psycopg.connect(**connection_kwargs, autocommit=True) as admin:
            admin.execute(f'CREATE DATABASE "{verify_name}"')
        restore_args = [
            "pg_restore", *common, "--no-owner", "--exit-on-error",
            "--dbname", url.set(database=verify_name).render_as_string(hide_password=True),
            str(backup_path),
        ]
        restore_env = _postgres_env(url)
        subprocess.run(restore_args, check=True, env=restore_env)
        with psycopg.connect(**{**connection_kwargs, "dbname": verify_name}) as restored:
            rows = restored.execute(
                "SELECT tablename FROM pg_catalog.pg_tables WHERE schemaname = 'public'"
            ).fetchall()
            restored_tables = {row[0] for row in rows}
            missing = REQUIRED_TABLES - restored_tables
            if missing:
                raise RuntimeError("Restore verification missing required tables: " + ", ".join(sorted(missing)))
            migration = restored.execute("SELECT version_num FROM alembic_version").fetchone()
            if migration is None:
                raise RuntimeError("Restored database has no Alembic revision")
    finally:
        with psycopg.connect(**connection_kwargs, autocommit=True) as admin:
            admin.execute(f'DROP DATABASE IF EXISTS "{verify_name}" WITH (FORCE)')

    manifest = backup_path.with_suffix(".sha256")
    manifest.write_text(f"{digest}  {backup_path.name}\n", encoding="utf-8")
    print(f"backup={backup_path.name}")
    print(f"sha256={digest}")
    print(f"restore_verification=passed")
    return backup_path


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=Path("./backups"))
    args = parser.parse_args()
    create_backup(args.output_dir)
