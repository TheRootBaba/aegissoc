"""Create a PostgreSQL custom-format backup and verify a real temporary restore."""

import argparse
import hashlib
import os
import subprocess
import uuid
from datetime import datetime, timezone
from pathlib import Path

import psycopg
from psycopg.types.json import Jsonb
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


def _record_job(url, *, status: str, started_at: datetime, error_type: str | None, details: dict) -> None:
    connection_kwargs = {
        "host": url.host, "port": url.port or 5432, "user": url.username,
        "password": url.password, "dbname": url.database,
    }
    with psycopg.connect(**connection_kwargs) as connection:
        connection.execute(
            """INSERT INTO operational_job_runs
               (id, job_name, status, started_at, completed_at, records_affected, error_type, details)
               VALUES (%s, %s, %s, %s, %s, %s, %s, %s)""",
            (uuid.uuid4(), "database_backup", status, started_at,
             datetime.now(timezone.utc), 0, error_type, Jsonb(details)),
        )


def create_backup(output_dir: Path) -> Path:
    database_url = os.environ.get("DATABASE_URL")
    if not database_url:
        raise RuntimeError("DATABASE_URL is required")
    url = make_url(database_url)
    if url.get_backend_name() != "postgresql":
        raise RuntimeError("Backup verification requires PostgreSQL")

    started_at = datetime.now(timezone.utc)
    backup_path = None
    try:
        output_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(output_dir, 0o700)
        stamp = started_at.strftime("%Y%m%dT%H%M%SZ")
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

        os.chmod(backup_path, 0o600)
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
                "--dbname", verify_name, str(backup_path),
            ]
            subprocess.run(restore_args, check=True, env=env)
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
        _record_job(url, status="success", started_at=started_at, error_type=None, details={
            "backup_file": backup_path.name, "sha256": digest,
            "restore_verification": "passed",
        })
        print(f"backup={backup_path.name}")
        print(f"sha256={digest}")
        print("restore_verification=passed")
        return backup_path
    except Exception as exc:
        try:
            _record_job(url, status="failed", started_at=started_at,
                        error_type=type(exc).__name__, details={
                            "backup_file": backup_path.name if backup_path else None,
                            "restore_verification": "failed",
                        })
        except Exception:
            # Preserve the original backup failure if the operational journal is unavailable.
            pass
        raise


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=Path("./backups"))
    args = parser.parse_args()
    create_backup(args.output_dir)
