# Operational recovery runbook

This runbook is for the local Docker Compose deployment. Adapt credentials, storage, RPO, and RTO before production use.

## First deployment of the retention and backup workers

The API container applies Alembic migrations with the migration-owner connection, provisions a separate non-owner runtime role, and then starts Uvicorn with the runtime connection. Preserve the database volume and ensure `POSTGRES_PASSWORD` in `.env` matches the existing `aegis` database role when reusing an initialized volume.

```powershell
docker compose up --build -d db api
docker compose ps
docker compose exec api alembic current
docker compose up -d scheduler retention-worker response-worker integration-worker response-worker
docker compose ps
```

Wait for the API health check to pass before running the backup profile. The retention worker also waits for the `retention_policies` table, but that guard is a startup safety net—not a replacement for explicitly applying migrations.

## Health and incident triage

1. Check API liveness and database readiness:
   `curl http://localhost:8000/health/live` and `curl http://localhost:8000/health/ready`.
2. Sign in and inspect `GET /api/v1/operations/health` and `GET /api/v1/operations/metrics`.
3. Inspect worker logs with `docker compose logs --since=30m api scheduler retention-worker integration-worker response-worker`.
4. Check source freshness and rejection counters in the Sources workspace. A stale source is not equivalent to a healthy source.
5. Review failed schedule executions and the security audit chain before making corrective changes.

## Backup and restore verification

Backups use PostgreSQL custom format. The backup job runs `pg_dump`, validates the archive catalog, restores it into a uniquely named temporary database, checks required AegisSOC tables and the Alembic revision, then drops the temporary database.

Run from PowerShell:

```powershell
docker compose --profile backup run --rm backup
```

The named `aegis_backups` volume stores dump files and SHA-256 manifests. Copy verified artifacts to independent, access-controlled storage on a separate failure domain. A local Docker volume alone is not a disaster-recovery strategy.

To inspect backup files:

```powershell
docker compose run --rm --entrypoint sh backup -c "ls -lh /backups"
```

A restore drill should use an isolated PostgreSQL instance. Never restore over the active database as a first test. For a manual restore, create an empty target database, then run `pg_restore --no-owner --exit-on-error --dbname <target>` with the selected dump. Run Alembic status and the API test suite before routing traffic to the restored instance.

## Recovery sequence

1. Stop API and worker writes: `docker compose stop api scheduler retention-worker integration-worker`.
2. Preserve the failed database volume and logs before attempting repair.
3. Provision a clean PostgreSQL target and restore the latest backup.
4. Confirm the restored Alembic revision and required tables; verify audit-chain integrity using the admin audit verification endpoint.
5. Start API first: `docker compose up -d api`; wait for `/health/ready`.
6. Start workers: `docker compose up -d scheduler retention-worker`.
7. Confirm source ingestion resumes, scheduled detections complete, and operational health returns to normal.
8. Record the incident, restore point, data-loss window, and follow-up actions in the audit trail/runbook.

## Retention safety

- Event retention defaults to 90 days; execution history defaults to 180 days; operational job history defaults to 90 days.
- Cleanup is bounded to 1,000 candidate rows per dataset per run.
- Event IDs referenced by open, acknowledged, or in-progress alerts are protected when the policy's evidence-preservation switch is enabled.
- The latest execution per schedule is always preserved.
- Retention changes and manual cleanup requests are administrator-only and audited.
- Test policy changes on a copy of the database before shortening retention in a production environment.

## Security and limitations

- Store `POSTGRES_PASSWORD` and `AUTH_SECRET_KEY` in a secrets manager for production; never commit them.
- Connector credentials are represented by external `credential_ref` values. The connector registry rejects inline secret fields and does not resolve secrets itself.
- Connector checks validate configuration only. They do not claim remote endpoint reachability or credential validity.
- A backup must be copied off-host and periodically restored in a separate environment. Hash manifests detect accidental corruption but do not replace signed, immutable storage.
- Define and test explicit RPO/RTO objectives; successful backup creation alone does not prove recovery readiness.


## Integration runtime

The connector poller is a separate process. Check its state with `GET /api/v1/connectors/runtime-health`, inspect a connector's `/executions` history and review `docker compose logs --since=30m integration-worker`. A failed poll records the exception class and schedules bounded backoff. Resolve endpoint, allowlist or credential issues before re-enabling a connector.

Credential references use `env://VARIABLE_NAME`. The API process needs the variable for approved response webhook delivery; the integration worker needs it for outbound feed polling. In Compose, the API and integration worker load the local `.env` file. Keep that file out of version control and rotate credentials through the relevant secret-management process.
