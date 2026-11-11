# AegisSOC

A local-first Security Operations Center platform for collecting, normalizing, and investigating security events. The current release is an engineering foundation for a controlled lab; it is not yet a production SIEM.

## Current capabilities

- FastAPI event ingestion and retrieval API backed by PostgreSQL.
- Canonical event normalization endpoint for common nested source fields and severity aliases; original source payloads are retained in `raw`.
- Deterministic SSH brute-force detection with persistent, deduplicated alerts and event-level evidence references.
- Validated event payloads with timezone-aware timestamps.
- Event search by severity, source, event type, hostname, source IP, and inclusive time range.
- Bounded offset pagination (limit 1–200) with deterministic timestamp/UUID ordering.
- Liveness and database-readiness endpoints.
- Alembic-managed database schema migrations.
- Per-request X-Request-ID response header and JSON application logs.
- Automated API tests using an isolated SQLite database.
- GitHub Actions test workflow for pushes and pull requests.

## Architecture

```text
Event producers (manual lab input today; Wazuh adapter planned)
                         |
                         v
                 FastAPI API layer
          validation / request correlation
                         |
                         v
                  PostgreSQL store
                         |
             query API / detection engine
             evidence-backed alert store
```

## Requirements

- Windows 10/11 with virtualization enabled
- WSL2 + Ubuntu and Docker Desktop using the WSL2 backend
- Git
- Python 3.12 for running tests outside Docker

## Run with Docker

1. Copy the example environment file and set a strong local database password:

   ```powershell
   Copy-Item .env.example .env
   ```

2. Start the stack:

   ```powershell
   docker compose up --build -d
   docker compose ps
   ```

   The API container applies pending Alembic migrations before starting Uvicorn.

3. Open the API documentation at http://localhost:8000/docs. Liveness and readiness are available at /health/live and /health/ready.

4. Stop the stack with docker compose down. To delete the database volume as well (destructive), use docker compose down -v.

## Run locally

A PostgreSQL server must be running and DATABASE_URL in .env must point to it.

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
Copy-Item .env.example .env
alembic upgrade head
uvicorn app.main:app --reload
```

## Configuration

| Variable | Description | Default |
|---|---|---|
| APP_NAME | API title | AegisSOC API |
| APP_ENV | development, test, staging, or production | development |
| DATABASE_URL | SQLAlchemy database URL | local SQLite URL in code; Docker Compose supplies PostgreSQL |
| LOG_LEVEL | DEBUG, INFO, WARNING, ERROR, or CRITICAL | INFO |

Do not commit .env or put real credentials, tokens, or production logs in the repository. Rotate any credential that has been exposed.

## API usage

### Ingest a synthetic event (PowerShell)

```powershell
$body = @{
  source = "lab-manual"
  event_type = "authentication.failure"
  severity = "medium"
  timestamp = (Get-Date).ToUniversalTime().ToString("o")
  hostname = "ubuntu-lab"
  source_ip = "192.0.2.25"
  username = "analyst"
  message = "Synthetic failed SSH login for detection testing."
  raw = @{ synthetic = $true; scenario = "ssh-failures" }
} | ConvertTo-Json -Depth 5

Invoke-RestMethod -Method Post -Uri http://localhost:8000/api/v1/events -ContentType "application/json" -Body $body
```

### Normalize and ingest source events

Source adapters can submit source-specific JSON to `POST /api/v1/events/ingest/{source}`. The source identifier is part of the URL. The normalizer maps common timestamp, event action, severity, host, IP, username, and message aliases into the canonical event contract. For example, use `/api/v1/events/ingest/syslog-lab` with fields such as `@timestamp`, `event.action`, `event.severity`, `host.name`, `src_ip`, `user.name`, and `message`. The endpoint stores the normalized event and retains the submitted source record in `raw`. Missing required fields and unsupported severity values are rejected rather than guessed. The original `POST /api/v1/events` contract remains available.

### Run detections and inspect alerts

The first detection pack contains two deterministic rules. AUTH-SSH-001 detects repeated SSH authentication failures from one source IP against one target host (five failures by default). AUTH-SSH-002 detects password spraying when the same source/target pair attempts five or more distinct usernames in the window. Both require a source IP and an SSH indicator in the event type or message. The detector is intentionally run on demand in this phase; scheduling and analyst workflow are later work.

```powershell
# Evaluate recent events using the default five-failure / ten-minute threshold
$run = Invoke-RestMethod -Method Post -Uri http://localhost:8000/api/v1/detections/run -ContentType "application/json" -Body (@{ window_minutes = 10; threshold = 5 } | ConvertTo-Json)

# Inspect generated alerts and their evidence event IDs
Invoke-RestMethod "http://localhost:8000/api/v1/alerts"
$run.alerts | Format-List
```

Repeated detector runs update the matching alert instead of creating duplicates. Alerts retain the IDs of the source events that triggered the rule.\n\n### Investigate and manage alerts\n\nPhase 1.5 adds alert detail, lifecycle transitions, assignment, analyst notes, and an append-only audit history. Supported statuses are `open`, `acknowledged`, `in_progress`, `resolved`, and `false_positive`. Reopen a resolved or false-positive alert by moving it back to `open`; invalid transitions return HTTP 409. The `actor`/`author` values are analyst-supplied labels for the lab workflow, not authenticated identities. Authentication and trusted identity binding are reserved for Phase 1.7.\n\n```powershell\n# Inspect one alert\n$alertId = "<alert-id>"\nInvoke-RestMethod "http://localhost:8000/api/v1/alerts/$alertId"\n\n# Assign and acknowledge it\n$update = @{ actor = "analyst-01"; assigned_to = "analyst-01"; status = "acknowledged" } | ConvertTo-Json\nInvoke-RestMethod -Method Patch -Uri "http://localhost:8000/api/v1/alerts/$alertId" -ContentType "application/json" -Body $update\n\n# Add an investigation note\n$note = @{ author = "analyst-01"; body = "Validated source IP against the synthetic lab timeline." } | ConvertTo-Json\nInvoke-RestMethod -Method Post -Uri "http://localhost:8000/api/v1/alerts/$alertId/notes" -ContentType "application/json" -Body $note\n\n# Review notes and the audit trail\nInvoke-RestMethod "http://localhost:8000/api/v1/alerts/$alertId/notes"\nInvoke-RestMethod "http://localhost:8000/api/v1/alerts/$alertId/history"\n\n# Resolve after investigation\n$resolve = @{ actor = "analyst-01"; status = "resolved" } | ConvertTo-Json\nInvoke-RestMethod -Method Patch -Uri "http://localhost:8000/api/v1/alerts/$alertId" -ContentType "application/json" -Body $resolve\n```

### Search events

All filters are optional and combine with AND semantics. start_time and end_time are inclusive and must include a timezone offset. Results are ordered newest first; UUID is used as a stable tie-breaker when timestamps match.

```powershell
# Page through all events
Invoke-RestMethod "http://localhost:8000/api/v1/events?limit=25&offset=0"

# Exact-match filters
Invoke-RestMethod "http://localhost:8000/api/v1/events?severity=high&source=wazuh-lab&event_type=authentication.failure"

# Time-bounded search (UTC)
Invoke-RestMethod "http://localhost:8000/api/v1/events?start_time=2026-11-11T10:00:00Z&end_time=2026-11-11T11:00:00Z"
```

Every HTTP response includes an X-Request-ID header. Use it to correlate a client request with its server-side log entries. The ID is generated by the API; caller-supplied IDs are not trusted.

## Database migrations

Migrations are version-controlled under migrations/versions. For local development, run alembic upgrade head after installing dependencies and configuring DATABASE_URL. To inspect the current revision, run alembic current; to see pending history, run alembic history.

Do not use Base.metadata.create_all() to provision application databases. Schema changes must be represented by reviewed Alembic revisions.

## Tests and continuous integration

Run the test suite locally:

```powershell
python -m pytest -q
```

Tests use an isolated in-memory SQLite database and do not require PostgreSQL. GitHub Actions runs the same test suite on pushes to main and on pull requests targeting main.

## Repository layout

```text
aegissoc/
├── .github/workflows/
├── app/
│   ├── api/routes/
│   ├── core/
│   ├── db/
│   ├── models.py
│   ├── schemas/
│   └── main.py
├── migrations/
│   ├── versions/
│   └── env.py
├── tests/
├── alembic.ini
├── compose.yaml
├── Dockerfile
└── requirements.txt
```

## Security boundary

Only ingest events from systems you own or are explicitly authorized to monitor. Use synthetic data during development. Authentication, authorization, rate limiting, retention controls, alerting, and production deployment hardening remain future work.

## Roadmap

1. Phase 1.1: migration discipline, validated configuration, request correlation, structured logs, bounded event queries.
2. Phase 1.2: event search filters, stable pagination, and automated test execution.
3. Phase 1.3: normalized event contract and ingestion validation.
4. Phase 1.4: deterministic SSH brute-force detection and evidence-backed alerts.
5. Phase 1.5: alert lifecycle and analyst workflow.
6. Phase 1.6: MITRE ATT&CK references and Wazuh integration.
7. Phase 1.7: operational security controls and deployment readiness.
