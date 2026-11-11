# AegisSOC

A local-first Security Operations Center platform for collecting, normalizing, and investigating security events. The current release is an engineering foundation for a controlled lab; it is not yet a production SIEM.

## Current capabilities

- FastAPI event ingestion and retrieval API backed by PostgreSQL.
- Canonical event normalization endpoint for common nested source fields and severity aliases; original source payloads are retained in `raw`.
- Deterministic SSH brute-force and password-spray detections with persistent, deduplicated alerts and event-level evidence references.
- MITRE ATT&CK tactic and technique metadata on detection alerts, including direct technique references.
- Native Wazuh JSON alert ingestion with rule-level severity mapping, canonical field extraction, and raw-payload preservation.
- Replay-safe source event ingestion using a unique `(source, external_id)` key.
- A browser-based analyst dashboard for alert triage, event review, and investigation workflow.
- Alert lifecycle transitions, analyst assignment, investigation notes, and append-only audit history.
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
Event producers (manual lab input / Wazuh JSON alerts)
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
                         ^
                         |
              analyst dashboard UI
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

3. Open the analyst dashboard at http://localhost:8000/dashboard. API documentation is at http://localhost:8000/docs. Liveness and readiness are available at /health/live and /health/ready.

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

### Ingest native Wazuh alerts

Send a Wazuh manager alert JSON object to `POST /api/v1/events/ingest/wazuh`. The adapter maps `rule.level` (0–3 info, 4–7 low, 8–11 medium, 12–14 high, 15 critical), `rule.description`/`rule.groups`, `agent.name`, `data.srcip`, `data.dstuser`, `timestamp`, and `full_log`. SSH authentication failures are classified as `authentication.failure` only when the alert content identifies both SSH and an authentication-failure signal; other alerts remain `wazuh.alert`. The complete submitted object is retained in `raw`. Wazuh alert `id` is stored as `external_id`; replaying the same source ID returns the original event with HTTP 200 rather than inserting a duplicate. Events without a source ID can still be ingested but cannot be deduplicated by this key.

```powershell
$wazuhAlert = @{
  id = "1710000000.12345"
  timestamp = (Get-Date).ToUniversalTime().ToString("o")
  rule = @{ id = "5710"; level = 10; description = "sshd: authentication failed"; groups = @("authentication_failed", "sshd") }
  agent = @{ id = "007"; name = "ubuntu-wazuh-01" }
  data = @{ srcip = "198.51.100.24"; dstuser = "root" }
  full_log = "sshd: Failed password for root from 198.51.100.24 port 22"
} | ConvertTo-Json -Depth 8

Invoke-RestMethod -Method Post -Uri http://localhost:8000/api/v1/events/ingest/wazuh -ContentType "application/json" -Body $wazuhAlert
```

### Bulk source ingestion

High-volume producers can submit a bounded batch to `POST /api/v1/events/ingest/{source}/bulk`. The request body is `{"events": [...]}` and accepts 1–500 source records. The same source-specific normalization rules used by the single-event endpoint apply to every record, including native Wazuh normalization when `{source}` is `wazuh`.

The endpoint returns a per-index outcome for each submitted record:
- `accepted`: a new canonical event was inserted and its event ID is returned.
- `duplicate`: the `(source, external_id)` already exists; the original event ID is returned and the original record is not overwritten.
- `rejected`: the record failed normalization or canonical validation; the error is returned for that index.

Valid records are committed together even when sibling records are rejected. The response includes received, accepted, duplicate, and rejected counts. Empty batches and batches over 500 records are rejected with HTTP 422. The PostgreSQL and SQLite insert paths use database-level `ON CONFLICT DO NOTHING` against the source/external-ID unique key, making concurrent producer retries safe rather than relying only on a pre-insert lookup.

Example PowerShell request:

```powershell
$batch = @{
  events = @(
    @{
      id = "lab-event-001"
      "@timestamp" = (Get-Date).ToUniversalTime().ToString("o")
      event = @{ action = "authentication.failure"; severity = "warning" }
      host = @{ name = "ubuntu-lab" }
      src_ip = "192.0.2.25"
      user = @{ name = "analyst" }
      message = "Synthetic failed SSH login"
    },
    @{
      id = "lab-event-002"
      "@timestamp" = (Get-Date).ToUniversalTime().ToString("o")
      event = @{ action = "process.started"; severity = "info" }
      host = @{ name = "ubuntu-lab" }
      message = "Synthetic process start"
    }
  )
} | ConvertTo-Json -Depth 8

Invoke-RestMethod -Method Post -Uri http://localhost:8000/api/v1/events/ingest/lab-sensor/bulk -ContentType "application/json" -Body $batch
```

### Run detections and inspect alerts

The first detection pack contains two deterministic rules. AUTH-SSH-001 detects repeated SSH authentication failures from one source IP against one target host (five failures by default) and maps to MITRE ATT&CK T1110 (Brute Force). AUTH-SSH-002 detects password spraying when the same source/target pair attempts five or more distinct usernames in the window and maps to T1110.003 (Password Spraying). Both map to the Credential Access tactic. Both require a source IP and an SSH indicator in the event type or message. The detector is intentionally run on demand in this phase; scheduled detection is a later work package.

```powershell
# Evaluate recent events using the default five-failure / ten-minute threshold
$run = Invoke-RestMethod -Method Post -Uri http://localhost:8000/api/v1/detections/run -ContentType "application/json" -Body (@{ window_minutes = 10; threshold = 5 } | ConvertTo-Json)

# Inspect generated alerts and their evidence event IDs
Invoke-RestMethod "http://localhost:8000/api/v1/alerts"
$run.alerts | Format-List
```

Repeated detector runs update the matching alert instead of creating duplicates. Alerts retain the IDs of the source events that triggered the rule.

### Investigate and manage alerts

Phase 1.5 adds alert detail, lifecycle transitions, assignment, analyst notes, and an append-only audit history. Supported statuses are `open`, `acknowledged`, `in_progress`, `resolved`, and `false_positive`. Reopen a resolved or false-positive alert by moving it back to `open`; invalid transitions return HTTP 409. The API derives actor and author identities from the verified bearer token; caller-supplied identity labels are ignored.

```powershell
# Inspect one alert
$alertId = "<alert-id>"
Invoke-RestMethod "http://localhost:8000/api/v1/alerts/$alertId"

# Assign and acknowledge it
$update = @{ assigned_to = "analyst-01"; status = "acknowledged" } | ConvertTo-Json
Invoke-RestMethod -Method Patch -Uri "http://localhost:8000/api/v1/alerts/$alertId" -ContentType "application/json" -Body $update

# Add an investigation note
$note = @{ body = "Validated source IP against the synthetic lab timeline." } | ConvertTo-Json
Invoke-RestMethod -Method Post -Uri "http://localhost:8000/api/v1/alerts/$alertId/notes" -ContentType "application/json" -Body $note

# Review notes and the audit trail
Invoke-RestMethod "http://localhost:8000/api/v1/alerts/$alertId/notes"
Invoke-RestMethod "http://localhost:8000/api/v1/alerts/$alertId/history"

# Resolve after investigation
$resolve = @{ status = "resolved" } | ConvertTo-Json
Invoke-RestMethod -Method Patch -Uri "http://localhost:8000/api/v1/alerts/$alertId" -ContentType "application/json" -Body $resolve
```

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

The dashboard uses `GET /api/v1/events/stats` and `GET /api/v1/alerts/stats` for all-time aggregate totals, so the headline metrics do not incorrectly count only the latest visible page. The event stream still displays the latest 25 records. Alert search also supports `status`, `rule_id`, `attack_technique_id`, and `assigned_to` filters; event search accepts `external_id`.

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
├── web/                  # Analyst dashboard assets
├── alembic.ini
├── compose.yaml
├── Dockerfile
└── requirements.txt
```

## Security boundary

Only ingest events from systems you own or are explicitly authorized to monitor. Use synthetic data during development. Local authentication and role-based authorization are implemented, but AegisSOC is still a controlled lab build rather than a production SIEM. Shared rate limiting, token revocation, tamper-evident audit chaining, retention controls, alerting, and hardened production deployment remain future work.



## Phase 1.11 — source inventory and ingestion health

AegisSOC now maintains a persistent source registry. The migration seeds the inventory from existing canonical event history so previously observed producers appear immediately; new sources are also discovered automatically when a producer submits its first event. Historical duplicate/rejection outcomes cannot be reconstructed, so the migration counts existing persisted event rows as accepted and initializes unavailable historical outcome counters to zero. Sources can also be registered by an administrator before telemetry arrives. The inventory records source type and display name, last ingestion attempt, last successfully accepted event timestamp, and cumulative accepted, duplicate, and rejected record counts.

The observed health state is intentionally distinct from registration metadata:
- **healthy** — a recent accepted event is within the freshness window and the latest ingestion attempt did not fail completely.
- **failing** — the latest observed request contained only rejected records and no successful or duplicate outcomes.
- **stale** — the last accepted event timestamp is older than 15 minutes, even if a later request only replayed an old event.
- **inactive** — the source has not yet delivered a successfully accepted event.

The stale threshold is currently a fixed 15-minute operational default. A fully rejected latest attempt takes precedence and reports failing; otherwise health is derived from the last accepted event timestamp. Registering a source does not mark it healthy.

Authenticated endpoints:
- `GET /api/v1/sources` — list the inventory and observed health.
- `GET /api/v1/sources/{source_name}` — inspect one source.
- `POST /api/v1/sources` — administrator-only registration using `source_name`, `display_name`, optional `source_type`, and optional `description`.

Single-event and bulk ingestion update source counters in the same database transaction as event persistence. PostgreSQL and SQLite use atomic upserts for concurrent counter increments. The dashboard now includes a Data Source Health workspace with per-source status, counters, last activity, administrator registration, and a 60-second refresh cadence. No source status is fabricated when there is no telemetry.

Run the new migration and restart the API after updating:

```powershell
docker compose up --build -d
docker compose exec api alembic upgrade head
```


## Roadmap

1. Phase 1.1: migration discipline, validated configuration, request correlation, structured logs, bounded event queries.
2. Phase 1.2: event search filters, stable pagination, and automated test execution.
3. Phase 1.3: normalized event contract and ingestion validation.
4. Phase 1.4: deterministic SSH brute-force detection and evidence-backed alerts.
5. Phase 1.5: alert lifecycle, analyst workflow, and local analyst dashboard.
6. Phase 1.6: native Wazuh ingestion, replay-safe source event IDs, MITRE ATT&CK technique mapping, and aggregate dashboard metrics.
7. Phase 1.7: authentication, role-based access control, trusted analyst identities, login throttling, and production secret guardrails.
8. Phase 1.8–1.9: analyst workspace, access management, and visual identity iterations.
9. Phase 1.10: bounded bulk ingestion and database-backed replay protection.
10. Phase 1.11: persistent source inventory, ingestion health, and analyst dashboard source coverage.


## Phase 1.7 — authentication and access control

The API now uses short-lived signed bearer tokens. Sign in with `POST /api/v1/auth/login` using JSON `username` and `password`, then pass the returned token as `Authorization: Bearer <token>`. `GET /api/v1/auth/me` returns the verified identity and role.

| Role | Permissions |
|---|---|
| `admin` | Read SOC data, ingest events, run detections, manage alerts, create/list users |
| `analyst` | Read SOC data, ingest events, run detections, manage alerts and notes |
| `read_only` | Read events, alerts, metrics, notes, and audit history |

There is no public self-registration or default account. Create the first administrator interactively after migrations:

```powershell
docker compose exec api python -m scripts.create_admin
```

For local non-container development, run `python -m scripts.create_admin` after `alembic upgrade head`. Rotate an existing account password interactively with `docker compose exec api python -m scripts.reset_password` (or `python -m scripts.reset_password` outside Docker). User provisioning is administrator-only through `POST /api/v1/auth/users`. Passwords require at least 12 characters and are stored as salted PBKDF2-HMAC-SHA256 hashes. Analyst identity in alert updates, notes, and audit entries comes from the verified token; client-supplied actor labels are ignored.

### Security configuration

- Set `AUTH_SECRET_KEY` to a unique random value of at least 32 characters in production. Startup rejects the development placeholder.
- `ACCESS_TOKEN_MINUTES` controls token lifetime (5–1440 minutes; default 30).
- Login attempts are throttled to five per client IP per rolling minute in each API process. This is defense-in-depth for a single-instance lab; production multi-instance deployments also need shared rate limiting at the reverse proxy or API gateway.
- The dashboard keeps the bearer token in session storage for the current browser tab. Sign-out clears the current tab session; expired or rejected tokens return the interface to sign-in. Use HTTPS outside localhost and deploy a hardened reverse proxy, secure headers, secret management, backups, and monitoring before production.
- Wazuh ingestion is protected like other event ingestion endpoints. Use a dedicated least-privilege analyst account until service identities are implemented.

## Roadmap update

Phase 1.7 delivers local authentication, RBAC, trusted analyst identities, login throttling, and production secret guardrails. Distributed rate limiting, tamper-evident audit chaining, dedicated event-producer service identities, and full production deployment hardening remain future work.


## Phase 1.8 — analyst experience overhaul

The dashboard now has a redesigned responsive SOC workspace with a persistent operations sidebar, clearer security metrics, a searchable/filterable detection queue, an evidence-led investigation panel, and a normalized telemetry table. The visual system uses a restrained midnight palette, high-contrast typography, severity/status treatments, and responsive layouts for smaller screens.

Authentication and session handling are implemented as explicit UI states: sign-in validates the bearer token before revealing the workspace, API requests preserve the Authorization header when request options are merged, expired sessions return to sign-in, and both sign-out controls clear the tab session. Read-only users cannot see mutation controls. Administrators get a Team & Access view to create accounts and inspect provisioned users.

The CI workflow runs `node --check web/app.js` alongside PostgreSQL migrations and the Python API test suite. The dashboard uses the existing API contracts; no frontend framework or build tool is required.

Open the dashboard at http://localhost:8000/dashboard. After updating the branch, rebuild the API container so its static assets are refreshed:

```powershell
docker compose up --build -d
```


### Emergency local password rotation

If an administrator password was shared, pasted into a terminal recording, or otherwise exposed, rotate it immediately:

```powershell
docker compose exec api python -m scripts.reset_password
```

The command prompts for the account and the new password without echoing the password. Existing bearer tokens remain valid only until their configured expiry; sign out active browser tabs after rotation.


## Phase 1.9 — AegisSOC visual identity

The analyst workspace now uses a distinct graphite-and-signal-lime visual language rather than a stock teal dashboard treatment. Space Grotesk provides the display and interface typography; IBM Plex Mono is reserved for operational metadata, identifiers, timestamps, and compact labels. The layout emphasizes a stronger editorial page introduction, high-contrast KPI hierarchy, quieter grid texture, restrained square-corner surfaces, and clearer separation between detection work and investigation detail. Severity colors remain semantically distinct from the brand accent.

This is a visual-system milestone, not a claim that the analyst experience is complete. The next frontend increments should add richer time-series telemetry, event/alert drill-down, saved investigation context, pagination, and live update behavior against explicit API contracts. Verify the dashboard in a browser at desktop and mobile widths after rebuilding the container.
