# AegisSOC — Phase 1

A local-first Security Operations Center platform foundation.

## Phase 1 scope
- FastAPI backend
- PostgreSQL event store
- Normalized security event schema
- Event ingestion and retrieval API
- Health/readiness endpoints
- Automated API tests

This is a development foundation, not a production SIEM. Authentication, authorization,
rate limiting, durable migrations, endpoint agents, detection rules and Wazuh integration
are intentionally scheduled for later phases.

## Architecture

```text
Security event producers (later: Wazuh / Syslog / Windows agents)
                         |
                         v
                FastAPI ingestion API
                         |
                 Pydantic validation
                         |
                         v
                  PostgreSQL
                         |
              Query API / analyst UI (later)
```

## Requirements
- Windows 10/11 with virtualization enabled
- WSL2 + Ubuntu
- Docker Desktop configured to use the WSL2 backend
- Git
- 8 GB free disk space recommended

## Run with Docker (recommended)

1. Copy `.env.example` to `.env`.
2. From this directory, run:

   ```powershell
   Copy-Item .env.example .env
   docker compose up --build -d
   docker compose ps
   ```

3. Open:
   - API docs: http://localhost:8000/docs
   - Liveness: http://localhost:8000/health/live
   - Readiness: http://localhost:8000/health/ready

4. Stop:

   ```powershell
   docker compose down
   ```

5. Stop and delete the local database volume (destructive):

   ```powershell
   docker compose down -v
   ```

## Run locally without Docker

Use Python 3.11 or 3.12. PostgreSQL must be running and accessible.

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
Copy-Item .env.example .env
uvicorn app.main:app --reload
```

Update `DATABASE_URL` in `.env` to point to your local PostgreSQL instance.

## API examples

### Ingest an event

```powershell
$body = @{
  source = "lab-manual"
  event_type = "authentication.failure"
  severity = "medium"
  timestamp = (Get-Date).ToUniversalTime().ToString("o")
  hostname = "ubuntu-lab"
  source_ip = "192.0.2.25"
  username = "analyst"
  message = "Three failed SSH login attempts observed in the isolated lab."
  raw = @{
    lab = $true
    scenario = "simulated-ssh-failures"
    attempt_count = 3
  }
} | ConvertTo-Json -Depth 5

Invoke-RestMethod -Method Post `
  -Uri http://localhost:8000/api/v1/events `
  -ContentType "application/json" `
  -Body $body
```

### List events

```powershell
Invoke-RestMethod http://localhost:8000/api/v1/events
```

### Filter by severity

```powershell
Invoke-RestMethod "http://localhost:8000/api/v1/events?severity=medium"
```

## Run tests locally

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
pytest -q
```

Tests use an isolated SQLite database and do not need a running PostgreSQL server.

## Repository layout

```text
aegissoc/
├── app/
│   ├── api/routes/
│   ├── core/
│   ├── db/
│   ├── schemas/
│   ├── services/
│   └── main.py
├── tests/
├── .env.example
├── .gitignore
├── compose.yaml
├── Dockerfile
└── requirements.txt
```

## Safety
Only ingest logs and events from systems you own or are explicitly authorized to monitor.
Use synthetic events for initial testing. Do not upload secrets, credentials, personal data,
or unredacted production logs to a public repository.

## Next milestones
- Phase 1.1: configuration hardening, pagination, request IDs and structured logging
- Phase 2: normalization pipeline and rule-based detections
- Phase 3: Wazuh integration in a resource-conscious lab
