# Runtime verification evidence

This directory contains a lab snapshot captured on 12 November 2026 at 00:35 UTC. The files are grouped by API, Docker, tests and capture notes. The capture metadata no longer includes the local Windows user path:

- [API liveness](lab-snapshot-2026-11-12-0035-utc/api/api-liveness.json) · [API readiness](lab-snapshot-2026-11-12-0035-utc/api/api-readiness.json) · [connector health](lab-snapshot-2026-11-12-0035-utc/api/connector-runtime-health.json) · [Wazuh poll history](lab-snapshot-2026-11-12-0035-utc/api/wazuh-indexer-poll-history.json) · [event totals](lab-snapshot-2026-11-12-0035-utc/api/event-statistics.json) · [alert totals](lab-snapshot-2026-11-12-0035-utc/api/alert-statistics.json).
- [AegisSOC services](lab-snapshot-2026-11-12-0035-utc/docker/aegissoc-services.txt) · [Wazuh services](lab-snapshot-2026-11-12-0035-utc/docker/wazuh-services.txt) · [Windows agent](lab-snapshot-2026-11-12-0035-utc/docker/windows-agent-service.txt) · [Docker version](lab-snapshot-2026-11-12-0035-utc/docker/docker-version.txt) · [Compose version](lab-snapshot-2026-11-12-0035-utc/docker/compose-version.txt).
- [pytest results](lab-snapshot-2026-11-12-0035-utc/tests/pytest-results.txt) · [pytest exit code](lab-snapshot-2026-11-12-0035-utc/tests/pytest-exit-code.txt) — local Python 3.12 test output.
- [Capture metadata](lab-snapshot-2026-11-12-0035-utc/notes/capture-metadata.txt) — timestamp and checkout type.

## Recorded results

- API liveness: `alive`.
- API readiness: `ready`, database connected.
- Connector runtime: 45 successful executions, one scheduled connector, zero leased connectors and zero connectors with failures.
- Event snapshot: 886 total events; 872 attributed to `wazuh-indexer-lab`.
- Alert snapshot: 4 total alerts (2 high, 2 medium).
- Local tests: 168 passed, 1 skipped, exit code 0.

This snapshot predates the dashboard state shared for the follow-up review. Its counts are historical and should not be compared with a later live dashboard session.

## Collection caveat

[The failed connector detail request](lab-snapshot-2026-11-12-0035-utc/api/connector-detail-request-405.txt) records a manual request that received HTTP 405. The connector execution history and worker health snapshots show successful polling; the 405 is a mismatch in the evidence-collection request, not a failed polling execution. Do not use the failed detail request alone to infer connector health.

## Evidence boundaries

This is a lab snapshot, not a continuous monitoring report or production certification. Event and alert totals are point-in-time values. Synthetic test events must remain distinguished from genuine endpoint telemetry. Local pytest output does not replace the PostgreSQL migration/RLS GitHub Actions workflow on the pull request. Review screenshots and logs for sensitive values before sharing outside the project.
