# Runtime verification evidence

This directory contains a timestamped snapshot from the local Windows lab on 2026-11-12. It is organized by evidence type:

- [API](run-20261112-003500/api/) — liveness/readiness, connector runtime health and execution history, event and alert statistics.
- [Docker](run-20261112-003500/docker/) — AegisSOC services, Wazuh services, Windows Wazuh agent service, Docker and Compose versions.
- [Tests](run-20261112-003500/tests/) — local Python 3.12 pytest output and process exit code.
- [Run metadata](run-20261112-003500/notes/run-info.txt) — capture timestamp and local project path.

## Recorded results

- API liveness: `alive`.
- API readiness: `ready`, database connected.
- Connector runtime: 45 successful executions, one scheduled connector, zero leased connectors and zero connectors with failures.
- Event snapshot: 886 total events; 872 attributed to `wazuh-indexer-lab`.
- Alert snapshot: 4 total alerts (2 high, 2 medium).
- Local tests: 168 passed, 1 skipped, exit code 0.

## Collection caveat

`api/04-wazuh-connector-error.txt` preserves a failed manual detail request that received HTTP 405. The connector execution history and worker health snapshots show successful polling; the 405 is a mismatch in the evidence-collection request, not a failed polling execution. Do not use the failed detail request alone to infer connector health.

## Evidence boundaries

This is a lab snapshot, not a continuous monitoring report or production certification. Event and alert totals are point-in-time values. Synthetic test events must remain distinguished from genuine endpoint telemetry. Local pytest output does not replace the PostgreSQL migration/RLS GitHub Actions workflow on the pull request. Review screenshots and logs for sensitive values before sharing outside the project.
