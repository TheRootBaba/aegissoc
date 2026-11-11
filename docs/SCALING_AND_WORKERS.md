# Worker execution and scaling

Phase 1.29 separates outbound connector polling from API request handling and makes due work claimable by multiple PostgreSQL-backed worker replicas.

## Process boundaries

- `api`: authenticated HTTP APIs and dashboard.
- `scheduler`: recurring detection execution.
- `retention-worker`: bounded cleanup and retention work.
- `integration-worker`: outbound event, Wazuh, MISP and OpenCTI polling.
- `response-worker`: approved response webhook delivery and receiver reconciliation.

The integration worker uses persisted runtime state and leases. PostgreSQL workers claim due work with `FOR UPDATE SKIP LOCKED`; the lease expires if a process dies. Failures use bounded exponential backoff and persist exception classes, not potentially sensitive exception strings. Connector execution history is queryable for operational review.

## Capacity controls

A single poll is limited to a 15-second request timeout, a 5 MiB response, and 1,000 records. Scanner imports are limited to 500 assets and 5,000 findings. Sigma execution is limited to a bounded event sample and lookback window. These are deliberate admission limits; increase them only with measurements and load tests.

Run more than one integration worker only against PostgreSQL. SQLite is suitable for local development and isolated tests, not concurrent worker replicas. All workers enumerate active workspaces and set an explicit workspace context before processing tenant-owned records. PostgreSQL RLS is enforced with a separate `NOSUPERUSER NOBYPASSRLS` runtime role; worker code does not receive an RLS bypass. Workspace context is also applied to ORM operations so test environments can exercise query scoping, but SQLite is not a substitute for PostgreSQL RLS.

## Operations

Inspect `GET /api/v1/connectors/runtime-health`, connector execution history and worker logs. Alert on persistent connector failures, growing due-work lag, repeated partial ingestion and stale last-success timestamps. Keep API, scheduler and integration worker deployments on the same application revision and database migration level.

Before production rollout, define provider-specific rate limits, retry-after handling, pagination/cursors, network egress policy, secret rotation and recovery objectives. The generic JSON polling contract is a runtime foundation, not a substitute for vendor-specific integration certification.
