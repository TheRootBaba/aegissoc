# Integration runtime

This document describes the connector execution path introduced in Phase 1.24. The connector registry remains the administrative source of truth; a separate worker performs outbound polling so API request handling is not coupled to vendor latency.

## Supported execution modes

| Connector type | Direction | Runtime behavior |
|---|---|---|
| `http_poll` | Pull | Poll a JSON endpoint and normalize each record into a canonical security event |
| `threat_feed` | Pull | Poll a JSON feed and reconcile IP, domain and hash indicators |
| `http_event` | Push | Accept source-specific events through the authenticated ingestion API |
| `wazuh` | Push | Accept native Wazuh alert JSON through the Wazuh normalizer |
| `syslog` | Forwarded | Register transport metadata; a separate collector forwards events to the API |
| `generic` | Push | Accept canonical or normalizable JSON events |
| `response_webhook` | Outbound action | Deliver an approved response request to an explicitly allowlisted receiver |

The polling worker currently supports JSON arrays or an array located at `records_path` (default `items`). It does not claim to implement every vendor's pagination or proprietary API protocol. A vendor-specific adapter should be added when the vendor's authentication, cursor and rate-limit semantics are known.

## Register a polling connector

Administrator-only example:

```http
POST /api/v1/connectors
Authorization: Bearer <admin-token>
Content-Type: application/json
```

```json
{
  "connector_key": "edr-events",
  "connector_type": "http_poll",
  "display_name": "EDR event export",
  "credential_ref": "env://AEGIS_EDR_TOKEN",
  "config": {
    "endpoint": "https://edr.example.net/api/events",
    "allowed_hosts": ["edr.example.net"],
    "interval_seconds": 60,
    "records_path": "items",
    "auth_header": "Authorization"
  },
  "enabled": true
}
```

For a threat feed, use `connector_type: threat_feed`. Each record must include `type` (`ip`, `domain`, or `hash`) and `value`; optional fields include `confidence`, `severity`, `source`, `description`, `tags`, and `expires_at`.

The referenced secret is resolved only in the worker process from its environment. Supported references use `env://VARIABLE_NAME`; the raw secret is never stored in connector JSON or returned by the connector API. The optional `auth_header` is restricted to `Authorization` or `X-API-Key`. Authorization values are sent as Bearer tokens.

## Network and payload controls

- The hostname must exactly match an entry in `allowed_hosts`.
- HTTPS is required unless an administrator explicitly sets `allow_http: true`.
- Embedded URL credentials are rejected.
- Redirects are disabled; the worker will not follow a server-supplied redirect to another host.
- TLS certificate verification remains enabled.
- Connection and request timeouts are bounded.
- Responses are limited to 5 MiB and 1,000 records per poll.
- Credentials are resolved from the worker environment, never from connector configuration.
- Host allowlists are security policy. Restrict connector creation and changes to trusted administrators and use dedicated egress controls in production.

## Delivery and retries

Connector runtime state and execution history are persisted in PostgreSQL. The worker claims due connector states with a lease; PostgreSQL workers use `FOR UPDATE SKIP LOCKED` so multiple replicas do not normally claim the same due row. A crashed worker's lease expires and another worker can retry.

Failures record the exception class rather than exception text, then use bounded exponential backoff (60 seconds up to one hour). Event records use the existing unique `(source, external_id)` constraint, so polling the same export again does not create duplicate events when the producer supplies stable IDs. Threat feed records reconcile on indicator type and value.

Inspect connector history at `GET /api/v1/connectors/{connector_id}/executions` and runtime totals at `GET /api/v1/connectors/runtime-health`.

## Start the worker

Docker Compose includes an independent `integration-worker` service:

```powershell
docker compose up --build -d db api
docker compose exec api alembic upgrade head
docker compose up -d integration-worker
docker compose logs -f integration-worker
```

Add each referenced credential variable to the worker's environment (for a local Compose deployment, the project `.env` file is loaded by the worker service). Do not commit the file.

The worker is deliberately separate from the API. Do not start several SQLite-backed workers; multi-worker claiming relies on PostgreSQL row locks in production.
