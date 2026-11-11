# AegisSOC integration framework

The integration registry binds a stable producer key to a validated adapter contract. Registered producers use the same authenticated event-ingestion APIs and canonical event model as existing sources.

## Supported adapter contracts

| Adapter | Required configuration | Normalization |
|---|---|---|
| `wazuh` | `manager_url` (HTTP(S), no embedded credentials) and an external `credential_ref` | Existing native Wazuh alert normalizer |
| `syslog` | `host`, optional `port` (default 514), optional `transport` (`udp`, `tcp`, or `tls`) | Canonical event normalizer |
| `http_event` | Optional application-relative `ingest_path` | Canonical event normalizer |
| `generic` | No required fields | Canonical event normalizer |

These are adapter contracts, not claims that AegisSOC runs a UDP/TCP syslog listener or polls remote vendor APIs. Syslog collectors and other producers must forward events to the authenticated ingestion API. Native transport listeners and vendor-specific credential resolvers remain separate integration work.

## Register a connector

Administrator-only example:

```http
POST /api/v1/connectors
Authorization: Bearer <admin-token>
Content-Type: application/json
```

```json
{
  "connector_key": "syslog-prod",
  "connector_type": "syslog",
  "display_name": "Production Syslog",
  "config": {
    "host": "syslog-collector.internal",
    "port": 6514,
    "transport": "tls"
  },
  "credential_ref": "vault://security/syslog-prod",
  "enabled": true
}
```

Use `GET /api/v1/connectors` to inventory connectors. `PATCH /api/v1/connectors/{id}` updates display name, adapter config, external credential reference, or enabled state. `DELETE` removes only the connector configuration; it does not remove ingested events.

## Ingest through an adapter

Use the connector key as the source path. The API validates the registered adapter, normalizes the payload, persists the event idempotently, and updates the connector's last-observed timestamp.

```http
POST /api/v1/events/ingest/syslog-prod
Authorization: Bearer <analyst-token>
Content-Type: application/json
```

```json
{
  "@timestamp": "2026-11-11T12:00:00Z",
  "event": {
    "action": "process.started",
    "severity": "info"
  },
  "host": {
    "name": "linux-edge-01"
  },
  "message": "sshd process started"
}
```

The existing bulk endpoint can be used for bounded batch ingestion at `POST /api/v1/events/ingest/{connector_key}/bulk`.

## Credential boundary

Connector configuration is metadata, not a secret store. Secret-like fields are rejected recursively in the `config` object. Store only a reference such as `vault://...` in `credential_ref`; the application does not resolve that reference in this phase and never accepts a raw token/password as a substitute.

## Health semantics

- `unverified`: configuration exists but no successful event has been observed.
- `observed`: at least one accepted or duplicate ingestion has been processed for this connector key.
- `misconfigured`: adapter configuration validation failed.
- `disabled`: connector ingestion is administratively disabled.

The administrator `POST /api/v1/connectors/{id}/check` action validates local configuration only. It does not open a network connection, test remote credentials, or assert that a vendor service is online.
