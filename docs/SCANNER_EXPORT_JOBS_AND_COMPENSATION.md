# Scanner export-job connectors

Nessus, Tenable.io, and Qualys VMDR connectors run through the leased connector worker.
They use the existing `ConnectorRuntimeState.cursor` for the export job ID and stage, and
the existing `ConnectorExecution` rows for durable execution history. No vendor secret
belongs in `config`; set `credential_ref` to a configured secret-store reference.

## Connector configuration

All providers require:
- `endpoint`: HTTPS API base URL.
- `allowed_hosts`: exact host allowlist containing the endpoint host.
- `credential_ref`: external secret reference on the connector record.
- `scan_id`: vendor scan/report identifier.
- `start_path`, `status_path`, and `download_path`: absolute API paths beginning with
  one slash. Paths may interpolate `{scan_id}`, `{job_id}`, and `{file_id}`.
- `interval_seconds`: 60–86400 seconds (default 300).
- Optional `start_method` (default POST) and `start_payload`.

The provider credential formats are:
- Nessus: `access_key:secret_key`, sent as `X-ApiKeys`.
- Tenable.io: `access_key:secret_key`, sent as `X-ApiKeys`.
- Qualys: `username:password`, sent as HTTP Basic authentication.

The secret resolver must return the provider's credential string. TLS verification is
enabled, redirects are disabled, API responses are bounded to 5 MiB, and only exact
allowlisted hosts are accepted. HTTP 429/503 responses use the bounded numeric
`Retry-After` delay (maximum one hour); other failures use the worker's exponential retry.

The configured status response must include a supported `status` value: queued, pending,
running, processing, in_progress, completed, complete, finished, ready, failed, error,
cancelled, or canceled. Nessus/Tenable may also return a `file` identifier. The export
download must be JSON accepted by the existing provider normalizer (top-level
`scan_id`/info, and `assets` or `hosts` with host identity and findings). CSV exports
must be converted by the vendor API/configuration before download; this worker does not
guess or parse vendor-specific CSV schemas.

Each scan is deduplicated by workspace, provider, and scan ID. Findings are matched only
to assets already present in that workspace. Unmatched assets are counted as rejected
findings, not silently created.

## Receiver compensation

A response receiver must explicitly configure:
- `capabilities.compensation: true`
- `compensation_endpoint` on an allowlisted HTTPS host
- a receiver-issued `X-Aegis-Action-Reference` on successful original delivery

An administrator can then request compensation. A deterministic idempotency key derived
from the original action key is sent with the original reference and action details.
A receiver response must echo `original_idempotency_key` and report `compensated`,
`pending`, or `rejected`. Compensation is never inferred from an action type, and
a request without a receiver reference is rejected.

The existing action worker also reconciles ambiguous deliveries through the configured
`reconciliation_endpoint` before retrying, using the original idempotency key. This is
important because a network timeout does not prove that a receiver failed to execute an
action.
