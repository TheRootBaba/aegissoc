# AegisSOC platform architecture

## Purpose and operating model

AegisSOC is a local-first security operations platform. It receives telemetry from configured producers, converts source-specific records into a canonical event model, evaluates deterministic detections, preserves evidence, and gives analysts a controlled workflow for investigations and response.

The API and dashboard are not the integration runtime. Outbound polling and recurring work execute in separate worker processes. This separation keeps vendor latency, transient network failures and retry behavior out of analyst-facing request paths.

## Runtime topology

```text
                  +-----------------------+
                  | Analyst browser       |
                  | Dashboard / API docs  |
                  +-----------+-----------+
                              |
                              v
                  +-----------------------+
                  | FastAPI application   |
                  | Auth / RBAC / APIs    |
                  +-----------+-----------+
                              |
             +----------------+-----------------+
             |                |                 |
             v                v                 v
      Event ingestion    Investigation     Governance APIs
      normalization      and detection     cases / Sigma /
      idempotency         queries           response approvals
             |                |                 |
             +----------------+-----------------+
                              |
                              v
                  +-----------------------+
                  | PostgreSQL            |
                  | events / alerts /     |
                  | cases / IOCs / assets |
                  | connector state /     |
                  | audit chain           |
                  +-----------+-----------+
                              ^
             +----------------+----------------+
             |                |                |
             v                v                v
       Detection         Retention        Integration
       scheduler         worker           worker
       recurring rules   cleanup/backup   HTTP poll/feed
```

The Compose deployment keeps the API, detection scheduler, retention worker and integration worker as separate services. They share the PostgreSQL database and application revision. The API container applies Alembic migrations before serving traffic; workers wait for the API readiness check in the Compose configuration.

## Event path

1. A producer authenticates and submits source-specific JSON to the ingestion endpoint or the integration worker retrieves a configured JSON export.
2. The source adapter validates its connector configuration and maps known fields into the canonical event schema.
3. The original payload is retained in `raw` for later investigation.
4. PostgreSQL enforces uniqueness on `(source, external_id)`. A replay returns the original event instead of creating a second record.
5. Source inventory counters record accepted, duplicate and rejected outcomes.
6. Detection rules evaluate persisted events and create alerts with stable fingerprints and evidence event IDs.
7. Analysts pivot from events to alerts, entities, cases, assets and threat indicators. Case and governance mutations are appended to the audit chain.

An event without a stable producer ID can still be ingested, but the source/external-ID uniqueness constraint cannot deduplicate it.

## Integration runtime

The connector registry stores adapter type, endpoint metadata, enablement, health and an external credential reference. The integration worker reads due connector states, claims a lease, performs a bounded request, records an execution result and schedules the next attempt.

The current pull contract accepts JSON arrays or arrays located at a configured dotted path. Event connectors feed canonical ingestion; threat-feed connectors reconcile IP, domain and hash indicators. The runtime does not claim universal vendor API support. Pagination, provider-specific cursor semantics and provider rate-limit handling belong in dedicated adapters.

Credential values are not stored in connector JSON. The runtime supports `env://VARIABLE_NAME` references and resolves them from the process environment. HTTPS is the default. Administrators must provide an exact hostname allowlist; redirects are disabled, TLS verification is enabled, and request duration, response size and batch size are bounded.

## Vulnerability and asset path

Asset records are curated inventory, not discovered hosts. Scanner imports must map each scanner record to an existing stable asset key. Findings are deduplicated by asset and vulnerability identifier. A scanner/scan ID ledger makes retried imports idempotent.

The scanner-neutral import API does not run a scan or independently validate the scanner's severity, CVSS score or exploitability assessment. The source scanner remains responsible for those determinations.

## Threat intelligence path

Threat-feed records are normalized to IP, domain or hash indicators. Type/value uniqueness prevents duplicate registry entries. Feed synchronization retains provenance and expiry, while analyst revocation remains authoritative. Matching is local: AegisSOC does not submit customer telemetry to public reputation services.

## Detection path

The built-in detection engine and the Sigma subset both produce the same evidence-linked alert model. Sigma YAML is parsed with safe loading. The current evaluator supports selector maps, AND/OR conditions, scalar/list values, wildcard matching and three string modifiers. Unsupported Sigma condition syntax is rejected at import. The implementation is not a complete Sigma compiler.

Rules are imported disabled, tested against representative events and enabled by an administrator. Execution is bounded by a time window, event sample and enabled-rule cap. Alert fingerprints are deterministic per rule/event pair.

## Response control path

Response actions are requests, not direct host-control operations. An analyst creates a pending action, a different administrator approves or rejects it, and an administrator separately invokes execution. The approved request is delivered to a registered response webhook using a stable idempotency key and optional HMAC signature.

The receiver is responsible for authenticating the signature, enforcing idempotency, validating the target and performing the downstream action. AegisSOC does not execute shell commands or directly isolate endpoints. Interrupted executions require reconciliation with the receiver before any manual retry.

## Persistence and audit

Alembic owns schema evolution. The current migration chain ends at `0014_runtime_sigma_response`. Operational execution records are stored separately from event and alert evidence. Audit entries record actor, action, resource and bounded metadata; secrets and webhook response bodies are not copied into audit details.

The audit chain is tamper-evident within the database trust boundary. Production deployments should export signed or immutable audit evidence to an independently controlled system.

## Failure and recovery model

- Connector failures persist an exception class, advance bounded exponential backoff and leave a retryable due state.
- A lease prevents ordinary concurrent claims; PostgreSQL `SKIP LOCKED` supports multiple integration worker replicas.
- An expired lease allows a later worker to mark an abandoned in-flight execution and retry.
- Event replay is safe when producer IDs are stable.
- Scanner scan IDs prevent a retried scan from applying twice.
- Response webhook delivery is one-shot inside AegisSOC; the receiver must enforce the supplied idempotency key.
- Database backup and restore procedures remain in the operations runbook.

## Security boundaries

- Authentication and role checks protect administrative configuration and mutation APIs.
- Only administrators can register or change connector configuration.
- Outbound HTTP destinations require exact host allowlists.
- Raw secrets are rejected from connector config and resolved from environment references.
- Response execution requires a separate approval and explicit execution call.
- Feed content and scanner findings are treated as external observations, not trusted instructions.
- API and worker logs store error classes rather than raw exception messages where those messages may contain credentials or endpoint details.

## Deployment and verification

Use the root README for local setup and the following operational documents for configuration and recovery:

- [Integration runtime](INTEGRATION_RUNTIME.md)
- [Vulnerability imports](VULNERABILITY_IMPORTS.md)
- [Threat-feed synchronization](THREAT_FEED_SYNC.md)
- [Sigma detection engineering](SIGMA_DETECTION.md)
- [Response action governance](RESPONSE_GOVERNANCE.md)
- [Worker scaling](SCALING_AND_WORKERS.md)
- [Operations and recovery](OPERATIONS_RUNBOOK.md)

The automated CI workflow applies migrations against PostgreSQL, verifies the Alembic head, validates dashboard JavaScript syntax and runs the API test suite.

## Explicit non-goals of this release

This release does not provide full Sigma specification support, universal vendor connectors, native Syslog listeners, scanner execution, automatic public-reputation lookups, direct endpoint isolation, full tenant/workspace isolation, or a production multi-region deployment. Those require separate design and validation rather than being implied by the existence of a generic API.
