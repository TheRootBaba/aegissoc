# Platform completion: phases 1.30b–1.34

This document records the scope delivered by the platform-completion branch and distinguishes implemented controls from work that still requires provider certification or production deployment evidence.

## 1.30b — Workspace and tenant isolation

- Adds workspaces and active workspace memberships; existing users and records are backfilled into a default workspace.
- Requires membership resolution for authenticated API requests. Multi-workspace users select a workspace with `X-Workspace-ID`.
- Applies workspace scoping to ORM reads, updates and deletes, assigns workspace ownership to new ORM records, and rejects tenant-owned writes without a workspace context on PostgreSQL.
- Adds PostgreSQL `ENABLE ROW LEVEL SECURITY` and `FORCE ROW LEVEL SECURITY` policies for tenant-owned tables. The API and workers use a separate `NOSUPERUSER NOBYPASSRLS` runtime role.
- Adds database triggers to reject cross-workspace references for case/alert links, notes, schedule executions, asset findings, connector state and response records.
- Updates scheduler, retention, integration and response workers to enumerate active workspaces and process each workspace under an explicit context.

PostgreSQL is the enforcement boundary. SQLite remains useful for isolated tests, but it does not provide RLS and must not be used to validate production tenant isolation.

## 1.31 — Provider adapters

- Wazuh Manager: HTTPS API authentication using a referenced `username:password` secret, token exchange, and configurable event polling.
- Wazuh Indexer: HTTPS alert search with Basic Auth, bounded page sizes and persisted search-after cursor.
- MISP: HTTPS REST attribute polling, API-key header authentication, pagination and attribute normalization.
- OpenCTI: HTTPS GraphQL indicator polling, token authentication, cursor pagination and STIX-pattern normalization.
- Nessus, Tenable and Qualys: provider-specific export normalization into the scanner import contract. Findings only attach to assets already registered in the selected workspace; unknown assets are rejected rather than silently created.

The scanner adapters normalize exported data; this branch does not claim a live authenticated scan-export polling client for every Nessus, Tenable or Qualys deployment. Provider API versions, rate limits and tenant-specific schemas still need validation against customer instances.

## 1.32 — Sigma and correlation

- Validates YAML input and a deliberately bounded Sigma subset before persistence.
- Supports selector matching, field mappings, condition expressions, wildcard selection and safe string matching.
- Adds bounded `event_count` correlation with rule references, group-by fields, a 1-minute to 7-day window and threshold checks.
- Produces deduplicated alerts with event evidence, and runs enabled Sigma rules from the scheduled detection worker.

This is not full Sigma specification compatibility. Unsupported modifiers, pipelines, backend-specific field semantics and correlation types must be rejected or implemented explicitly rather than guessed.

## 1.33 — Response execution

- Separates approval from execution and requires an enabled, allowlisted response webhook.
- Uses durable claims, PostgreSQL `SKIP LOCKED`, leases, a bounded attempt count, exponential retry and a stable idempotency key.
- Streams receiver responses without buffering arbitrary response bodies, records response metadata and writes audit entries for attempts and terminal outcomes.
- Adds a dedicated response worker that processes each workspace independently.

Recovery first queries an optional, same-allowlist HTTPS reconciliation endpoint using the stable idempotency key. A receiver reports a matching key and one of `succeeded`, `pending`, `failed` or `not_found`; confirmed completion prevents duplicate delivery, pending actions are deferred, and not-found actions may be retried with the original key. Reconciliation responses are bounded to 64 KiB. Receivers must implement this contract and idempotent POST handling before automated actions are enabled.

## 1.34 — SSO, secrets and production controls

- Adds optional OIDC login with administrator-provisioned issuer/subject mappings; automatic account creation is intentionally disabled.
- Supports `env://NAME` and restricted `file:///run/secrets/NAME` references for connector and OIDC credentials.
- Runs migrations with the migration-owner connection, provisions a separate runtime database role, and starts the API with that non-owner role.
- Rejects production configuration that uses SQLite or the migration-owner database role, and requires a unique signing secret.
- Adds PostgreSQL RLS integration coverage, runtime-role checks, provider fixtures and security regression tests to CI.

The application has stronger production controls, but production readiness is not a certification. Before exposing it to customer telemetry, complete a threat model, independent penetration test, load/soak testing, backup restore drill, secret rotation exercise, and deployment-specific SSO and provider validation.

## Remaining roadmap to a production-grade SOC platform

1. **1.35 — Live scanner integrations:** authenticated Nessus/Tenable/Qualys export jobs, cursor persistence, rate-limit handling and provider-version contract tests.
2. **1.36 — Detection coverage:** broader Sigma compatibility, rule packs, validation/linting, regression fixtures, and richer multi-event correlation.
3. **1.37 — Response orchestration:** receiver-specific adapters and status reconciliation, approval expiry, cancellation, rollback/compensation and action simulation.
4. **1.38 — Enterprise identity and governance:** SAML/SCIM, group-to-role mapping, MFA policy integration, workspace lifecycle, quotas and delegated administration.
5. **1.39 — Production operations:** cloud secrets-manager adapters, key rotation, HA deployment, capacity/load tests, disaster recovery objectives and compliance evidence.
6. **1.40 — Analyst experience:** final dashboard information architecture and visual refinement, investigation timelines, saved workflows and accessibility review.
7. **1.41 — Release assurance:** independent security review, threat model closure, software supply-chain controls, signed releases and customer deployment guides.

AegisSOC should be called production-ready only after the operational and assurance evidence above exists for the actual deployment environment.
