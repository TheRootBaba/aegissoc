# AegisSOC Architecture

These diagrams describe the intended logical flow in the repository. They are source diagrams, not screenshots of a running deployment. Deployment-specific topology, provider endpoints, secrets and trust boundaries must be confirmed against the target environment.

## Platform components

```mermaid
flowchart LR
  subgraph Sources
    W[Wazuh]
    S[Nessus / Tenable / Qualys]
    T[MISP / OpenCTI]
    E[HTTP event sources]
  end
  subgraph AegisSOC
    C[Connector workers]
    I[Normalize and deduplicate]
    DB[(PostgreSQL)]
    SIG[Sigma and scheduled detections]
    CASE[Alerts / investigations / cases]
    RESP[Approval-gated response worker]
    AUD[Audit chain]
    UI[Analyst dashboard and API]
  end
  W --> C
  S --> C
  T --> C
  E --> C
  C --> I --> DB
  DB --> SIG --> CASE
  DB --> UI
  CASE --> RESP
  RESP --> AUD
  C --> AUD
  SIG --> AUD
  UI --> AUD
```

## Ingestion and detection lifecycle

```mermaid
sequenceDiagram
  participant Provider
  participant Worker
  participant Normalize
  participant Store as PostgreSQL
  participant Sigma
  participant Analyst
  Provider->>Worker: Fetch / export page
  Worker->>Worker: Validate TLS, host allowlist and credential reference
  Worker->>Normalize: Provider payload
  Normalize->>Store: Upsert normalized assets/events/findings
  Store-->>Worker: Persisted cursor and dedupe outcome
  Store->>Sigma: Eligible event window
  Sigma->>Store: Rule and correlation alerts with evidence IDs
  Analyst->>Store: Review alert, timeline and case
```

## Response lifecycle

```mermaid
stateDiagram-v2
  [*] --> Pending
  Pending --> Approved: independent approver
  Pending --> Rejected: deny
  Pending --> Cancelled: cancel
  Pending --> Expired: expiry
  Approved --> Queued: execute request
  Queued --> Succeeded: receiver confirms
  Queued --> RetryScheduled: transient failure
  RetryScheduled --> Queued: due retry / same idempotency key
  Queued --> Reconciliation: ambiguous receiver result
  Reconciliation --> Succeeded: receiver reference confirmed
  Reconciliation --> Failed: reconciliation rejected
  Succeeded --> [*]
  Rejected --> [*]
  Cancelled --> [*]
  Expired --> [*]
  Failed --> [*]
```

## Deployment and recovery boundary

```mermaid
flowchart TB
  LB[Ingress / TLS termination] --> API[API and dashboard]
  API --> DB[(PostgreSQL primary)]
  API --> SEC[External secret manager]
  WORK[Connector and response workers] --> DB
  WORK --> SEC
  DB --> BACKUP[Encrypted backup repository]
  BACKUP --> RESTORE[Isolated restore environment]
  RESTORE --> DRILL[Restore validation and RPO/RTO evidence]
  MON[Metrics, logs and alerting] --- API
  MON --- WORK
  MON --- DB
```

## Required deployment-specific validation

- Confirm network zones, ingress policy, egress allowlists, database access paths and secret-manager integration.
- Confirm backup encryption, retention, restore permissions and recovery-point/recovery-time objectives.
- Confirm HA/failover behavior and worker lease/retry behavior under node loss.
- Attach a redacted deployment diagram and evidence from the actual target environment before calling the system production-ready.
