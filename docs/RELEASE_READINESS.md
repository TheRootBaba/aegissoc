# AegisSOC release readiness

This document is the release gate for the next public AegisSOC release. It deliberately distinguishes merged implementation from independently verified deployment evidence.

## Current baseline

- Phases 1.35–1.37 are present in the merged implementation (PR #31).
- The PR #31 GitHub Actions run is not green: 162 passed, 6 failed, 1 skipped.
- PostgreSQL migrations, migration revision verification, least-privilege runtime-role provisioning, PostgreSQL RLS checks, and dashboard JavaScript syntax passed in that run.
- A passing historical run is not a substitute for a fresh run against the release candidate.

## Blocking test failures recorded for PR #31

| Test | Recorded failure | Required closure |
|---|---|---|
| `tests/test_api.py::test_admin_can_create_user_and_user_can_login` | User creation/login returned HTTP 403 instead of 200 | Trace admin authorization and workspace membership setup; preserve least privilege and add regression coverage |
| `tests/test_api.py::test_scheduler_worker_executes_due_schedule_and_persists_result` | Expected 5 executions, got 10 | Check scheduler batch/claim semantics and prevent duplicate processing |
| `tests/test_dashboard_assets.py::test_dashboard_has_role_aware_team_and_source_management` | Expected role-guard string absent from current dashboard bundle | Test observable role-based behavior rather than a brittle source substring; retain admin/non-admin coverage |
| `tests/test_platform_expansion.py::test_sigma_api_import_test_and_enable` | Composite primary key lookup supplied an incomplete identifier | Use both workspace ID and rule ID in lookup and add tenant-scoped regression |
| `tests/test_platform_expansion.py::test_sigma_event_count_correlation_creates_grouped_evidence_alert` | Expected one alert, got zero | Trace fixture event fields, rule matching, correlation grouping and evidence creation |
| `tests/test_platform_expansion.py::test_response_worker_retries_transient_receiver_failure_with_stable_idempotency` | Naive/aware datetime comparison raised TypeError | Normalize persisted timestamps at the boundary and test SQLite and PostgreSQL behavior |

Do not mark this section complete until each test passes and the full workflow succeeds on the candidate commit.

## Phase 1.35–1.37 verification still required

### Scanner export jobs

- Contract tests for Nessus, Tenable and Qualys authentication, start, poll, download, throttling, malformed payload and provider failure responses.
- Verify durable cursor recovery after worker restart.
- Verify duplicate scan imports are idempotent.
- Verify unknown assets are rejected and workspace boundaries are enforced.
- Validate configured provider API paths and JSON payload formats against supported provider versions.
- Record a successful test-environment integration run for each provider before claiming provider certification. CSV exports are not supported unless a dedicated parser is implemented and tested.

### Sigma detection

- Positive and negative fixtures for every shipped rule.
- Parser and unique-ID validation for the complete rule pack.
- API import, test, enable, schedule and alert-evidence integration coverage.
- Document supported Sigma syntax and explicitly list unsupported modifiers, pipelines and correlation types.

### Response orchestration

- Approval, expiry, cancellation, dry-run, successful delivery and receiver rejection.
- Stable idempotency under timeout, retry and worker restart.
- Receiver reconciliation for succeeded, pending, failed and not-found states.
- Compensation capability, reference validation, allowlist enforcement and idempotent compensation.
- Demonstrate only against a local or dedicated test receiver; never trigger destructive production actions in a portfolio demo.

## Release gates

### Engineering and CI

- [ ] All six recorded failures fixed with focused regression tests.
- [ ] Full API, service, worker, database and dashboard test suites pass.
- [ ] PostgreSQL migrations apply from an empty database and from the previous supported release.
- [ ] RLS and cross-workspace isolation tests pass under the non-owner runtime role.
- [ ] Lint, type checks, dependency checks and dashboard build/syntax checks pass where configured.
- [ ] Fresh CI run on the exact release-candidate commit is successful.

### Security and operations

- [ ] Threat model reviewed and findings tracked to closure.
- [ ] Independent security assessment / penetration test completed.
- [ ] Dependency and container image vulnerability review completed.
- [ ] SBOM generated and release artifacts signed.
- [ ] Secret and signing-key rotation exercised.
- [ ] Backup restore and disaster recovery drill recorded.
- [ ] Load, concurrency and soak tests completed against stated targets.
- [ ] Monitoring, alerting, retention, incident response and rollback runbooks reviewed.

### Deployment and compatibility

- [ ] Clean installation guide verified by a reviewer.
- [ ] Upgrade and rollback tested from the supported previous version.
- [ ] Production configuration uses PostgreSQL and a least-privilege runtime role.
- [ ] SSO and each supported external provider tested in a representative environment.
- [ ] Supported versions, network requirements, permissions and known limitations published.

## Documentation and evidence inventory

The existing screenshot gallery contains genuine dashboard captures for the overview, alert queue, cases, investigation workbench, detection rules and schedules, entity correlation, threat intelligence, integrations, asset risk, response playbook, audit trail, team access, and operations/retention.

Add or refresh the following captures from the release candidate using synthetic data only:

| Asset | Evidence to capture |
|---|---|
| `overview.png` | Populated workspace overview and service health |
| `source-health.png` | Source inventory, freshness and ingestion outcomes |
| `event-detail.png` | Normalized event and raw evidence view |
| `alert-evidence.png` | Alert with linked event IDs and detection explanation |
| `case-timeline.png` | Case lifecycle, notes, assignments and linked alerts |
| `scanner-export-job.png` | Scanner job start, polling and completion |
| `scanner-findings.png` | Imported assets and vulnerability findings |
| `sigma-validation.png` | Rule validation and enabled state |
| `sigma-alert.png` | Detection result and evidence linkage |
| `response-approval.png` | Approval and dry-run workflow |
| `response-reconciliation.png` | Test receiver idempotency and reconciliation result |
| `workspace-access.png` | Membership and role permissions |
| `audit-verification.png` | Audit trail and verification result |
| `operations-health.png` | Worker status, retention and operational health |

Keep captures unaltered as product evidence. Redact sensitive information at the source by using a dedicated synthetic workspace. Do not add generated dashboard mockups as if they were application screenshots.

## Demo recordings

Capture from the exact release candidate:

1. Product overview (2–3 minutes).
2. Synthetic event → detection → alert → case investigation (3–5 minutes).
3. Threat-intelligence enrichment (2–3 minutes).
4. Scanner export and vulnerability import (2–4 minutes).
5. Sigma rule validation and alert generation (2–3 minutes).
6. Approval → safe test receiver → idempotency/reconciliation (3–5 minutes).
7. Workspace isolation and access governance (2–3 minutes).
8. Operations, health and recovery walkthrough (2–4 minutes).

Use Git LFS or GitHub release assets for large recordings. Keep a README beside the recordings with application commit, environment, scenario, capture date and any limitations.

## Final publication package

- [ ] README describes supported capabilities without overstating provider certification or Sigma compatibility.
- [ ] Architecture, data-flow, trust-boundary, deployment and recovery diagrams are current.
- [ ] Getting-started, configuration, integrations, API, operations, security and upgrade guides are complete.
- [ ] Screenshot gallery links only to files that exist in the release.
- [ ] Demo index links to recordings and states their tested application revision.
- [ ] Changelog and release notes identify breaking changes and known limitations.
- [ ] License, SECURITY.md, CONTRIBUTING.md and support policy are present and consistent.
- [ ] Version tag, signed release artifacts, checksums and SBOM are published.

## Status vocabulary

Use only these meanings in release notes:

- **Implemented:** code exists in the repository.
- **Automated-tested:** relevant tests pass in CI.
- **Integration-verified:** exercised against a representative external service or receiver.
- **Operationally-validated:** load, restore, rotation and deployment exercises have evidence.
- **Release-ready:** all mandatory release gates above are closed for the specific release candidate.

A merged pull request alone does not imply integration-verified, operationally-validated or release-ready.
