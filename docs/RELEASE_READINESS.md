# AegisSOC release readiness

Use this checklist before publishing a release. Code being merged does not mean the deployment has been tested.

## Current baseline

- PR #34 is merged into `main` at `3e7c70456e9db9de27543d42917b92f1a89d0291`.
- Its GitHub Actions run passed on the merged implementation candidate: 170 passed, 1 skipped. PostgreSQL migrations, runtime-role setup, RLS tests, dashboard JavaScript syntax and both Compose configurations passed.
- The six failures recorded during PR #31 are historical. The corresponding tests passed in the PR #34 full-suite run.
- The local lab snapshot was captured at 00:35 UTC on 12 November 2026. It predates the dashboard state reported later that morning and is not a current health report.
- The dashboard health changes for source timestamps, connector status, active-alert counts and overdue schedules are now in `main`. The CI run for that implementation passed with 174 passed and 1 skipped.\n- On 12 November 2026, the local Wazuh Compose override built and started. The API reported `alive` and `ready`, and the Docker network showed the Wazuh Indexer, Manager and Dashboard attached. This verifies container startup only. The dashboard still showed the Indexer source as inactive with no last-event timestamp, so end-to-end ingestion freshness remains unverified.\n- The current release pass adds recovery of missing source timestamps from existing stored telemetry. It does not treat a successful empty poll as proof that new events arrived.
- A passing CI run verifies the tested code. It does not replace a clean installation, refreshed product screenshots or external-provider testing.

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

- [x] All six recorded failures fixed with focused regression tests; the current full test suite passes.
- [x] Full API, service, worker, database and dashboard test suites pass.
- [ ] PostgreSQL migrations apply from an empty database and from the previous supported release.
- [x] RLS and cross-workspace isolation tests pass under the non-owner runtime role.
- [ ] Lint, type checks, dependency checks and dashboard build/syntax checks pass where configured.
- [x] PR #34 implementation candidate passed CI (170 passed, 1 skipped).
- [x] Dashboard health follow-up implementation passes CI (174 passed, 1 skipped).
- [x] Final documentation and dashboard follow-up head passes CI (174 passed, 1 skipped).

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

The [organized screenshot gallery](SCREENSHOT_GALLERY.md) contains genuine historical dashboard captures for the overview, alert queue, cases, investigation workbench, detection rules and schedules, entity correlation, threat intelligence, integrations, asset risk, response playbook, audit trail, team access, and operations/retention. The timestamped local runtime/test bundle is indexed in [docs/evidence/README.md](evidence/README.md). It records the 00:35 UTC lab snapshot, not the later dashboard session. The screenshots predate the dashboard follow-up and do not show the current candidate. Recapture them after the local smoke test.

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
- [x] License, SECURITY.md, CONTRIBUTING.md and support policy are present and consistent.
- [ ] Version tag, signed release artifacts, checksums and SBOM are published.

## Status vocabulary

Use only these meanings in release notes:

- **Implemented:** code exists in the repository.
- **Automated-tested:** relevant tests pass in CI.
- **Integration-verified:** exercised against a representative external service or receiver.
- **Operationally-validated:** load, restore, rotation and deployment exercises have evidence.
- **Release-ready:** all mandatory release gates above are closed for the specific release candidate.

A merged pull request alone does not imply integration-verified, operationally-validated or release-ready.
