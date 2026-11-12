# Release readiness

This checklist tracks what has been tested and what still needs evidence before AegisSOC is used outside a development or lab environment. A merged pull request or a green CI run is not, by itself, a production release.

## Current project status

**Suitable for public source publication and local-lab use. Not cleared for production deployment.**

The current baseline is `main` at commit `d993051` (12 November 2026).

### Verified

- GitHub Actions passed on the publication pass: **175 tests passed, 1 skipped**. The workflow covered the test suite, PostgreSQL migration and runtime-role checks, RLS behavior, dashboard JavaScript syntax and Compose validation.
- The local Docker smoke test used `compose.yaml` with the optional `compose.wazuh.yaml` override.
- The API returned `alive` from `/health/live` and `ready` from `/health/ready`.
- The API, database, scheduler, integration worker, response worker and retention worker started. The database and API health checks passed.
- The integration worker queried the Wazuh Indexer successfully (HTTP 200) and completed its connector cycle.
- The dashboard showed three active alerts, matching the three acknowledged alerts. There were no overdue detection schedules, detection failures or ingest rejections in that check.
- The Wazuh source reported healthy status and a recent event timestamp after the local smoke test.

These checks describe one local lab run. They do not establish availability, security or performance in a production environment.

### Dashboard health interpretation

The local dashboard still reported overall operations health as **degraded** because five other configured sources were stale. That status is expected when a source has no recent event evidence. A successful connector poll is not the same as receiving fresh events, so stale sources should not be marked healthy just to make the overall status green.

## Remaining work before production

### Security review
- [ ] Complete a threat model review and track findings to closure.
- [ ] Run an independent security assessment or penetration test.
- [ ] Review Python dependencies, base images and container packages for known vulnerabilities.
- [ ] Exercise secret and signing-key rotation.
- [ ] Generate an SBOM and sign release artifacts.

### Operations and recovery
- [ ] Test backup restoration in an isolated environment and record the result.
- [ ] Define and verify recovery point and recovery time objectives.
- [ ] Run load, concurrency and soak tests against documented targets.
- [ ] Test worker restart, retry, lease expiry and database failover behavior.
- [ ] Review monitoring, alerting, retention, incident response and rollback procedures.

### Installation and compatibility
- [ ] Have a reviewer follow the clean-install guide on a fresh machine.
- [ ] Test upgrades from the previous supported version and document rollback.
- [ ] Validate each external provider against a representative supported version and account.
- [ ] Publish supported versions, network requirements, permissions and known limitations.
- [ ] Refresh screenshots and recordings from the exact release candidate.

## Integration-specific checks

### Scanner imports
- [ ] Test Nessus, Tenable and Qualys authentication, export creation, polling, download and provider errors.
- [ ] Confirm cursor recovery after worker restart and idempotent re-import behavior.
- [ ] Verify unknown-asset handling and workspace isolation.
- [ ] Record a successful run against each supported provider before describing it as integration-verified.

Scanner adapters import existing exports. They do not start vulnerability scans.

### Sigma detections
- [ ] Keep positive and negative fixtures for each shipped rule.
- [ ] Validate rule parsing, unique IDs, enablement, scheduling and alert evidence.
- [ ] Document unsupported syntax, modifiers and correlation types.

Only the documented Sigma subset is supported.

### Response actions
- [ ] Test approval, rejection, expiry, cancellation and dry-run behavior.
- [ ] Test delivery, retries and idempotency across timeouts and worker restarts.
- [ ] Test receiver reconciliation for successful, pending, failed and unknown outcomes.
- [ ] Validate allowlists and compensation behavior against a dedicated test receiver.

Do not use destructive production actions in a portfolio demo.

## Evidence to keep with a release

For each release candidate, record:

- application commit and version;
- test run URL and result;
- deployment configuration and provider versions;
- date and environment used for each integration test;
- backup/restore and load-test results;
- screenshot or recording source for each demonstrated workflow;
- known issues and checks that were not run.

Use synthetic data for screenshots and recordings. Capture the application directly and redact sensitive values before saving the files. Do not add generated dashboard mockups as product evidence.

Suggested screenshots:

| File | What it should show |
|---|---|
| `overview.png` | Workspace overview and service health |
| `source-health.png` | Source status, event freshness and ingestion outcomes |
| `event-detail.png` | Normalized event and raw evidence |
| `alert-evidence.png` | Alert with linked event IDs and detection details |
| `case-timeline.png` | Case status, notes and linked alerts |
| `scanner-findings.png` | Imported assets and vulnerability findings |
| `sigma-validation.png` | Rule validation and enabled state |
| `response-approval.png` | Approval and dry-run flow |
| `response-reconciliation.png` | Test receiver result and reconciliation |
| `workspace-access.png` | Membership and role permissions |
| `audit-verification.png` | Audit history and verification result |
| `operations-health.png` | Worker status, retention and source health |

## Status terms

Use these terms consistently in documentation and release notes:

- **Implemented:** the code is present.
- **Automated-tested:** the relevant automated tests pass.
- **Integration-verified:** the feature has been exercised against a representative external service or receiver.
- **Operationally-validated:** deployment, load, recovery and rotation exercises have recorded results.
- **Production-ready:** the required security, operational and compatibility gates have been completed for the specific release.

Do not use these labels interchangeably. In particular, passing unit tests does not prove an external integration works, and a successful local startup does not prove production readiness.
