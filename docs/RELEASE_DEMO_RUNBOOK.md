# Release Demo and Evidence Runbook

This runbook is a capture plan. It does not claim that a release build was launched or that recordings were created. Capture only from the exact release-candidate commit, with synthetic data and secrets redacted.

## Preconditions

1. Check out the release-candidate SHA and record it in the evidence manifest.
2. Start the documented deployment with the production-like configuration, but isolated synthetic data and non-production credentials.
3. Run migrations and the complete CI workflow for that SHA.
4. Verify dashboard/API health, worker health, database migration revision and runtime-role/RLS checks.
5. Use a clean browser profile and resettable demo tenant. Do not expose real customer data, tokens, hostnames or provider secrets.

## Recording sequence

| Recording | Required visible flow | Evidence to retain |
|---|---|---|
| 01 Platform overview | Dashboard, health, connectors and tenant context | MP4 + commit SHA |
| 02 Event to investigation | Ingest synthetic event, detect alert, inspect evidence, open case | MP4 + event/alert IDs |
| 03 Threat intelligence | Poll a fixture feed and show normalized indicator and provenance | MP4 + connector execution |
| 04 Scanner export | Start/poll/download a fixture export, reconcile known asset and finding | MP4 + export job and import IDs |
| 05 Sigma detection | Import/validate rule, run detection and show evidence-linked alert | MP4 + rule and alert IDs |
| 06 Response | Request, independent approval, execute against a test receiver, reconcile result | MP4 + action ID and receiver reference |
| 07 Workspace security | Show role restrictions and workspace isolation checks | MP4 + test report |
| 08 Operations | Show worker state, audit verification, retention and backup status | MP4 + sanitized report |

## Architecture diagram exports

Render the Mermaid diagrams in `docs/ARCHITECTURE.md` to SVG/PNG for the release site. Keep the editable Mermaid source in the repository and record the renderer/version used.

## Evidence manifest

For every capture, record: artifact filename, release SHA, UTC capture time, environment identifier, operator, synthetic-data fixture version, redaction review and SHA-256 checksum. Store large recordings as Git LFS objects or GitHub Release assets rather than ordinary Git blobs.

## Acceptance gates not replaceable by a demo

- Nessus, Tenable and Qualys real-provider contract tests in a controlled tenant.
- Real response receiver acceptance, idempotency and ambiguous-outcome reconciliation tests.
- Independent security review/penetration test and dependency/SBOM review.
- Load and soak test with defined throughput, latency and error-rate targets.
- Key rotation test and secret revocation test.
- Encrypted backup restore drill with measured RPO/RTO.
- HA/failover and disaster-recovery exercise.

A screenshot, video, diagram or synthetic fixture is not a substitute for any of these gates. Attach actual outputs only after they have been generated and reviewed.
