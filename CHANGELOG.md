# Changelog

Notable project changes are recorded here. This changelog is maintained manually; it is not a promise that every internal change is listed.

## Unreleased

### Documentation
- Reworked the README around the actual local setup, project boundaries and current feature set.
- Replaced the stale release-readiness notes with the current CI and local Wazuh smoke-test results.
- Tightened the contributor guide so test expectations and security constraints are clear.

### Source inventory
- Recover a missing source last-event timestamp from telemetry already stored for that source when the integration worker next records a poll.
- Keep successful empty polls separate from event freshness; an empty poll does not mark a source healthy.

### Dashboard fixes
- Bump the dashboard script asset version so browsers load the updated active-alert and operations metrics logic.
- Record the latest event time during Wazuh Indexer polling, including duplicate records.
- Restore connector status from saved poll history when the summary fields were not updated.
- Count open, acknowledged and in-progress alerts as active work.
- Mark overdue detection schedules in the dashboard and operations health.
- Show connector poll history separately from configuration validation.
- Rename the lab evidence snapshot and remove the local Windows user path from its metadata.

### Repository and deployment
- Corrected the API container startup command.
- Kept the default Docker Compose deployment independent of the optional Wazuh Docker network and local CA bundle.
- Added `compose.wazuh.yaml` for opt-in connectivity to a Wazuh single-node lab network.

### Dashboard evidence and quality
- Moved the 14 existing dashboard screenshots into `evidence/dashboard/` and normalized their filenames.
- Updated the screenshot gallery and added indexes for product screenshots and the timestamped local runtime/test evidence.
- Added regression checks that every dashboard navigation link targets a real section and every screenshot gallery image exists.

### Documentation and verification
- Updated README deployment instructions and release-readiness evidence provenance.
- Added contributor, security reporting and support policies.
- Added CI validation for both standalone and Wazuh Compose configurations.
