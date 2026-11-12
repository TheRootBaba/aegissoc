# Changelog

Notable project changes are recorded here. This changelog is maintained manually; it is not a promise that every internal change is listed.

## Unreleased

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
