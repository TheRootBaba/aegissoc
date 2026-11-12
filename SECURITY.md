# Security policy

AegisSOC is an actively developed engineering project and lab deployment. It is not a certified production SIEM, and no security response SLA or bug-bounty program is offered.

## Reporting a vulnerability

Please do not disclose suspected vulnerabilities, credentials, exploit details or sensitive logs in a public issue or pull request.

1. If GitHub private vulnerability reporting is enabled for this repository, use the repository's **Security → Report a vulnerability** workflow.
2. If private reporting is unavailable, contact the repository maintainer through the GitHub profile before sharing technical details.
3. Include the affected commit or version, impact, prerequisites, reproduction steps and any suggested mitigation. Use synthetic data and redact secrets.

The maintainer will acknowledge reports as time permits, assess impact and coordinate a fix or mitigation. There is no guaranteed response or remediation timeline.

## Supported security posture

- Keep `.env`, provider credentials, CA private keys, tokens, real telemetry and customer screenshots out of Git.
- Use PostgreSQL with the dedicated non-owner runtime role for tenant isolation.
- Keep migration-owner credentials separate from application runtime credentials.
- Treat the audit hash chain as tamper-evident within the database trust boundary, not as an external immutable archive.
- Do not enable automated response actions against production systems until the receiver contract, allowlist, approval process and reconciliation behavior have been independently validated.

See [release readiness](docs/RELEASE_READINESS.md) and the [operations runbook](docs/OPERATIONS_RUNBOOK.md) for remaining assurance work.
