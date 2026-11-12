# Support

AegisSOC is an actively developed engineering project and lab deployment. It is not a certified production SIEM and does not include a commercial support agreement, uptime commitment or response-time SLA.

## Getting help

- Use GitHub Issues for reproducible bugs, documentation corrections and feature requests.
- For suspected security vulnerabilities, follow [SECURITY.md](SECURITY.md) instead of opening a public issue.
- Before opening an issue, search existing issues and review the [README](README.md), [integration guide](docs/INTEGRATIONS.md) and [operations runbook](docs/OPERATIONS_RUNBOOK.md).

When reporting a problem, include the commit SHA, operating system, Python/Docker versions, relevant sanitized logs, expected behavior and exact reproduction steps. Never attach secrets, access tokens, private keys, customer telemetry or unredacted production screenshots.

## Scope

Provider-specific behavior depends on the deployed provider version, permissions, API schema and network policy. Scanner imports, Sigma compatibility and response receiver support are intentionally bounded as described in the engineering documentation. Production deployment requires the additional assurance work listed in [release readiness](docs/RELEASE_READINESS.md).
