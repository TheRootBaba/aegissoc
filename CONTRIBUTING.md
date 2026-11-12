# Contributing to AegisSOC

Thanks for helping improve AegisSOC. Contributions should preserve its explicit security boundaries and documented integration limits.

## Development environment

- Python 3.12
- Git
- Node.js 22 for dashboard JavaScript syntax checks
- Docker Desktop / Docker Compose for local PostgreSQL-backed integration work

Create a virtual environment and install dependencies:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
pytest -q
node --check web/app.js
```

For a local deployment, follow the root [README](README.md). The default Compose stack is standalone; use `compose.wazuh.yaml` only when connecting to an existing Wazuh single-node Docker network and local CA bundle.

## Change expectations

- Add regression tests for behavior changes, including authorization and workspace boundaries.
- Keep PostgreSQL RLS tests meaningful; SQLite tests do not prove PostgreSQL tenant isolation.
- Use synthetic fixtures and documentation-only IP ranges in tests and examples.
- Validate external provider response shapes with fixtures. Do not silently guess unsupported API fields or claim provider certification from mocks.
- Keep Sigma support bounded and document unsupported syntax.
- Keep response actions approval-gated, allowlisted and idempotent.
- Preserve accessible labels, keyboard behavior, responsive layout and reduced-motion support in dashboard changes.
- Update the relevant guide and screenshot gallery when user-visible workflows change. Product screenshots must be genuine captures from the application, not generated mockups.

## Pull requests

- Use a focused branch and descriptive commit messages.
- Explain the user-visible behavior, security impact, migrations and operational implications.
- Include test results and note any checks that could not be run.
- Never include `.env`, credentials, private keys, local databases, customer telemetry or unredacted logs.
- Do not mark work production-ready unless the release gates in [release readiness](docs/RELEASE_READINESS.md) are met.

GitHub Actions validates migrations, runtime-role provisioning, PostgreSQL RLS, dashboard JavaScript syntax, Compose configuration and the test suite on pull requests to `main`.
