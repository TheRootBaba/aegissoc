# Contributing

Thanks for taking the time to work on AegisSOC. The main thing to protect when changing the project is its security model: workspace boundaries, approval checks and the limits of each integration need to remain clear.

## Local setup

The project uses Python 3.12. Node.js 22 is used for the dashboard JavaScript check. Docker Desktop and Docker Compose are needed for PostgreSQL-backed integration work.

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
pytest -q
node --check web/app.js
```

For a running instance, follow the root [README](README.md). The default Compose stack runs without Wazuh. Use `compose.wazuh.yaml` only when connecting to an existing Wazuh single-node Docker network and its local CA bundle.

## Before opening a pull request

- Add a regression test when behavior changes, especially around authentication, authorization and workspace isolation.
- Do not treat SQLite tests as proof that PostgreSQL row-level security works. Keep the PostgreSQL checks in place.
- Use synthetic events and documentation-only IP ranges in fixtures and examples.
- Test provider response formats with fixtures. Do not infer support for undocumented API fields or describe a mock test as provider certification.
- Keep Sigma support within the documented subset.
- Keep response actions approval-gated, allowlisted and idempotent.
- For dashboard changes, check keyboard access, labels, responsive layouts and reduced-motion behavior.
- Update the relevant guide when a workflow changes. Screenshots must come from the running application, not generated mockups.

## Pull request notes

Keep each change focused and use a commit message that explains what changed. In the pull request, describe:

- the behavior being changed and why;
- any database migration or compatibility impact;
- security implications and affected workspace boundaries;
- tests you ran and checks you could not run.

Do not include `.env`, credentials, private keys, local databases, customer telemetry or unredacted logs.

AegisSOC should not be described as production-ready until the checks in [release readiness](docs/RELEASE_READINESS.md) have been completed for the release candidate.

GitHub Actions runs the test suite and checks PostgreSQL migrations, runtime-role provisioning, RLS behavior, dashboard JavaScript syntax and both Compose configurations on pull requests to `main`.
