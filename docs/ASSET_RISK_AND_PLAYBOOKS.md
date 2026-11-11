# Asset risk and response playbooks

> Related product captures: [AegisSOC screenshot gallery](SCREENSHOT_GALLERY.md).

## Phase 1.22 — Asset inventory and vulnerability triage

AegisSOC maintains an analyst-curated inventory of managed assets and source-attributed vulnerability observations.

- `GET /api/v1/asset-risk/assets` lists assets with bounded search, status, and criticality filters.
- `POST /api/v1/asset-risk/assets` registers an asset. `asset_key` is unique and stable.
- `PATCH /api/v1/asset-risk/assets/{asset_id}` updates ownership, environment, criticality, lifecycle, tags, and notes.
- `GET /api/v1/asset-risk/assets/{asset_id}/findings` lists findings for an asset.
- `POST /api/v1/asset-risk/assets/{asset_id}/findings` records a finding with vulnerability identifier, severity, source, and optional remediation due date.
- `PATCH /api/v1/asset-risk/findings/{finding_id}` tracks triage through `open`, `in_progress`, `accepted_risk`, `remediated`, or `false_positive`.

The asset key and vulnerability identifier are unique at their documented scopes. Analyst changes are written to the global tamper-evident audit chain. This is an inventory and triage capability, not a vulnerability scanner: findings must come from an authorized scanner or analyst, and AegisSOC does not claim CVSS calculation or exploitability validation.

## Phase 1.23 — Response playbook execution

Playbook runs provide auditable, case-linked checklists:

- `GET /api/v1/asset-risk/playbooks` lists recent runs, optionally filtered by case or status.
- `POST /api/v1/asset-risk/playbooks` starts a run with 1–30 named steps and an optional incident case.
- `PATCH /api/v1/asset-risk/playbooks/{run_id}/steps/{step_index}` marks a step complete or reopens it.
- Each completed step records the server-derived analyst and timestamp.
- A run becomes completed only when all required steps are complete; optional steps do not block completion.
- Run creation and step changes are audit logged.

Playbook steps are inert checklist data. The platform does not execute shell commands, isolate endpoints, disable accounts, or perform other response actions automatically. Human approval and authorized integrations remain required for future orchestration.

## Migration

Apply Alembic revision `0013_asset_risk_playbooks`:

```powershell
docker compose exec api alembic upgrade head
docker compose exec api alembic current
```
