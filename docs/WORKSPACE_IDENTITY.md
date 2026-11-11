# Workspace identity foundation

Phase 1.30 begins by establishing durable workspace identity and membership records.

## What this phase provides

- A workspaces registry with stable UUIDs, unique slugs, names, and active state.
- A workspace_memberships relation that binds users to workspaces with an explicit workspace role.
- Migration 0015_workspace_identity, which creates one Default Workspace and backfills every existing user into it using the user's current role and active state.
- Authenticated read endpoints:
  - GET /api/v1/workspaces lists only active workspaces the caller belongs to.
  - GET /api/v1/workspaces/{workspace_id} returns a workspace only when the caller has an active membership; non-members receive 404.

The migration does not rewrite or delete existing SOC records. Existing event, alert, case, asset, indicator, connector, detection, audit, and operational data remain unchanged.

## Security boundary and rollout

This is the identity/control-plane foundation, **not yet full tenant data isolation**. Existing SOC data-plane routes and background workers still operate on the current single shared dataset. This release intentionally does not expose workspace creation, invitation, switching, or cross-workspace data access.

Do not deploy this phase as a multi-customer SaaS boundary or create additional workspaces manually. The next isolation work must add workspace ownership to every tenant-owned record, scope reads and writes (including child records and idempotency keys), and propagate workspace context through scheduler, retention, connector, and response workers. PostgreSQL row-level security and cross-tenant integration tests are required before multi-workspace provisioning is enabled.

This staged rollout preserves current installations and makes the identity model reviewable before data-plane changes are introduced.
