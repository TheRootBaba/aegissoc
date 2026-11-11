"""Add workspace ownership, scoped uniqueness, and PostgreSQL row-level security."""

from alembic import op
import sqlalchemy as sa

revision = "0016_tenant_isolation"
down_revision = "0015_workspace_identity"
branch_labels = None
depends_on = None

TENANT_TABLES = (
    "security_events", "detection_alerts", "alert_notes", "alert_audit_logs",
    "source_registry", "saved_event_queries", "detection_schedules",
    "detection_executions", "audit_chain_state", "security_audit_entries",
    "retention_policies", "operational_job_runs", "connector_configs",
    "incident_cases", "case_alert_links", "case_notes", "detection_rule_configs",
    "threat_indicators", "managed_assets", "vulnerability_findings",
    "response_playbook_runs", "connector_runtime_states", "connector_executions",
    "sigma_rules", "response_action_requests", "scanner_import_runs",
)

SCOPED_UNIQUES = (
    ("security_events", "uq_security_events_workspace_source_external_id", ["workspace_id", "source", "external_id"]),
    ("detection_alerts", "uq_detection_alerts_workspace_fingerprint", ["workspace_id", "fingerprint"]),
    ("source_registry", "uq_source_registry_workspace_name", ["workspace_id", "source_name"]),
    ("saved_event_queries", "uq_saved_event_queries_workspace_owner_name", ["workspace_id", "created_by", "name"]),
    ("detection_schedules", "uq_detection_schedules_workspace_owner_name", ["workspace_id", "created_by", "name"]),
    ("retention_policies", "uq_retention_policies_workspace_kind", ["workspace_id", "data_kind"]),
    ("connector_configs", "uq_connector_configs_workspace_key", ["workspace_id", "connector_key"]),
    ("incident_cases", "uq_incident_cases_workspace_number", ["workspace_id", "case_number"]),
    ("security_audit_entries", "uq_security_audit_entries_workspace_sequence", ["workspace_id", "sequence"]),
    ("threat_indicators", "uq_threat_indicators_workspace_type_value", ["workspace_id", "indicator_type", "value"]),
    ("managed_assets", "uq_managed_assets_workspace_key", ["workspace_id", "asset_key"]),
    ("vulnerability_findings", "uq_vulnerability_findings_workspace_asset_vuln", ["workspace_id", "asset_id", "vulnerability_id"]),
    ("scanner_import_runs", "uq_scanner_import_runs_workspace_scanner_scan", ["workspace_id", "scanner_name", "scan_id"]),
    ("response_action_requests", "uq_response_actions_workspace_idempotency", ["workspace_id", "idempotency_key"]),
)


def _drop_old_unique(table: str, columns: list[str]) -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    expected = set(columns)
    for item in inspector.get_unique_constraints(table):
        if set(item.get("column_names") or []) == expected and item.get("name"):
            op.drop_constraint(item["name"], table, type_="unique")
    for item in inspector.get_indexes(table):
        if item.get("unique") and set(item.get("column_names") or []) == expected:
            op.drop_index(item["name"], table_name=table)


def upgrade() -> None:
    bind = op.get_bind()
    workspace_id = bind.execute(
        sa.text("SELECT id FROM workspaces WHERE slug = 'default' ORDER BY created_at LIMIT 1")
    ).scalar_one()

    for table in TENANT_TABLES:
        op.add_column(table, sa.Column("workspace_id", sa.Uuid(as_uuid=True), nullable=True))
        op.execute(sa.text(f'UPDATE "{table}" SET workspace_id = :workspace_id WHERE workspace_id IS NULL').bindparams(workspace_id=workspace_id))
        op.alter_column(table, "workspace_id", existing_type=sa.Uuid(as_uuid=True), nullable=False)
        op.create_foreign_key(
            f"fk_{table}_workspace_id", table, "workspaces",
            ["workspace_id"], ["id"], ondelete="CASCADE",
        )
        op.create_index(f"ix_{table}_workspace_id", table, ["workspace_id"])

    # Audit-chain sequence numbers are now independent within each workspace.
    op.drop_constraint("audit_chain_state_pkey", "audit_chain_state", type_="primary")
    op.create_primary_key("pk_audit_chain_state", "audit_chain_state", ["id", "workspace_id"])

    for table, _, columns in SCOPED_UNIQUES:
        old_columns = [column for column in columns if column != "workspace_id"]
        _drop_old_unique(table, old_columns)

    for table, name, columns in SCOPED_UNIQUES:
        op.create_unique_constraint(name, table, columns)

    # The workspace registry is visible only through active membership.
    op.execute("""
        ALTER TABLE workspaces ENABLE ROW LEVEL SECURITY;
        ALTER TABLE workspaces FORCE ROW LEVEL SECURITY;
        CREATE POLICY workspace_membership_read ON workspaces
        USING (
            current_setting('aegis.worker', true) = 'on'
            OR EXISTS (
                SELECT 1 FROM workspace_memberships membership
                WHERE membership.workspace_id = workspaces.id
                  AND membership.user_id = NULLIF(current_setting('aegis.user_id', true), '')::uuid
                  AND membership.is_active = true
            )
        )
        WITH CHECK (
            current_setting('aegis.worker', true) = 'on'
            OR current_setting('aegis.manage_workspaces', true) = 'on'
        );
        ALTER TABLE workspace_memberships ENABLE ROW LEVEL SECURITY;
        ALTER TABLE workspace_memberships FORCE ROW LEVEL SECURITY;
        CREATE POLICY membership_owner_read ON workspace_memberships
        USING (
            current_setting('aegis.worker', true) = 'on'
            OR user_id = NULLIF(current_setting('aegis.user_id', true), '')::uuid
            OR (
                current_setting('aegis.manage_memberships', true) = 'on'
                AND workspace_id = NULLIF(current_setting('aegis.workspace_id', true), '')::uuid
            )
            OR current_setting('aegis.manage_workspaces', true) = 'on'
        )
        WITH CHECK (
            current_setting('aegis.worker', true) = 'on'
            OR user_id = NULLIF(current_setting('aegis.user_id', true), '')::uuid
            OR (
                current_setting('aegis.manage_memberships', true) = 'on'
                AND workspace_id = NULLIF(current_setting('aegis.workspace_id', true), '')::uuid
            )
            OR current_setting('aegis.manage_workspaces', true) = 'on'
        );
    """)

    for table in TENANT_TABLES:
        op.execute(f"""
            ALTER TABLE "{table}" ENABLE ROW LEVEL SECURITY;
            ALTER TABLE "{table}" FORCE ROW LEVEL SECURITY;
            CREATE POLICY tenant_workspace_isolation ON "{table}"
            USING (workspace_id = NULLIF(current_setting('aegis.workspace_id', true), '')::uuid)
            WITH CHECK (workspace_id = NULLIF(current_setting('aegis.workspace_id', true), '')::uuid);
        """)


def downgrade() -> None:
    raise RuntimeError(
        "Tenant isolation cannot be downgraded automatically: workspace-scoped uniqueness "
        "may have admitted values that collide in the former global namespace. Restore a "
        "pre-migration backup and use the documented recovery procedure."
    )
