from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WEB = ROOT / "web"


def test_dashboard_exposes_authentication_and_session_controls():
    html = (WEB / "index.html").read_text(encoding="utf-8")
    for element_id in (
        "login-form", "login-button", "signout-button", "sidebar-signout",
        "auth-overlay", "run-detections", "source-grid", "source-create-form",
    ):
        assert f'id="{element_id}"' in html
    assert 'id="signout-button" hidden' in html
    assert 'id="sidebar-signout" title="Sign out" aria-label="Sign out" hidden' in html


def test_dashboard_has_role_aware_team_and_source_management():
    html = (WEB / "index.html").read_text(encoding="utf-8")
    script = (WEB / "app.js").read_text(encoding="utf-8")
    assert 'id="team-nav"' in html
    assert 'id="create-user-form"' in html
    assert 'id="users-list"' in html
    assert 'data-nav="sources"' in html
    assert 'id="source-register-panel"' in html
    assert 'state.user?.role !== "admin"' in script
    assert 'state.user.role === "read_only"' in script
    assert 'api("/api/v1/sources")' in script
    assert 'function renderSources()' in script


def test_authenticated_fetch_merges_options_before_bearer_headers():
    script = (WEB / "app.js").read_text(encoding="utf-8")
    assert '...(state.token ? { Authorization: "Bearer " + state.token } : {})' in script
    assert 'const response = await fetch(path, { ...options, headers });' in script
    assert 'fetch(path, {headers:' not in script


def test_dashboard_styles_include_responsive_and_reduced_motion_support():
    styles = (WEB / "styles.css").read_text(encoding="utf-8")
    assert "@media(max-width:680px)" in styles
    assert "@media(prefers-reduced-motion:reduce)" in styles
    assert ".auth-overlay.hidden" in styles
    assert ".team-section.visible" in styles
    assert ".source-card" in styles
    assert ".source-state.failing" in styles


def test_dashboard_uses_a_premium_matte_graphite_visual_system():
    html = (WEB / "index.html").read_text(encoding="utf-8")
    styles = (WEB / "styles.css").read_text(encoding="utf-8")
    assert "Geist" in html
    assert "Geist+Mono" in html
    assert "Security operations." in html
    assert "--bg: #0B0D10" in styles
    assert "--surface: #11151A" in styles
    assert "--green: #3C9B76" in styles
    assert ".metrics-grid" in styles
    assert ".source-layout" in styles
    assert "linear-gradient" not in styles
    assert "backdrop-filter" not in styles


def test_dashboard_exposes_investigation_workbench_controls():
    html = (WEB / "index.html").read_text(encoding="utf-8")
    script = (WEB / "app.js").read_text(encoding="utf-8")
    for element_id in (
        "event-query-text", "event-query-severity", "event-query-source",
        "event-query-time", "event-query-group", "saved-query-select",
        "saved-query-name", "saved-query-shared", "run-event-query",
        "reset-event-query", "save-event-query", "query-aggregations",
    ):
        assert f'id="{element_id}"' in html
    assert 'api("/api/v1/events/query"' in script
    assert 'api("/api/v1/events/saved-queries"' in script
    assert 'api("/api/v1/events/fields"' in script
    assert "function renderQueryAggregations()" in script


def test_dashboard_exposes_detection_schedule_controls():
    html = (WEB / "index.html").read_text(encoding="utf-8")
    script = (WEB / "app.js").read_text(encoding="utf-8")
    for element_id in (
        "schedule-create-panel", "schedule-create-form", "schedule-name",
        "schedule-interval", "schedule-window", "schedule-threshold",
        "schedule-create-button", "schedules-grid", "schedule-history",
    ):
        assert f'id="{element_id}"' in html
    assert 'data-nav="schedules"' in html
    assert 'api("/api/v1/detection-schedules")' in script
    assert 'function renderSchedules()' in script
    assert 'function loadScheduleHistory(' in script


def test_dashboard_exposes_audit_integrity_controls():
    html = (WEB / "index.html").read_text(encoding="utf-8")
    script = (WEB / "app.js").read_text(encoding="utf-8")
    for element_id in ("audit-status", "verify-audit", "audit-count", "audit-list"):
        assert f'id="{element_id}"' in html
    assert 'data-nav="audit"' in html
    assert 'api("/api/v1/audit?limit=10")' in script
    assert 'api("/api/v1/audit/verify")' in script
    assert "function renderAudit()" in script



def test_dashboard_exposes_retention_operations_and_connector_workspaces():
    html = (WEB / "index.html").read_text(encoding="utf-8")
    script = (WEB / "app.js").read_text(encoding="utf-8")
    for element_id in (
        "operations", "operations-status", "ops-events-hour", "ops-events-day",
        "ops-detection-failures", "ops-ingest-rejected", "retention-policies",
        "run-retention", "operations-jobs", "connectors", "connector-create-form",
        "connector-list", "connector-config", "connector-credential-ref",
    ):
        assert f'id="{element_id}"' in html
    assert 'api("/api/v1/operations/health")' in script
    assert 'api("/api/v1/operations/metrics")' in script
    assert 'api("/api/v1/operations/retention")' in script
    assert 'api("/api/v1/connectors")' in script
    assert "function renderOperations()" in script
    assert "function renderConnectors()" in script


def test_dashboard_uses_sharp_matte_surfaces_and_geist_typography():
    html = (WEB / "index.html").read_text(encoding="utf-8")
    styles = (WEB / "styles.css").read_text(encoding="utf-8")
    assert "Geist" in html
    assert "Geist+Mono" in html
    assert "border-radius: 6px" in styles
    assert "--line: #242B33" in styles
    assert "--focus: #6B9A9A" in styles
    assert "box-shadow: var(--shadow-float)" in styles
