from pathlib import Path
import re

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
    # Role checks are centralized through currentRole()/applyCurrentUser so
    # workspace membership roles and the signed-in user stay in sync.
    assert "function applyCurrentUser()" in script
    assert "const role = currentRole();" in script
    assert '$("team-nav").hidden = role !== "admin";' in script
    assert '$("source-register-panel").hidden = role !== "admin";' in script
    assert '$("run-detections").hidden = role === "read_only";' in script
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


def test_dashboard_uses_a_light_60_30_10_design_system():
    html = (WEB / "index.html").read_text(encoding="utf-8")
    styles = (WEB / "styles.css").read_text(encoding="utf-8")
    assert "Inter:wght@400;500;600;700;800" in html
    assert "IBM+Plex+Mono" in html
    assert "Security operations." in html
    assert "--bg: #F3F5F2" in styles
    assert "--navy: #173746" in styles
    assert "--teal: #0B8D83" in styles
    assert "60% warm mineral canvas" in styles
    assert ".metrics-grid" in styles
    assert ".source-layout" in styles
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


def test_dashboard_uses_clear_modern_typography_and_matte_surfaces():
    html = (WEB / "index.html").read_text(encoding="utf-8")
    styles = (WEB / "styles.css").read_text(encoding="utf-8")
    assert "Inter:wght@400;500;600;700;800" in html
    assert "IBM+Plex+Mono" in html
    assert "border-radius: 6px" in styles
    assert "--line: #DCE4E0" in styles
    assert "--focus: #0B8D83" in styles
    assert "box-shadow: var(--shadow-float)" in styles

def test_dashboard_exposes_case_management_and_rule_governance_workspaces():
    html = (WEB / "index.html").read_text(encoding="utf-8")
    script = (WEB / "app.js").read_text(encoding="utf-8")
    for element_id in (
        "cases", "case-create-form", "case-list", "case-detail",
        "detection-rules", "detection-rule-list", "case-create-toggle",
    ):
        assert f'id="{element_id}"' in html
    assert 'data-nav="cases"' in html
    assert 'data-nav="detection-rules"' in html
    assert 'api("/api/v1/cases")' in script
    assert 'api("/api/v1/detection-rules")' in script
    assert "function renderCases()" in script
    assert "function renderDetectionRules()" in script
    assert "function selectCase(" in script


def test_dashboard_visual_system_v3_improves_readability_and_spacing():
    styles = (WEB / "styles.css").read_text(encoding="utf-8")
    assert "--text: #172A32" in styles
    assert "--muted: #52666C" in styles
    assert "line-height: 1.65" in styles
    assert "font-size: clamp(24px, 2vw, 27px)" in styles
    assert "min-height: 40px" in styles
    assert ".case-layout" in styles
    assert ".detection-rule-list" in styles


def test_dashboard_exposes_threat_intelligence_and_entity_correlation():
    html = (WEB / "index.html").read_text(encoding="utf-8")
    script = (WEB / "app.js").read_text(encoding="utf-8")
    for element_id in ("threat-intel", "indicator-form", "indicator-list", "indicator-matches",
                       "entity-correlation", "entity-type", "entity-search", "entities-body"):
        assert f'id="{element_id}"' in html
    assert 'data-nav="threat-intel"' in html
    assert 'data-nav="entity-correlation"' in html
    assert 'api("/api/v1/threat-intel/indicators?limit=200")' in script
    assert 'api("/api/v1/threat-intel/entities?min_events=1&limit=200")' in script
    assert "function renderThreatIntel()" in script
    assert "function renderEntities()" in script


def test_dashboard_exposes_asset_risk_and_response_playbook_workspaces():
    html = (WEB / "index.html").read_text(encoding="utf-8")
    script = (WEB / "app.js").read_text(encoding="utf-8")
    for element_id in (
        "asset-risk", "asset-form", "asset-inventory", "assets-body",
        "finding-form", "finding-list", "response-playbooks", "playbook-form",
        "playbook-list",
    ):
        assert f'id="{element_id}"' in html
    assert 'data-nav="asset-risk"' in html
    assert 'data-nav="response-playbooks"' in html
    assert 'api("/api/v1/asset-risk/assets?limit=200")' in script
    assert 'api("/api/v1/asset-risk/playbooks?limit=100")' in script
    assert "function renderAssetRisk()" in script
    assert "function renderPlaybooks()" in script
    assert "styles.css?v=3.2" in html
    assert "app.js?v=3.2" in html


def test_dashboard_navigation_targets_existing_sections():
    html = (WEB / "index.html").read_text(encoding="utf-8")
    navigation = re.findall(r'<a\b[^>]*href="#([^"]+)"[^>]*data-nav="([^"]+)"', html)
    sections = set(re.findall(r'<section\b[^>]*\bid="([^"]+)"', html))
    assert len(navigation) == 15
    assert len({name for name, _ in navigation}) == len(navigation)
    assert all(target == name and target in sections for target, name in navigation)


def test_screenshot_gallery_references_existing_image_assets():
    gallery_path = ROOT / "docs" / "SCREENSHOT_GALLERY.md"
    gallery = gallery_path.read_text(encoding="utf-8")
    image_paths = re.findall(r'!\[[^]]*\]\(([^)]+)\\)', gallery)
    assert image_paths
    assert all((gallery_path.parent / image_path).resolve().is_file() for image_path in image_paths)
