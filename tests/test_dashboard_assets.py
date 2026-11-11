from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WEB = ROOT / "web"


def test_dashboard_exposes_authentication_and_session_controls():
    html = (WEB / "index.html").read_text(encoding="utf-8")
    for element_id in (
        "login-form",
        "login-button",
        "signout-button",
        "sidebar-signout",
        "auth-overlay",
        "run-detections",
    ):
        assert f'id="{element_id}"' in html
    assert 'id="signout-button" hidden' in html
    assert 'id="sidebar-signout" title="Sign out" aria-label="Sign out" hidden' in html


def test_dashboard_has_role_aware_team_management_surface():
    html = (WEB / "index.html").read_text(encoding="utf-8")
    script = (WEB / "app.js").read_text(encoding="utf-8")
    assert 'id="team-nav"' in html
    assert 'id="create-user-form"' in html
    assert 'id="users-list"' in html
    assert 'state.user?.role !== "admin"' in script
    assert 'state.user.role === "read_only"' in script


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


def test_dashboard_uses_a_distinctive_signal_lime_visual_system():
    html = (WEB / "index.html").read_text(encoding="utf-8")
    styles = (WEB / "styles.css").read_text(encoding="utf-8")
    assert "Space+Grotesk" in html
    assert "IBM+Plex+Mono" in html
    assert "Operational clarity." in html
    assert "--cyan:#c7f36b" in styles
    assert "--bg:#0b0e0c" in styles
    assert ".page-intro h1{font-size:clamp(38px,4.2vw,59px)" in styles
    assert "background-size:44px 44px,44px 44px,auto" in styles
