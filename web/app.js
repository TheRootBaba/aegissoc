"use strict";

const $ = (id) => document.getElementById(id);
const state = {
  alerts: [], events: [], sources: [], eventStats: {}, alertStats: {}, users: [],
  selectedId: null, token: null, user: null, toastTimer: null,
};
const esc = (value) => String(value ?? "—").replace(/[&<>"']/g, (char) => ({
  "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
}[char]));
const date = (value) => {
  if (!value) return "—";
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? "—" : parsed.toLocaleString();
};
const count = (value) => Number(value || 0).toLocaleString();
const pill = (value, prefix = "") =>
  '<span class="pill ' + prefix + esc(value) + '">' +
  esc(String(value ?? "unknown").replaceAll("_", " ")) + "</span>";

function showToast(message, type = "success") {
  const region = $("toast-region");
  const item = document.createElement("div");
  item.className = "toast" + (type === "error" ? " error" : "");
  item.textContent = message;
  region.append(item);
  window.setTimeout(() => item.remove(), 3600);
}
function setHealth(online, message) {
  const el = $("health-pill");
  el.classList.toggle("offline", !online);
  el.innerHTML = '<span class="status-orb"></span><span>' + esc(message) + "</span>";
}
function showAuth(message = "") {
  $("auth-overlay").classList.remove("hidden");
  $("login-error").textContent = message;
  $("login-password").value = "";
  $("login-username").focus();
}
function clearSession() {
  sessionStorage.removeItem("aegis_token");
  state.token = null;
  state.user = null;
  state.alerts = [];
  state.events = [];
  state.sources = [];
  state.eventStats = {};
  state.alertStats = {};
  state.users = [];
  state.selectedId = null;
  $("session-label")?.replaceChildren();
  $("sidebar-username").textContent = "Analyst";
  $("sidebar-role").textContent = "Signed out";
  $("sidebar-avatar").textContent = "A";
  $("team-nav").hidden = true;
  $("team").classList.remove("visible");
  $("run-detections").hidden = false;
  $("signout-button").hidden = true;
  $("sidebar-signout").hidden = true;
  $("alerts-body").innerHTML = '<tr><td colspan="5" class="table-empty">Sign in to load alerts.</td></tr>';
  $("events-body").innerHTML = '<tr><td colspan="5" class="table-empty">Sign in to load telemetry.</td></tr>';
  $("source-grid").innerHTML = '<div class="source-empty">Sign in to inspect source health.</div>';
  $("source-register-panel").hidden = true;
  $("detail-panel").innerHTML = '<div class="investigation-empty"><span class="empty-radar">◎</span><span class="section-kicker">INVESTIGATION WORKSPACE</span><h3>Nothing selected</h3><p>Sign in to inspect alerts and investigations.</p></div>';
  showAuth();
}
async function api(path, options = {}) {
  // Merge options first, then build headers so caller options cannot accidentally
  // replace the bearer token. This was the cause of authenticated actions failing.
  const headers = {
    Accept: "application/json",
    ...(options.body ? { "Content-Type": "application/json" } : {}),
    ...(state.token ? { Authorization: "Bearer " + state.token } : {}),
    ...(options.headers || {}),
  };
  const response = await fetch(path, { ...options, headers });
  const body = response.status === 204 ? null : await response.json().catch(() => null);
  if (!response.ok) {
    if (response.status === 401 && state.token && path !== "/api/v1/auth/login") {
      clearSession();
    }
    throw new Error(body?.detail || response.statusText || "Request failed");
  }
  return body;
}
function renderMetrics() {
  const byStatus = state.alertStats.by_status || {};
  const bySeverity = state.alertStats.by_severity || {};
  const open = byStatus.open || 0;
  const high = (bySeverity.high || 0) + (bySeverity.critical || 0);
  const progress = (byStatus.acknowledged || 0) + (byStatus.in_progress || 0);
  $("metric-open").textContent = count(open);
  $("metric-high").textContent = count(high);
  $("metric-events").textContent = count(state.eventStats.total_events ?? state.events.length);
  $("metric-progress").textContent = count(progress);
  $("nav-alert-count").textContent = count(open);
  $("alert-count").textContent = count(state.alertStats.total_alerts ?? state.alerts.length) + " alerts";
  $("event-count").textContent = count(state.events.length) + " recent events";
  $("event-total-footer").textContent = count(state.eventStats.total_events ?? state.events.length);
}
function renderAlerts() {
  const severity = $("severity-filter").value;
  const technique = $("attack-filter").value;
  const search = $("alert-search").value.trim().toLowerCase();
  const rows = state.alerts.filter((alert) => {
    const haystack = [alert.title, alert.rule_id, alert.hostname, alert.source_ip,
      alert.attack_technique_id, alert.status].join(" ").toLowerCase();
    return (!severity || alert.severity === severity) &&
      (!technique || alert.attack_technique_id === technique) &&
      (!search || haystack.includes(search));
  });
  $("alerts-body").innerHTML = rows.length ? rows.map((alert) =>
    '<tr class="alert-row ' + (alert.id === state.selectedId ? "selected" : "") + '" data-id="' + esc(alert.id) + '">' +
    '<td><button class="row-link" type="button" data-alert-id="' + esc(alert.id) + '">' + esc(alert.title) + '</button>' +
    '<div class="sub-cell">' + esc(alert.rule_id) + " · " + esc(alert.attack_technique_id || "Unmapped") +
    " · " + esc(alert.hostname) + "</div></td><td>" + pill(alert.severity, "sev-") +
    "</td><td>" + pill(alert.status, "status-") + "</td><td>" + esc(alert.source_ip) +
    '</td><td>' + esc(date(alert.last_seen)) + "</td></tr>").join("") :
    '<tr><td colspan="5" class="table-empty">No alerts match the current filters.</td></tr>';
  $("alert-footer").textContent = rows.length + " visible · " + state.alerts.length + " loaded";
}
function renderEvents() {
  $("events-body").innerHTML = state.events.length ? state.events.slice(0, 25).map((event) =>
    "<tr><td><strong>" + esc(event.event_type) + '</strong><div class="sub-cell">' +
    esc(event.source) + "</div></td><td>" + pill(event.severity, "sev-") +
    "</td><td>" + esc(event.hostname) + "</td><td>" + esc(event.source_ip) +
    "</td><td>" + esc(date(event.timestamp)) + "</td></tr>").join("") :
    '<tr><td colspan="5" class="table-empty">No events ingested yet. Connect a source or send a lab event to get started.</td></tr>';
}
function renderSources() {
  const sources = state.sources || [];
  const counts = sources.reduce((total, source) => {
    total[source.health_status] = (total[source.health_status] || 0) + 1;
    return total;
  }, {});
  $("source-count").textContent = count(sources.length) + " sources";
  $("nav-source-count").textContent = count(sources.length);
  $("source-health-summary").textContent = sources.length
    ? (counts.healthy || 0) + " healthy · " + (counts.stale || 0) + " stale · " +
      (counts.failing || 0) + " failing · " + (counts.inactive || 0) + " inactive"
    : "No sources observed";
  $("source-grid").innerHTML = sources.length ? sources.map((source) => {
    const status = source.health_status || "inactive";
    const symbol = source.source_type === "wazuh" ? "◈" :
      source.source_type === "endpoint" ? "▣" :
      source.source_type === "cloud" ? "☁" :
      source.source_type === "network" ? "⌁" : "⌘";
    return '<article class="source-card"><div class="source-card-head"><div class="source-title">' +
      '<span class="source-symbol">' + symbol + '</span><span><strong>' + esc(source.display_name) +
      '</strong><small>' + esc(source.source_name) + ' · ' + esc(source.source_type) +
      '</small></span></div><span class="source-state ' + esc(status) + '">' + esc(status) +
      '</span></div><div class="source-counters"><div><span>Accepted</span><strong>' +
      count(source.accepted_events) + '</strong></div><div><span>Duplicates</span><strong>' +
      count(source.duplicate_events) + '</strong></div><div><span>Rejected</span><strong>' +
      count(source.rejected_events) + '</strong></div></div><div class="source-timing"><span>Last event: ' +
      esc(source.last_successful_event_at ? date(source.last_successful_event_at) : "Not observed") +
      '</span><span>Attempt: ' + esc(source.last_attempt_at ? date(source.last_attempt_at) : "—") +
      '</span></div></article>';
  }).join("") : '<div class="source-empty">No sources registered yet. Register a producer or send its first event to discover it automatically.</div>';
}

function renderUsers() {
  $("member-count").textContent = state.users.length + " members";
  $("users-list").innerHTML = state.users.length ? state.users.map((user) =>
    '<div class="user-row"><span class="member-avatar">' + esc(user.username.slice(0, 1).toUpperCase()) +
    '</span><span class="member-details"><strong>' + esc(user.username) +
    '</strong><small>Added ' + esc(date(user.created_at)) + "</small></span>" +
    '<span class="role-chip role-' + esc(user.role) + '">' + esc(user.role.replaceAll("_", " ")) +
    '</span><span class="member-active" title="' + (user.is_active ? "Active" : "Inactive") +
    '"></span></div>').join("") :
    '<div class="table-empty">No workspace members found.</div>';
}
async function loadInvestigation(id) {
  state.selectedId = id;
  renderAlerts();
  const panel = $("detail-panel");
  panel.innerHTML = '<div class="table-empty">Loading investigation details…</div>';
  try {
    const [alert, notes, history] = await Promise.all([
      api("/api/v1/alerts/" + encodeURIComponent(id)),
      api("/api/v1/alerts/" + encodeURIComponent(id) + "/notes"),
      api("/api/v1/alerts/" + encodeURIComponent(id) + "/history"),
    ]);
    const readOnly = state.user?.role === "read_only";
    panel.innerHTML =
      '<div class="detail-head"><div><div class="section-kicker">' + esc(alert.rule_id) +
      '</div><h3>' + esc(alert.title) + '</h3><div class="detail-meta">' + esc(alert.id) +
      '</div></div>' + pill(alert.severity, "sev-") + "</div>" +
      '<p class="detail-description">' + esc(alert.description) + "</p>" +
      '<div class="detail-grid"><div><label>SOURCE IP</label><strong>' + esc(alert.source_ip) +
      '</strong></div><div><label>TARGET HOST</label><strong>' + esc(alert.hostname) +
      '</strong></div><div><label>EVENT COUNT</label><strong>' + esc(alert.event_count) +
      '</strong></div><div><label>USERNAMES</label><strong>' + esc(alert.username) +
      '</strong></div><div><label>FIRST SEEN</label><strong>' + esc(date(alert.first_seen)) +
      '</strong></div><div><label>LAST SEEN</label><strong>' + esc(date(alert.last_seen)) +
      "</strong></div></div>" +
      '<div class="attack-card"><div class="section-kicker">MITRE ATT&CK MAPPING</div><strong>' +
      esc(alert.attack_technique_id || "Not mapped") + " · " + esc(alert.attack_technique_name || "—") +
      '</strong><span>' + esc(alert.attack_tactic || "No tactic assigned") + "</span>" +
      (alert.attack_technique_id ? '<a href="https://attack.mitre.org/techniques/' +
        encodeURIComponent(alert.attack_technique_id) + '/" target="_blank" rel="noopener noreferrer">Open technique ↗</a>' : "") +
      "</div>" +
      '<div class="field"><label for="status-input">WORKFLOW STATUS</label><select id="status-input" ' +
      (readOnly ? "disabled" : "") + '><option value="open">Open</option><option value="acknowledged">Acknowledged</option>' +
      '<option value="in_progress">In progress</option><option value="resolved">Resolved</option>' +
      '<option value="false_positive">False positive</option></select></div>' +
      '<div class="field"><label for="assignee-input">ASSIGNED ANALYST</label><input id="assignee-input" maxlength="120" ' +
      (readOnly ? "disabled" : "") + ' placeholder="Unassigned" value="' + esc(alert.assigned_to || "") + '"></div>' +
      '<div class="detail-meta">Audit identity is derived from your authenticated account.</div>' +
      '<div class="subsection"><h4>TRIGGERING EVIDENCE</h4><p class="detail-meta">' +
      esc((alert.evidence_event_ids || []).join(" · ")) + "</p></div>" +
      '<div class="detail-actions">' + (readOnly ? "" : '<button class="button button-primary" id="save-alert" type="button">Save changes</button>') +
      '<span class="detail-meta">Current status: ' + esc(alert.status.replaceAll("_", " ")) + "</span></div>" +
      '<div class="subsection"><h4>INVESTIGATION NOTES</h4><div>' +
      (notes.length ? notes.map((note) => '<div class="note-item"><strong>' + esc(note.author) +
        '</strong><time> · ' + esc(date(note.created_at)) + "</time><p>" + esc(note.body) + "</p></div>").join("") :
        '<p class="detail-meta">No investigation notes yet.</p>') + "</div>" +
      (readOnly ? "" : '<div class="field"><textarea id="note-input" maxlength="10000" placeholder="Record evidence, triage decisions, and findings…"></textarea></div><button class="button button-quiet" id="add-note" type="button">Add investigation note</button>') +
      '</div><div class="subsection"><h4>AUDIT HISTORY</h4>' +
      (history.length ? history.map((entry) => '<div class="history-item"><strong>' + esc(entry.action) +
        '</strong><time> · ' + esc(entry.actor) + " · " + esc(date(entry.created_at)) +
        "</time><p>" + esc(JSON.stringify(entry.details)) + "</p></div>").join("") :
        '<p class="detail-meta">No audit entries yet.</p>') + "</div>";

    $("status-input").value = alert.status;
    $("save-alert")?.addEventListener("click", async () => {
      const button = $("save-alert");
      button.disabled = true;
      try {
        await api("/api/v1/alerts/" + encodeURIComponent(id), {
          method: "PATCH",
          body: JSON.stringify({
            status: $("status-input").value,
            assigned_to: $("assignee-input").value.trim() || null,
          }),
        });
        showToast("Alert updated. The audit trail has been recorded.");
        await refreshDashboard();
        await loadInvestigation(id);
      } catch (error) {
        showToast(error.message, "error");
      } finally {
        if (button.isConnected) button.disabled = false;
      }
    });
    $("add-note")?.addEventListener("click", async () => {
      const button = $("add-note");
      const note = $("note-input").value.trim();
      if (!note) {
        showToast("Write an investigation note before saving.", "error");
        return;
      }
      button.disabled = true;
      try {
        await api("/api/v1/alerts/" + encodeURIComponent(id) + "/notes", {
          method: "POST", body: JSON.stringify({ body: note }),
        });
        showToast("Investigation note saved.");
        await loadInvestigation(id);
      } catch (error) {
        showToast(error.message, "error");
      } finally {
        if (button.isConnected) button.disabled = false;
      }
    });
  } catch (error) {
    panel.innerHTML = '<div class="investigation-empty"><h3>Unable to load this alert</h3><p>' + esc(error.message) + "</p></div>";
  }
}
async function refreshDashboard() {
  try {
    const [alerts, events, eventStats, alertStats, sources] = await Promise.all([
      api("/api/v1/alerts?limit=200"),
      api("/api/v1/events?limit=25"),
      api("/api/v1/events/stats"),
      api("/api/v1/alerts/stats"),
      api("/api/v1/sources"),
    ]);
    state.alerts = alerts;
    state.events = events;
    state.eventStats = eventStats;
    state.alertStats = alertStats;
    state.sources = sources;
    setHealth(true, "API operational");
    $("last-updated").textContent = "Last synced " + new Date().toLocaleTimeString();
    renderMetrics();
    renderAlerts();
    renderEvents();
    renderSources();
    if (state.selectedId && state.alerts.some((alert) => alert.id === state.selectedId)) {
      await loadInvestigation(state.selectedId);
    }
  } catch (error) {
    if (state.token) setHealth(false, "API connection issue");
    showToast(error.message, "error");
  }
}
async function refreshUsers() {
  if (state.user?.role !== "admin") return;
  try {
    state.users = await api("/api/v1/auth/users");
    renderUsers();
  } catch (error) {
    $("users-list").innerHTML = '<div class="table-empty">' + esc(error.message) + "</div>";
  }
}
async function bootstrap() {
  const token = sessionStorage.getItem("aegis_token");
  if (!token) {
    state.token = null;
    showAuth();
    return;
  }
  state.token = token;
  try {
    state.user = await api("/api/v1/auth/me");
    $("auth-overlay").classList.add("hidden");
    $("sidebar-username").textContent = state.user.username;
    $("sidebar-role").textContent = state.user.role.replaceAll("_", " ");
    $("sidebar-avatar").textContent = state.user.username.slice(0, 1).toUpperCase();
    $("team-nav").hidden = state.user.role !== "admin";
    $("source-register-panel").hidden = state.user.role !== "admin";
    $("team").classList.toggle("visible", state.user.role === "admin");
    $("run-detections").hidden = state.user.role === "read_only";
    $("signout-button").hidden = false;
    $("sidebar-signout").hidden = false;
    await refreshDashboard();
    await refreshUsers();
  } catch (error) {
    if (state.token) clearSession();
    showAuth("Your session could not be validated. Please sign in again.");
  }
}
async function signIn(event) {
  event.preventDefault();
  const button = $("login-button");
  button.disabled = true;
  button.innerHTML = "<span>Authenticating…</span>";
  $("login-error").textContent = "";
  try {
    const response = await fetch("/api/v1/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify({
        username: $("login-username").value.trim(),
        password: $("login-password").value,
      }),
    });
    const body = await response.json().catch(() => null);
    if (!response.ok) throw new Error(body?.detail || "Unable to sign in.");
    if (!body?.access_token) throw new Error("The authentication service returned no access token.");
    sessionStorage.setItem("aegis_token", body.access_token);
    state.token = body.access_token;
    await bootstrap();
    if (state.user) {
      $("login-form").reset();
      showToast("Welcome to AegisSOC, " + state.user.username + ".");
    } else {
      throw new Error("Sign-in succeeded, but the session could not be initialized.");
    }
  } catch (error) {
    $("login-error").textContent = error.message;
  } finally {
    button.disabled = false;
    button.innerHTML = "<span>Sign in to workspace</span><b>→</b>";
  }
}
async function createUser(event) {
  event.preventDefault();
  const button = $("create-user-button");
  const feedback = $("create-user-feedback");
  const form = $("create-user-form");
  button.disabled = true;
  feedback.className = "form-feedback";
  feedback.textContent = "Creating account…";
  try {
    const payload = {
      username: $("new-username").value.trim(),
      password: $("new-password").value,
      role: $("new-role").value,
    };
    await api("/api/v1/auth/users", { method: "POST", body: JSON.stringify(payload) });
    form.reset();
    feedback.textContent = "Account created successfully.";
    showToast("New workspace account created.");
    await refreshUsers();
  } catch (error) {
    feedback.className = "form-feedback error";
    feedback.textContent = error.message;
  } finally {
    button.disabled = false;
  }
}
async function registerSource(event) {
  event.preventDefault();
  const button = $("source-create-button");
  const feedback = $("source-create-feedback");
  button.disabled = true;
  feedback.className = "form-feedback";
  feedback.textContent = "Registering source…";
  try {
    await api("/api/v1/sources", { method: "POST", body: JSON.stringify({
      source_name: $("source-name").value.trim(),
      display_name: $("source-display-name").value.trim(),
      source_type: $("source-type").value,
    }) });
    $("source-create-form").reset();
    feedback.textContent = "Source registered. Health will reflect observed ingestion.";
    showToast("Source added to inventory.");
    await refreshDashboard();
  } catch (error) {
    feedback.className = "form-feedback error";
    feedback.textContent = error.message;
  } finally {
    button.disabled = false;
  }
}

function setActiveNav() {
  const current = location.hash.replace("#", "") || "overview";
  document.querySelectorAll("[data-nav]").forEach((link) => {
    link.classList.toggle("active", link.dataset.nav === current);
  });
  $("page-breadcrumb").textContent = current === "team" ? "Team & access" :
    current === "alerts" ? "Alert queue" : current === "events" ? "Event telemetry" :
    current === "sources" ? "Data source health" : "Overview";
}

$("login-form").addEventListener("submit", signIn);
$("signout-button").addEventListener("click", () => {
  clearSession();
  showToast("You have signed out.");
});
$("sidebar-signout").addEventListener("click", () => {
  clearSession();
  showToast("You have signed out.");
});
$("refresh-button").addEventListener("click", async () => {
  const button = $("refresh-button");
  button.disabled = true;
  try {
    await refreshDashboard();
    await refreshUsers();
  } finally {
    button.disabled = false;
  }
});
$("run-detections").addEventListener("click", async () => {
  const button = $("run-detections");
  button.disabled = true;
  button.textContent = "Running detections…";
  try {
    const result = await api("/api/v1/detections/run", {
      method: "POST", body: JSON.stringify({ window_minutes: 10, threshold: 5 }),
    });
    showToast("Detection run complete · " + result.alerts_created + " new · " + result.alerts_updated + " updated.");
    await refreshDashboard();
  } catch (error) {
    showToast(error.message, "error");
  } finally {
    button.disabled = false;
    button.innerHTML = "<span>▶</span> Run detections";
  }
});
$("create-user-form").addEventListener("submit", createUser);
$("source-create-form").addEventListener("submit", registerSource);
$("severity-filter").addEventListener("change", renderAlerts);
$("attack-filter").addEventListener("change", renderAlerts);
$("alert-search").addEventListener("input", renderAlerts);
$("alerts-body").addEventListener("click", (event) => {
  const trigger = event.target.closest("[data-alert-id]");
  if (trigger) loadInvestigation(trigger.dataset.alertId);
});
document.querySelectorAll("[data-nav]").forEach((link) => {
  link.addEventListener("click", () => {
    document.querySelectorAll("[data-nav]").forEach((item) => item.classList.remove("active"));
    link.classList.add("active");
  });
});
window.addEventListener("hashchange", setActiveNav);
setActiveNav();
bootstrap();
window.setInterval(() => { if (state.token) refreshDashboard(); }, 60000);
