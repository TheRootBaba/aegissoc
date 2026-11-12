"use strict";

const $ = (id) => document.getElementById(id);
const state = {
  alerts: [], events: [], sources: [], schedules: [], eventStats: {}, alertStats: {}, users: [],
  savedQueries: [], queryFields: [], queryResult: null, pendingSavedQuery: null,
  auditEntries: [], auditVerification: null, cases: [], detectionRules: [], selectedCaseId: null,
  operationsHealth: {}, operationsMetrics: {}, retentionPolicies: [], operationJobs: [], connectors: [],
  indicators: [], indicatorMatches: [], entities: [], assets: [], playbooks: [], findings: [],
  selectedId: null, token: null, user: null, toastTimer: null,
  workspaces: [], workspaceId: null,
};
const currentRole = () => state.user?.workspace_role || state.user?.role || "read_only";
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
  state.workspaceId = null;
  state.workspaces = [];
  localStorage.removeItem("aegis_workspace_id");
  if ($("workspace-name")) $("workspace-name").textContent = "No active workspace";
  if ($("workspace-select")) $("workspace-select").innerHTML = '<option value="">Select workspace</option>';
  state.alerts = [];
  state.events = [];
  state.sources = [];
  state.schedules = [];
  state.savedQueries = [];
  state.queryFields = [];
  state.queryResult = null;
  state.pendingSavedQuery = null;
  state.auditEntries = [];
  state.auditVerification = null;
  state.operationsHealth = {};
  state.operationsMetrics = {};
  state.retentionPolicies = [];
  state.operationJobs = [];
  state.connectors = [];
  state.assets = []; state.playbooks = []; state.findings = [];
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
  $("schedule-create-panel").hidden = true;
  $("schedules-grid").innerHTML = '<div class="source-empty">Sign in to inspect detection schedules.</div>';
  $("schedule-history").hidden = true;
  $("verify-audit").hidden = true;
  $("audit-list").innerHTML = '<div class="source-empty">Sign in to inspect the security audit trail.</div>';
  $("audit-status").textContent = "Not verified";
  $("audit-count").textContent = "0 records";
  $("operations-status").textContent = "Awaiting telemetry";
  $("retention-policies").innerHTML = '<div class="source-empty">Sign in to inspect retention policies.</div>';
  $("operations-jobs").innerHTML = '<div class="source-empty">Sign in to inspect maintenance history.</div>';
  $("connector-list").innerHTML = '<div class="source-empty">Sign in to inspect integrations.</div>';
  $("connector-create-panel").hidden = true;
  $("run-retention").hidden = true;
  $("source-register-panel").hidden = true;
  $("detail-panel").innerHTML = '<div class="investigation-empty"><span class="empty-radar">◎</span><span class="section-kicker">INVESTIGATION WORKSPACE</span><h3>Nothing selected</h3><p>Sign in to inspect alerts and investigations.</p></div>';
  showAuth();
}
async function api(path, options = {}) {
  // Keep the session token when an action supplies its own headers.
  const headers = {
    Accept: "application/json",
    ...(options.body ? { "Content-Type": "application/json" } : {}),
    ...(state.token ? { Authorization: "Bearer " + state.token } : {}),
    ...(state.workspaceId ? { "X-Workspace-ID": state.workspaceId } : {}),
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
  const active = (byStatus.open || 0) + (byStatus.acknowledged || 0) + (byStatus.in_progress || 0);
  const high = (bySeverity.high || 0) + (bySeverity.critical || 0);
  const progress = (byStatus.acknowledged || 0) + (byStatus.in_progress || 0);
  $("metric-open").textContent = count(active);
  $("metric-high").textContent = count(high);
  $("metric-events").textContent = count(state.eventStats.total_events ?? state.events.length);
  $("metric-progress").textContent = count(progress);
  $("nav-alert-count").textContent = count(active);
  $("alert-count").textContent = count(state.alertStats.total_alerts ?? state.alerts.length) + " alerts";
  $("event-count").textContent = count(state.events.length) + " recent events";
  $("event-total-footer").textContent = count(state.queryResult?.total ?? state.eventStats.total_events ?? state.events.length);
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
  const rows = state.queryResult?.events ?? state.events.slice(0, 25);
  $("events-body").innerHTML = rows.length ? rows.map((event) =>
    "<tr><td><strong>" + esc(event.event_type) + '</strong><div class="sub-cell">' +
    esc(event.source) + "</div></td><td>" + pill(event.severity, "sev-") +
    "</td><td>" + esc(event.hostname) + "</td><td>" + esc(event.source_ip) +
    "</td><td>" + esc(date(event.timestamp)) + "</td></tr>").join("") :
    '<tr><td colspan="5" class="table-empty">No events match this investigation. Adjust the filters or widen the time range.</td></tr>';
  $("event-count").textContent = state.queryResult
    ? count(state.queryResult.total) + " matches" : count(state.events.length) + " recent events";
  $("event-query-footer").innerHTML = state.queryResult
    ? "Showing <strong>" + count(rows.length) + "</strong> of <strong id=\"event-total-footer\">" + count(state.queryResult.total) + "</strong> matching events"
    : "All-time volume: <strong id=\"event-total-footer\">" + count(state.eventStats.total_events ?? state.events.length) + "</strong>";
  renderQueryAggregations();
}
function renderQueryAggregations() {
  const panel = $("query-aggregations");
  const groups = state.queryResult?.aggregations || [];
  if (!groups.length) { panel.hidden = true; panel.innerHTML = ""; return; }
  panel.hidden = false;
  panel.innerHTML = '<div class="aggregation-heading"><span>QUERY BREAKDOWN</span><strong>' +
    esc($("event-query-group").selectedOptions[0]?.textContent || "Grouped results") +
    '</strong></div><div class="aggregation-list">' + groups.map((item) =>
      '<div class="aggregation-item"><span>' + esc(item.value || "Unspecified") +
      '</span><strong>' + count(item.count) + '</strong></div>').join("") + '</div>';
}
function currentInvestigationQuery() {
  const query = {
    search: $("event-query-text").value.trim() || null,
    filters: [],
    group_by: $("event-query-group").value || null,
    limit: 100,
    offset: 0,
  };
  if ($("event-query-severity").value) query.filters.push({
    field: "severity", operator: "eq", value: $("event-query-severity").value,
  });
  if ($("event-query-source").value) query.filters.push({
    field: "source", operator: "eq", value: $("event-query-source").value,
  });
  const hours = $("event-query-time").value;
  if (hours !== "all") {
    query.end_time = new Date().toISOString();
    query.start_time = new Date(Date.now() - Number(hours) * 3600000).toISOString();
  }
  return query;
}
async function runEventQuery(query = null) {
  const button = $("run-event-query");
  button.disabled = true;
  button.textContent = "Searching…";
  $("query-feedback").textContent = "Executing a bounded investigation query…";
  try {
    const payload = query || state.pendingSavedQuery || currentInvestigationQuery();
    state.pendingSavedQuery = null;
    state.queryResult = await api("/api/v1/events/query", {
      method: "POST", body: JSON.stringify(payload),
    });
    renderEvents();
    $("query-feedback").textContent = state.queryResult.total + " matching events · " +
      state.queryResult.events.length + " displayed";
  } catch (error) {
    $("query-feedback").textContent = error.message;
    showToast(error.message, "error");
  } finally {
    button.disabled = false;
    button.textContent = "Run investigation";
  }
}
function renderSavedQueries() {
  const select = $("saved-query-select");
  const selected = select.value;
  select.innerHTML = '<option value="">Load a saved investigation…</option>' +
    state.savedQueries.map((item) => '<option value="' + esc(item.id) + '">' +
      esc(item.name) + (item.is_shared ? " · shared" : "") + '</option>').join("");
  if (state.savedQueries.some((item) => item.id === selected)) select.value = selected;
}
async function saveEventQuery() {
  const name = $("saved-query-name").value.trim();
  if (!name) { $("query-feedback").textContent = "Enter a name before saving this investigation."; return; }
  try {
    await api("/api/v1/events/saved-queries", {
      method: "POST",
      body: JSON.stringify({
        name, query: currentInvestigationQuery(),
        is_shared: $("saved-query-shared").checked,
      }),
    });
    $("saved-query-name").value = "";
    $("saved-query-shared").checked = false;
    state.savedQueries = await api("/api/v1/events/saved-queries");
    renderSavedQueries();
    $("query-feedback").textContent = "Investigation saved to your workspace.";
    showToast("Saved investigation created.");
  } catch (error) {
    $("query-feedback").textContent = error.message;
    showToast(error.message, "error");
  }
}
async function loadSavedQuery() {
  const item = state.savedQueries.find((saved) => saved.id === $("saved-query-select").value);
  if (!item) return;
  state.pendingSavedQuery = item.query;
  await runEventQuery(item.query);
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
  const sourceSelect = $("event-query-source");
  const selectedSource = sourceSelect.value;
  sourceSelect.innerHTML = '<option value="">All sources</option>' + sources.map((source) =>
    '<option value="' + esc(source.source_name) + '">' + esc(source.display_name) + '</option>'
  ).join("");
  if (sources.some((source) => source.source_name === selectedSource)) sourceSelect.value = selectedSource;

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

function renderSchedules() {
  const schedules = state.schedules || [];
  const isAdmin = currentRole() === "admin";
  $("schedule-create-panel").hidden = !isAdmin;
  $("schedule-count").textContent = count(schedules.length) + " schedules";
  $("schedules-grid").innerHTML = schedules.length ? schedules.map((schedule) => {
    const nextRun = schedule.next_run_at ? new Date(schedule.next_run_at) : null;
    const overdue = Boolean(schedule.enabled && nextRun && !Number.isNaN(nextRun.getTime()) && nextRun.getTime() < Date.now() - 30000);
    const status = schedule.enabled ? (overdue ? "overdue" : (schedule.last_status || "pending")) : "paused";
    const statusClass = status === "success" ? "healthy" : (status === "failed" || overdue) ? "failing" : "inactive";
    const interval = schedule.interval_seconds < 3600
      ? Math.round(schedule.interval_seconds / 60) + " min"
      : schedule.interval_seconds % 3600 === 0
        ? schedule.interval_seconds / 3600 + " hr" : Math.round(schedule.interval_seconds / 60) + " min";
    const nextRunText = nextRun && !Number.isNaN(nextRun.getTime())
      ? (overdue ? "Overdue · " : "") + date(schedule.next_run_at)
      : "Not scheduled";
    return '<article class="schedule-card"><div class="schedule-card-head"><div><strong>' +
      esc(schedule.name) + '</strong><small>Every ' + esc(interval) + ' · ' +
      esc(schedule.window_minutes) + 'm window · threshold ' + esc(schedule.threshold) +
      '</small></div><span class="source-state ' + statusClass + '">' + esc(status.replaceAll("_", " ")) +
      '</span></div><div class="schedule-timing"><span>Next run<strong>' +
      esc(nextRunText) + '</strong></span><span>Last run<strong>' +
      esc(schedule.last_run_at ? date(schedule.last_run_at) : "Never") + '</strong></span><span>Failures<strong>' +
      count(schedule.consecutive_failures) + '</strong></span></div>' +
      (schedule.last_error ? '<div class="schedule-error">' + esc(schedule.last_error) + '</div>' : '') +
      '<div class="schedule-actions"><button class="button button-quiet" type="button" data-schedule-history="' +
      esc(schedule.id) + '">Run history</button>' +
      (isAdmin ? '<button class="button button-secondary" type="button" data-schedule-toggle="' +
      esc(schedule.id) + '" data-enabled="' + esc(schedule.enabled) + '">' +
      (schedule.enabled ? "Pause" : "Enable") + '</button><button class="button button-quiet schedule-delete" type="button" data-schedule-delete="' +
      esc(schedule.id) + '">Delete</button>' : "") + '</div></article>';
  }).join("") : '<div class="source-empty">No detection schedules yet.</div>';
}
async function loadScheduleHistory(scheduleId) {
  try {
    const executions = await api("/api/v1/detection-schedules/" + encodeURIComponent(scheduleId) + "/executions?limit=20");
    const schedule = state.schedules.find((item) => item.id === scheduleId);
    const panel = $("schedule-history");
    panel.hidden = false;
    panel.innerHTML = '<div class="schedule-history-heading"><strong>' +
      esc(schedule?.name || "Detection schedule") + ' · Execution history</strong><button class="button button-quiet" id="close-schedule-history" type="button">Close</button></div>' +
      (executions.length ? '<div class="schedule-history-list">' + executions.map((run) =>
        '<div class="schedule-run"><span class="source-state ' + (run.status === "success" ? "healthy" : "failing") +
        '">' + esc(run.status) + '</span><span><strong>' + esc(date(run.started_at)) +
        '</strong><small>' + count(run.events_evaluated) + ' events · ' + count(run.alerts_created) +
        ' new alerts · ' + count(run.alerts_updated) + ' updated</small></span><span class="run-duration">' +
        count(run.duration_ms) + ' ms</span>' +
        (run.error ? '<small class="schedule-error">' + esc(run.error) + '</small>' : '') +
        '</div>').join("") + '</div>' : '<div class="source-empty">No executions have been recorded yet.</div>');
  } catch (error) {
    showToast(error.message, "error");
  }
}
async function handleScheduleAction(event) {
  const history = event.target.closest("[data-schedule-history]");
  if (history) { await loadScheduleHistory(history.dataset.scheduleHistory); return; }
  if (event.target.closest("#close-schedule-history")) { $("schedule-history").hidden = true; return; }
  const toggle = event.target.closest("[data-schedule-toggle]");
  if (toggle) {
    try {
      await api("/api/v1/detection-schedules/" + encodeURIComponent(toggle.dataset.scheduleToggle), {
        method: "PATCH", body: JSON.stringify({ enabled: toggle.dataset.enabled !== "true" }),
      });
      showToast("Detection schedule updated.");
      await refreshDashboard();
    } catch (error) { showToast(error.message, "error"); }
    return;
  }
  const remove = event.target.closest("[data-schedule-delete]");
  if (remove && window.confirm("Delete this detection schedule and its execution history?")) {
    try {
      await api("/api/v1/detection-schedules/" + encodeURIComponent(remove.dataset.scheduleDelete), { method: "DELETE" });
      $("schedule-history").hidden = true;
      showToast("Detection schedule deleted.");
      await refreshDashboard();
    } catch (error) { showToast(error.message, "error"); }
  }
}
function renderAudit() {
  const entries = state.auditEntries || [];
  $("audit-count").textContent = count(entries.length) + " recent records";
  $("verify-audit").hidden = currentRole() !== "admin";
  const verification = state.auditVerification;
  const status = $("audit-status");
  status.classList.toggle("audit-valid", Boolean(verification?.valid));
  status.classList.toggle("audit-invalid", Boolean(verification && !verification.valid));
  status.textContent = verification
    ? verification.valid ? "Verified · " + count(verification.checked_entries) + " entries"
      : "Integrity failure · sequence " + verification.first_invalid_sequence
    : "Not verified";
  $("audit-list").innerHTML = entries.length ? entries.map((entry) =>
    '<article class="audit-entry"><span class="audit-sequence">#' +
    String(entry.sequence).padStart(6, "0") + '</span><div class="audit-entry-main"><strong>' +
    esc(entry.action) + '</strong><small>' + esc(entry.actor) + ' · ' + esc(entry.resource_type) +
    (entry.resource_id ? ' · ' + esc(entry.resource_id) : '') + '</small></div><time>' +
    esc(date(entry.occurred_at)) + '</time><span class="audit-hash" title="' +
    esc(entry.entry_hash) + '">' + esc(entry.entry_hash.slice(0, 12)) + '…</span></article>'
  ).join("") : '<div class="source-empty">No operator actions recorded yet.</div>';
}
async function verifyAuditChain() {
  const button = $("verify-audit");
  button.disabled = true;
  button.textContent = "Verifying…";
  try {
    state.auditVerification = await api("/api/v1/audit/verify");
    renderAudit();
    showToast(state.auditVerification.message, state.auditVerification.valid ? "success" : "error");
  } catch (error) {
    showToast(error.message, "error");
  } finally {
    button.disabled = false;
    button.textContent = "Verify chain";
  }
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
    const readOnly = currentRole() === "read_only";
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
    const [alerts, events, eventStats, alertStats, sources, savedQueries, queryFields, schedules, auditEntries, operationsHealth, operationsMetrics, retentionPolicies, operationJobs, connectors, cases, detectionRules, indicators, indicatorMatches, entities, assets, playbooks] = await Promise.all([
      api("/api/v1/alerts?limit=200"),
      api("/api/v1/events?limit=25"),
      api("/api/v1/events/stats"),
      api("/api/v1/alerts/stats"),
      api("/api/v1/sources"),
      api("/api/v1/events/saved-queries"),
      api("/api/v1/events/fields"),
      api("/api/v1/detection-schedules"),
      api("/api/v1/audit?limit=10"),
      api("/api/v1/operations/health"),
      api("/api/v1/operations/metrics"),
      api("/api/v1/operations/retention"),
      api("/api/v1/operations/jobs?limit=20"),
      api("/api/v1/connectors"),
      api("/api/v1/cases"),
      api("/api/v1/detection-rules"),
      api("/api/v1/threat-intel/indicators?limit=200"),
      api("/api/v1/threat-intel/matches?limit=100"),
      api("/api/v1/threat-intel/entities?min_events=1&limit=200"),
      api("/api/v1/asset-risk/assets?limit=200"),
      api("/api/v1/asset-risk/playbooks?limit=100"),
    ]);
    state.alerts = alerts;
    state.events = events;
    state.eventStats = eventStats;
    state.alertStats = alertStats;
    state.sources = sources;
    state.schedules = schedules;
    state.auditEntries = auditEntries;
    state.operationsHealth = operationsHealth;
    state.operationsMetrics = operationsMetrics;
    state.retentionPolicies = retentionPolicies;
    state.operationJobs = operationJobs;
    state.connectors = connectors;
    state.cases = cases;
    state.detectionRules = detectionRules;
    state.indicators = indicators;
    state.indicatorMatches = indicatorMatches;
    state.entities = entities;
    state.assets = assets; state.playbooks = playbooks;
    state.savedQueries = savedQueries;
    state.queryFields = queryFields.fields || [];
    setHealth(true, "API operational");
    $("last-updated").textContent = "Last synced " + new Date().toLocaleTimeString();
    renderMetrics();
    renderAlerts();
    renderEvents();
    renderSources();
    renderSchedules();
    renderAudit();
    renderOperations();
    renderConnectors();
    renderCases();
    renderDetectionRules();
    renderThreatIntel();
    renderEntities();
    renderAssetRisk();
    renderPlaybooks();
    renderSavedQueries();
    if (state.selectedId && state.alerts.some((alert) => alert.id === state.selectedId)) {
      await loadInvestigation(state.selectedId);
    }
  } catch (error) {
    if (state.token) setHealth(false, "API connection issue");
    showToast(error.message, "error");
  }
}
async function refreshUsers() {
  if (currentRole() !== "admin") return;
  try {
    state.users = await api("/api/v1/auth/users");
    renderUsers();
  } catch (error) {
    $("users-list").innerHTML = '<div class="table-empty">' + esc(error.message) + "</div>";
  }
}
function renderWorkspaceSwitcher() {
  const select = $("workspace-select");
  if (!select) return;
  select.innerHTML = state.workspaces.map((workspace) =>
    '<option value="' + esc(workspace.id) + '">' + esc(workspace.name) + " · " +
    esc(workspace.role.replaceAll("_", " ")) + "</option>"
  ).join("");
  select.value = state.workspaceId || "";
  const active = state.workspaces.find((workspace) => workspace.id === state.workspaceId);
  $("workspace-name").textContent = active?.name || "No active workspace";
  $("workspace-avatar").textContent = active?.name?.slice(0, 1).toUpperCase() || "W";
  select.disabled = state.workspaces.length < 2;
}
function applyCurrentUser() {
  const role = currentRole();
  $("sidebar-username").textContent = state.user.username;
  $("sidebar-role").textContent = role.replaceAll("_", " ");
  $("sidebar-avatar").textContent = state.user.username.slice(0, 1).toUpperCase();
  $("team-nav").hidden = role !== "admin";
  $("source-register-panel").hidden = role !== "admin";
  $("team").classList.toggle("visible", role === "admin");
  $("run-detections").hidden = role === "read_only";
  $("signout-button").hidden = false;
  $("sidebar-signout").hidden = false;
}
async function switchWorkspace(workspaceId) {
  const selected = state.workspaces.find((workspace) => workspace.id === workspaceId);
  if (!selected || selected.id === state.workspaceId) return;
  state.workspaceId = selected.id;
  localStorage.setItem("aegis_workspace_id", selected.id);
  renderWorkspaceSwitcher();
  try {
    state.user = await api("/api/v1/auth/me");
    applyCurrentUser();
    await refreshDashboard();
    await refreshUsers();
    showToast("Switched to " + selected.name + ".");
  } catch (error) {
    showToast(error.message, "error");
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
    state.workspaces = await api("/api/v1/workspaces");
    const savedWorkspaceId = localStorage.getItem("aegis_workspace_id");
    const selected = state.workspaces.find((item) => item.id === savedWorkspaceId) ||
      state.workspaces.find((item) => item.slug === "default") || state.workspaces[0];
    if (!selected) throw new Error("Your account is not a member of an active AegisSOC workspace. Ask an administrator for access.");
    state.workspaceId = selected.id;
    localStorage.setItem("aegis_workspace_id", selected.id);
    renderWorkspaceSwitcher();
    state.user = await api("/api/v1/auth/me");
    $("auth-overlay").classList.add("hidden");
    applyCurrentUser();
    await refreshDashboard();
    await refreshUsers();
  } catch (error) {
    if (state.token && error.message.includes("401")) clearSession();
    showAuth(error.message || "Your session could not be validated. Please sign in again.");
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

function renderOperations() {
  const metrics = state.operationsMetrics || {};
  const health = state.operationsHealth || {};
  $("ops-events-hour").textContent = count(metrics.events?.last_hour);
  $("ops-events-day").textContent = count(metrics.events?.last_24_hours);
  $("ops-detection-failures").textContent = count(metrics.detection_executions?.failed_last_24_hours);
  $("ops-ingest-rejected").textContent = count(metrics.ingestion?.rejected_total);
  $("ops-schedules-overdue").textContent = count(health.enabled_schedules_overdue);
  const status = health.status || "unknown";
  $("operations-status").textContent = status.replaceAll("_", " ");
  $("operations-status").className = "data-chip " + (status === "operational" ? "status-healthy" : "status-warning");
  $("run-retention").hidden = currentRole() !== "admin";
  const admin = currentRole() === "admin";
  $("retention-policies").innerHTML = state.retentionPolicies.length
    ? state.retentionPolicies.map((policy) => {
      const editable = admin
        ? '<input class="retention-days" id="retention-days-' + esc(policy.data_kind) + '" type="number" min="1" max="3650" value="' + esc(policy.retention_days) + '">' +
          '<label class="retention-toggle"><input id="retention-enabled-' + esc(policy.data_kind) + '" type="checkbox" ' + (policy.enabled ? "checked" : "") + '> Enabled</label>' +
          (policy.data_kind === "events" ? '<label class="retention-toggle"><input id="retention-preserve-' + esc(policy.data_kind) + '" type="checkbox" ' + (policy.preserve_active_evidence ? "checked" : "") + '> Preserve active evidence</label>' : "") +
          '<button class="button button-secondary" type="button" data-retention-save="' + esc(policy.data_kind) + '">Save policy</button>'
        : '<strong>' + count(policy.retention_days) + ' days</strong><span>' + (policy.enabled ? "Enabled" : "Disabled") + '</span>';
      return '<div class="retention-row"><div class="retention-row-head"><strong>' + esc(policy.data_kind) + '</strong><small>Updated by ' + esc(policy.updated_by) + ' · ' + esc(date(policy.updated_at)) + '</small></div><div class="retention-controls">' + editable + '</div></div>';
    }).join("")
    : '<div class="source-empty">No retention policies are configured.</div>';
  $("job-count").textContent = count(state.operationJobs.length) + " runs";
  $("operations-jobs").innerHTML = state.operationJobs.length
    ? state.operationJobs.slice(0, 10).map((job) =>
      '<div class="operation-job"><span class="source-state ' + (job.status === "success" ? "healthy" : "failing") + '">' + esc(job.status) + '</span><div><strong>' + esc(job.job_name) + '</strong><small>' + esc(date(job.completed_at)) + ' · ' + count(job.records_affected) + ' rows</small></div><span class="job-error">' + esc(job.error_type || "—") + '</span></div>'
    ).join("")
    : '<div class="source-empty">No maintenance jobs have run yet.</div>';
}

function renderConnectors() {
  const admin = currentRole() === "admin";
  $("connector-create-panel").hidden = !admin;
  $("connector-count").textContent = count(state.connectors.length) + " connectors";
  $("connector-list").innerHTML = state.connectors.length
    ? state.connectors.map((connector) => {
      const config = connector.config || {};
      const stateClass = connector.health_status === "misconfigured" || connector.health_status === "degraded"
        ? "failing" : connector.health_status === "disabled" ? "inactive"
          : connector.health_status === "observed" ? "healthy" : "stale";
      const settings = [
        config.endpoint ? "Endpoint: " + config.endpoint : "",
        config.interval_seconds ? "Poll interval: " + config.interval_seconds + "s" : "",
        config.page_size ? "Page size: " + config.page_size : "",
        config.lookback ? "Lookback: " + config.lookback : "",
      ].filter(Boolean).join(" · ");
      const pollHistory = connector.last_success_at
        ? "Last successful poll: " + date(connector.last_success_at)
        : "No successful poll recorded";
      const checked = connector.last_checked_at
        ? "Last checked: " + date(connector.last_checked_at)
        : "Not checked yet";
      return '<article class="connector-row"><div class="connector-identity"><span class="connector-mark">' +
        esc(connector.connector_type.slice(0, 2).toUpperCase()) + '</span><div><strong>' +
        esc(connector.display_name) + '</strong><small>' + esc(connector.connector_key) + ' · ' +
        esc(connector.connector_type) + '</small></div></div><span class="source-state ' + stateClass + '">' +
        esc(connector.health_status) + '</span><div class="connector-config-summary"><span>' +
        esc(settings || "No additional settings") + '</span><small>' + esc(pollHistory) + ' · ' +
        esc(checked) + '</small><small>Credential reference: ' +
        esc(connector.credential_ref || "Not configured") + '</small></div><div class="connector-actions">' +
        (admin ? '<button class="button button-quiet" type="button" data-connector-check="' + esc(connector.id) +
        '">Validate settings</button><button class="button button-quiet schedule-delete" type="button" data-connector-delete="' +
        esc(connector.id) + '">Delete</button>' : "") + '</div></article>';
    }).join("")
    : '<div class="source-empty">No connectors registered. Add an integration to connect an external source.</div>';
}
async function saveRetentionPolicy(kind) {
  const button = document.querySelector('[data-retention-save="' + CSS.escape(kind) + '"]');
  if (!button) return;
  button.disabled = true;
  try {
    const payload = {
      retention_days: Number($("retention-days-" + kind).value),
      enabled: $("retention-enabled-" + kind).checked,
      preserve_active_evidence: kind === "events"
        ? $("retention-preserve-" + kind).checked
        : (state.retentionPolicies.find((policy) => policy.data_kind === kind)?.preserve_active_evidence ?? false),
    };
    await api("/api/v1/operations/retention/" + encodeURIComponent(kind), {
      method: "PUT", body: JSON.stringify(payload),
    });
    showToast("Retention policy updated and audit logged.");
    await refreshDashboard();
  } catch (error) {
    showToast(error.message, "error");
  } finally {
    if (button.isConnected) button.disabled = false;
  }
}

async function runRetentionNow() {
  const button = $("run-retention");
  button.disabled = true;
  try {
    const result = await api("/api/v1/operations/retention/run", { method: "POST" });
    showToast("Retention completed · " + count(result.records_affected) + " records removed.");
    await refreshDashboard();
  } catch (error) {
    showToast(error.message, "error");
  } finally {
    button.disabled = false;
  }
}

async function createConnector(event) {
  event.preventDefault();
  const button = $("connector-create-button");
  const feedback = $("connector-feedback");
  button.disabled = true;
  feedback.textContent = "Validating adapter configuration…";
  try {
    const config = JSON.parse($("connector-config").value || "{}");
    await api("/api/v1/connectors", {
      method: "POST",
      body: JSON.stringify({
        connector_key: $("connector-key").value.trim(),
        display_name: $("connector-display-name").value.trim(),
        connector_type: $("connector-type").value,
        credential_ref: $("connector-credential-ref").value.trim() || null,
        config,
        enabled: true,
      }),
    });
    $("connector-create-form").reset();
    feedback.textContent = "Connector registered. Configure the producer to ingest using this connector key.";
    showToast("Integration registered.");
    await refreshDashboard();
  } catch (error) {
    feedback.textContent = error instanceof SyntaxError ? "Configuration must be valid JSON." : error.message;
    showToast(feedback.textContent, "error");
  } finally {
    button.disabled = false;
  }
}

async function handleConnectorAction(event) {
  const check = event.target.closest("[data-connector-check]");
  const remove = event.target.closest("[data-connector-delete]");
  try {
    if (check) {
      const result = await api("/api/v1/connectors/" + encodeURIComponent(check.dataset.connectorCheck) + "/check", { method: "POST" });
      showToast(result.message, result.configuration_valid ? "success" : "error");
      await refreshDashboard();
    } else if (remove && window.confirm("Delete this connector configuration? Source event history will not be deleted.")) {
      await api("/api/v1/connectors/" + encodeURIComponent(remove.dataset.connectorDelete), { method: "DELETE" });
      showToast("Connector removed.");
      await refreshDashboard();
    }
  } catch (error) {
    showToast(error.message, "error");
  }
}


function renderCases() {
  const editable = currentRole() !== "read_only";
  $("case-create-toggle").hidden = !editable;
  $("case-count").textContent = count(state.cases.length) + " cases";
  $("case-list").innerHTML = state.cases.length ? state.cases.map((item) =>
    '<article class="case-row ' + (item.id === state.selectedCaseId ? "selected" : "") + '" data-case-id="' + esc(item.id) + '">' +
      '<div class="case-row-title"><strong>' + esc(item.title) + '</strong><small>' + esc(item.case_number) + ' · ' + esc(item.assignee || "Unassigned") + '</small></div>' +
      '<div class="case-row-meta">' + pill(item.priority, "status-") + pill(item.severity, "sev-") + '</div>' +
      '<div class="case-row-foot"><span>' + pill(item.status, "status-") + '</span><span>Updated ' + esc(date(item.updated_at)) + '</span></div>' +
    '</article>'
  ).join("") : '<div class="source-empty">No incident cases yet. Create a case to coordinate alerts and response activity.</div>';
}

async function selectCase(id) {
  state.selectedCaseId = id;
  renderCases();
  const panel = $("case-detail");
  panel.innerHTML = '<div class="table-empty">Loading case evidence and timeline…</div>';
  try {
    const item = await api("/api/v1/cases/" + encodeURIComponent(id));
    const editable = currentRole() !== "read_only";
    panel.innerHTML =
      '<div class="section-kicker">' + esc(item.case_number) + ' · INCIDENT RESPONSE</div>' +
      '<h3>' + esc(item.title) + '</h3>' +
      '<div class="case-detail-meta">Created by ' + esc(item.created_by) + ' · ' + esc(date(item.created_at)) + '</div>' +
      '<p class="detail-description">' + esc(item.description || "No case summary has been added.") + '</p>' +
      '<div class="case-detail-controls">' +
        '<label>Response status<select id="case-status" ' + (editable ? "" : "disabled") + '>' +
          ["open","investigating","contained","eradicated","recovered","closed"].map((v) => '<option value="' + v + '" ' + (item.status === v ? "selected" : "") + '>' + v.replaceAll("_"," ") + '</option>').join("") +
        '</select></label>' +
        '<label>Assignee<input id="case-assignee-edit" maxlength="120" value="' + esc(item.assignee || "") + '" placeholder="Unassigned" ' + (editable ? "" : "disabled") + '></label>' +
        '<label>Priority<select id="case-priority-edit" ' + (editable ? "" : "disabled") + '>' +
          ["p1","p2","p3","p4"].map((v) => '<option value="' + v + '" ' + (item.priority === v ? "selected" : "") + '>' + v.toUpperCase() + '</option>').join("") +
        '</select></label>' +
        '<label>Severity<select id="case-severity-edit" ' + (editable ? "" : "disabled") + '>' +
          ["critical","high","medium","low"].map((v) => '<option value="' + v + '" ' + (item.severity === v ? "selected" : "") + '>' + v + '</option>').join("") +
        '</select></label>' +
      '</div>' +
      (editable ? '<button class="button button-primary" type="button" data-case-save="' + esc(item.id) + '">Save case changes</button>' : "") +
      '<div class="subsection"><h4>LINKED ALERT EVIDENCE · ' + count(item.alerts.length) + '</h4>' +
        (item.alerts.length ? item.alerts.map((alert) =>
          '<div class="case-linked-alert"><div><strong>' + esc(alert.title) + '</strong><small>' + esc(alert.rule_id) + ' · ' + esc(alert.id) + '</small></div><div>' + pill(alert.severity, "sev-") +
          (editable ? '<button class="button button-quiet" type="button" data-case-unlink="' + esc(alert.id) + '" data-case-id="' + esc(item.id) + '">Remove</button>' : "") + '</div></div>'
        ).join("") : '<p class="detail-meta">No alerts linked to this case.</p>') +
        (editable ? '<div class="case-note-form"><input id="case-alert-id" placeholder="Alert UUID to link"><button class="button button-secondary" type="button" data-case-link="' + esc(item.id) + '">Link alert</button></div>' : "") +
      '</div>' +
      '<div class="subsection"><h4>ANALYST NOTES · ' + count(item.notes.length) + '</h4>' +
        (item.notes.length ? item.notes.map((note) => '<article class="case-note"><div class="case-note-head"><strong>' + esc(note.author) + '</strong><time>' + esc(date(note.created_at)) + '</time></div><p>' + esc(note.body) + '</p></article>').join("") : '<p class="detail-meta">No analyst notes recorded.</p>') +
        (editable ? '<form class="case-note-form" data-case-note="' + esc(item.id) + '"><textarea id="case-note-body" maxlength="10000" placeholder="Record investigation findings, containment actions or handoff context" required></textarea><button class="button button-secondary" type="submit">Add note</button></form>' : "") +
      '</div>' +
      '<div class="subsection"><h4>CASE TIMELINE</h4><div class="case-timeline">' +
        (item.timeline.length ? item.timeline.map((entry) => '<div class="case-timeline-item"><strong>' + esc(entry.action.replaceAll("."," · ")) + '</strong><small>' + esc(entry.actor) + ' · ' + esc(date(entry.occurred_at)) + '</small></div>').join("") : '<span class="detail-meta">No activity recorded.</span>') +
      '</div></div>';
  } catch (error) {
    panel.innerHTML = '<div class="investigation-empty"><h3>Unable to load case</h3><p>' + esc(error.message) + '</p></div>';
  }
}

async function createCase(event) {
  event.preventDefault();
  const button = $("case-create-button");
  button.disabled = true;
  try {
    const item = await api("/api/v1/cases", {
      method: "POST",
      body: JSON.stringify({
        title: $("case-title").value.trim(),
        description: $("case-description").value.trim(),
        priority: $("case-priority").value,
        severity: $("case-severity").value,
        assignee: $("case-assignee").value.trim() || null,
      }),
    });
    $("case-create-form").reset();
    $("case-create-form").hidden = true;
    showToast("Incident case " + item.case_number + " created.");
    await refreshDashboard();
    await selectCase(item.id);
  } catch (error) {
    $("case-create-feedback").textContent = error.message;
  } finally {
    button.disabled = false;
  }
}

async function handleCaseDetailClick(event) {
  const save = event.target.closest("[data-case-save]");
  const link = event.target.closest("[data-case-link]");
  const unlink = event.target.closest("[data-case-unlink]");
  try {
    if (save) {
      await api("/api/v1/cases/" + encodeURIComponent(save.dataset.caseSave), {
        method: "PATCH",
        body: JSON.stringify({
          status: $("case-status").value,
          assignee: $("case-assignee-edit").value.trim() || null,
          priority: $("case-priority-edit").value,
          severity: $("case-severity-edit").value,
        }),
      });
      showToast("Case updated and audit logged.");
      await refreshDashboard();
      await selectCase(save.dataset.caseSave);
    } else if (link) {
      const alertId = $("case-alert-id").value.trim();
      await api("/api/v1/cases/" + encodeURIComponent(link.dataset.caseLink) + "/alerts/" + encodeURIComponent(alertId), { method: "POST" });
      showToast("Alert evidence linked to case.");
      await refreshDashboard();
      await selectCase(link.dataset.caseLink);
    } else if (unlink) {
      await api("/api/v1/cases/" + encodeURIComponent(unlink.dataset.caseId) + "/alerts/" + encodeURIComponent(unlink.dataset.caseUnlink), { method: "DELETE" });
      showToast("Alert unlinked from case.");
      await refreshDashboard();
      await selectCase(unlink.dataset.caseId);
    }
  } catch (error) {
    showToast(error.message, "error");
  }
}

async function addCaseNote(event) {
  const form = event.target.closest("[data-case-note]");
  if (!form) return;
  event.preventDefault();
  try {
    await api("/api/v1/cases/" + encodeURIComponent(form.dataset.caseNote) + "/notes", {
      method: "POST", body: JSON.stringify({ body: $("case-note-body").value }),
    });
    showToast("Case note added to the audit timeline.");
    await refreshDashboard();
    await selectCase(form.dataset.caseNote);
  } catch (error) {
    showToast(error.message, "error");
  }
}

function renderDetectionRules() {
  const admin = currentRole() === "admin";
  $("rule-count").textContent = count(state.detectionRules.length) + " rules";
  $("detection-rule-list").innerHTML = state.detectionRules.length ? state.detectionRules.map((rule) =>
    '<article class="detection-rule-card">' +
      '<div class="detection-rule-head"><div><strong>' + esc(rule.title) + '</strong><span class="detection-rule-id">' + esc(rule.rule_id) + '</span></div>' + pill(rule.enabled ? "enabled" : "disabled", rule.enabled ? "status-resolved" : "status-open") + '</div>' +
      '<p>' + esc(rule.description) + '</p>' +
      '<div class="detection-rule-meta"><span>' + esc(rule.attack_tactic) + '</span><span>' + esc(rule.attack_technique_id) + ' · ' + esc(rule.attack_technique_name) + '</span></div>' +
      (admin ? '<div class="detection-rule-controls">' +
        '<label class="rule-enabled"><input id="rule-enabled-' + esc(rule.rule_id) + '" type="checkbox" ' + (rule.enabled ? "checked" : "") + '> Enabled</label>' +
        '<label>Threshold<input id="rule-threshold-' + esc(rule.rule_id) + '" type="number" min="2" max="100" placeholder="Default" value="' + esc(rule.threshold_override ?? "") + '"></label>' +
        '<label>Severity<select id="rule-severity-' + esc(rule.rule_id) + '"><option value="">Rule default</option>' + ["info","low","medium","high","critical"].map((v) => '<option value="' + v + '" ' + (rule.severity_override === v ? "selected" : "") + '>' + v + '</option>').join("") + '</select></label>' +
        '<button class="button button-secondary" type="button" data-rule-save="' + esc(rule.rule_id) + '">Save</button>' +
      '</div>' : "") +
      '<div class="case-detail-meta">Updated by ' + esc(rule.updated_by) + ' · ' + esc(date(rule.updated_at)) + '</div>' +
    '</article>'
  ).join("") : '<div class="source-empty">No detection rules are registered.</div>';
}

async function saveDetectionRule(ruleId) {
  const button = document.querySelector('[data-rule-save="' + CSS.escape(ruleId) + '"]');
  if (!button) return;
  button.disabled = true;
  try {
    const rawThreshold = $("rule-threshold-" + ruleId).value.trim();
    await api("/api/v1/detection-rules/" + encodeURIComponent(ruleId), {
      method: "PATCH",
      body: JSON.stringify({
        enabled: $("rule-enabled-" + ruleId).checked,
        threshold_override: rawThreshold ? Number(rawThreshold) : null,
        severity_override: $("rule-severity-" + ruleId).value || null,
      }),
    });
    showToast("Detection rule updated and audit logged.");
    await refreshDashboard();
  } catch (error) {
    showToast(error.message, "error");
  } finally {
    if (button.isConnected) button.disabled = false;
  }
}

function renderThreatIntel() {
  $("indicator-form").hidden = currentRole() === "read_only";
  $("indicator-count").textContent = count(state.indicators.length) + " indicators";
  $("indicator-match-count").textContent = count(state.indicatorMatches.length) + " matches";
  $("indicator-list").innerHTML = state.indicators.length ? state.indicators.map((item) =>
    '<article class="indicator-row"><div><div class="indicator-value">' + esc(item.value) + '</div>' +
    '<div class="indicator-meta">' + esc(item.indicator_type.toUpperCase()) + ' · ' + esc(item.source) +
    ' · Confidence ' + count(item.confidence) + '% · ' + esc(item.severity) + ' · ' + esc(item.status) +
    (item.expires_at ? ' · Expires ' + esc(date(item.expires_at)) : '') + '</div></div>' +
    '<div class="indicator-actions">' + pill(item.status, item.status === "active" ? "status-resolved" : "status-open") +
    (item.status === "active" && currentRole() !== "read_only" ? '<button class="button button-quiet" type="button" data-indicator-revoke="' + esc(item.id) + '">Revoke</button>' : '') +
    '</div></article>'
  ).join("") : '<div class="source-empty">No indicators registered. Add an IP, domain or file hash to begin building a local intelligence set.</div>';
  $("indicator-matches").innerHTML = state.indicatorMatches.length ? state.indicatorMatches.slice(0, 20).map((match) =>
    '<div class="match-row"><strong class="indicator-value">' + esc(match.indicator.value) + '</strong> · ' +
    esc(match.indicator.severity) + ' · ' + esc(match.event_source) + ' / ' + esc(match.event_type) +
    '<div class="indicator-meta">Evidence event ' + esc(match.event_id) + ' · ' + esc(date(match.event_timestamp)) + '</div></div>'
  ).join("") : '<div class="source-empty">No active indicators matched the latest 5,000 events.</div>';
}
function renderEntities() {
  const kind = $("entity-type").value;
  const query = $("entity-search").value.trim().toLowerCase();
  const rows = state.entities.filter((item) => (!kind || item.entity_type === kind) && (!query || item.value.toLowerCase().includes(query)));
  $("entity-count").textContent = count(rows.length) + " entities";
  $("entities-body").innerHTML = rows.length ? rows.map((item) =>
    '<tr><td><span class="entity-type">' + esc(item.entity_type) + '</span></td><td><strong class="indicator-value">' + esc(item.value) + '</strong></td>' +
    '<td>' + count(item.event_count) + '</td><td>' + count(item.alert_count) + '</td><td>' + count(item.source_count) +
    '<div class="sub-cell">' + esc(item.sources.join(", ")) + '</div></td><td>' + esc(date(item.last_seen)) + '</td></tr>'
  ).join("") : '<tr><td colspan="6" class="table-empty">No correlated entities match these filters. The correlation view considers the latest 30 days of normalized telemetry.</td></tr>';
}
async function createIndicator(event) {
  event.preventDefault();
  const button = $("indicator-submit");
  const feedback = $("indicator-feedback");
  button.disabled = true;
  feedback.textContent = "Validating indicator…";
  try {
    await api("/api/v1/threat-intel/indicators", { method: "POST", body: JSON.stringify({
      indicator_type: $("indicator-type").value,
      value: $("indicator-value").value.trim(),
      confidence: Number($("indicator-confidence").value),
      severity: $("indicator-severity").value,
      source: $("indicator-source").value.trim(),
      description: $("indicator-description").value.trim(),
    }) });
    $("indicator-form").reset();
    $("indicator-confidence").value = "70";
    feedback.textContent = "Indicator stored and audit logged.";
    showToast("Threat indicator added.");
    await refreshDashboard();
  } catch (error) {
    feedback.textContent = error.message;
    showToast(error.message, "error");
  } finally { button.disabled = false; }
}
async function handleIndicatorAction(event) {
  const button = event.target.closest("[data-indicator-revoke]");
  if (!button) return;
  button.disabled = true;
  try {
    await api("/api/v1/threat-intel/indicators/" + encodeURIComponent(button.dataset.indicatorRevoke), {
      method: "PATCH", body: JSON.stringify({ status: "revoked" }),
    });
    showToast("Indicator revoked. Historical record retained.");
    await refreshDashboard();
  } catch (error) { showToast(error.message, "error"); }
}
async function refreshEntities() {
  const button = $("refresh-entities");
  button.disabled = true;
  try {
    const type = $("entity-type").value;
    const query = new URLSearchParams({ min_events: "1", limit: "200" });
    if (type) query.set("type", type);
    state.entities = await api("/api/v1/threat-intel/entities?" + query.toString());
    renderEntities();
    showToast("Cross-source entity pivots refreshed.");
  } catch (error) { showToast(error.message, "error"); }
  finally { button.disabled = false; }
}


function renderAssetRisk() {
  const rows = state.assets || [];
  $("asset-count").textContent = count(rows.length) + " assets";
  $("assets-body").innerHTML = rows.length ? rows.map((asset) =>
    '<tr><td><button class="text-link" type="button" data-asset-select="' + esc(asset.id) + '">' +
    '<strong>' + esc(asset.hostname) + '</strong><div class="sub-cell">' + esc(asset.asset_key) + '</div></button></td>' +
    '<td>' + esc(asset.environment) + '</td><td>' + pill(asset.criticality, "sev-") + '</td>' +
    '<td>' + esc(asset.owner || "Unassigned") + '</td><td>' + pill(asset.status, "status-") + '</td></tr>'
  ).join("") : '<tr><td colspan="5" class="table-empty">No managed assets registered yet.</td></tr>';
  const options = '<option value="">Select managed asset…</option>' + rows.map((a) =>
    '<option value="' + esc(a.id) + '">' + esc(a.asset_key + " · " + a.hostname) + '</option>').join("");
  $("finding-asset").innerHTML = options;
  $("playbook-case").innerHTML = '<option value="">No linked case</option>' + state.cases.map((item) =>
    '<option value="' + esc(item.id) + '">' + esc(item.case_number + " · " + item.title) + '</option>').join("");
}
async function loadAssetFindings(assetId) {
  try {
    const rows = await api("/api/v1/asset-risk/assets/" + encodeURIComponent(assetId) + "/findings");
    state.findings = rows;
    $("finding-list").innerHTML = rows.length ? rows.map((item) =>
      '<div class="finding-row"><div><strong>' + esc(item.vulnerability_id) + ' · ' + esc(item.title) + '</strong>' +
      '<small>' + esc(item.source) + ' · Discovered ' + esc(date(item.discovered_at)) + '</small></div>' +
      '<div class="finding-actions">' + pill(item.severity, "sev-") + pill(item.status, "status-") +
      (item.status === "open" || item.status === "in_progress" ? '<button class="button button-secondary" data-finding-status="' + esc(item.id) + '" data-next-status="remediated" type="button">Mark remediated</button>' : '') +
      '</div></div>'
    ).join("") : '<div class="source-empty">No findings recorded for this asset.</div>';
  } catch (error) { showToast(error.message, "error"); }
}
function renderPlaybooks() {
  const rows = state.playbooks || [];
  $("playbook-count").textContent = count(rows.length) + " runs";
  $("playbook-list").innerHTML = rows.length ? rows.map((run) =>
    '<article class="playbook-run"><div class="playbook-run-head"><div><strong>' + esc(run.title) + '</strong><small>' +
    esc(run.case_id ? "Linked case " + run.case_id : "Standalone run") + ' · ' + esc(run.created_by) + '</small></div>' +
    pill(run.status, "status-") + '</div><ol>' + run.steps.map((step, index) =>
      '<li class="' + (step.completed ? 'step-complete' : '') + '"><span>' + esc(step.title) + (step.required ? ' <em>Required</em>' : ' <em>Optional</em>') + '</span>' +
      '<button class="button button-secondary" type="button" data-playbook-run="' + esc(run.id) + '" data-step-index="' + index + '" data-completed="' + (!step.completed) + '">' +
      (step.completed ? "Reopen" : "Complete") + '</button></li>'
    ).join("") + '</ol></article>'
  ).join("") : '<div class="source-empty">No playbook runs yet. Start one from the checklist above.</div>';
}
async function createAsset(event) {
  event.preventDefault();
  const feedback = $("asset-feedback");
  try {
    await api("/api/v1/asset-risk/assets", { method: "POST", body: JSON.stringify({
      asset_key: $("asset-key").value.trim(), hostname: $("asset-hostname").value.trim(),
      environment: $("asset-environment").value, criticality: $("asset-criticality").value,
      owner: $("asset-owner").value.trim() || null,
    }) });
    $("asset-form").reset();
    feedback.textContent = "Asset registered and audit logged.";
    await refreshDashboard();
  } catch (error) { feedback.textContent = error.message; showToast(error.message, "error"); }
}
async function createFinding(event) {
  event.preventDefault();
  const assetId = $("finding-asset").value;
  if (!assetId) return;
  try {
    await api("/api/v1/asset-risk/assets/" + encodeURIComponent(assetId) + "/findings", { method: "POST", body: JSON.stringify({
      vulnerability_id: $("finding-id").value.trim(), title: $("finding-title").value.trim(),
      severity: $("finding-severity").value, source: $("finding-source").value.trim(),
    }) });
    $("finding-form").reset();
    $("finding-asset").value = assetId;
    await loadAssetFindings(assetId);
    showToast("Vulnerability finding recorded.");
  } catch (error) { showToast(error.message, "error"); }
}
async function createPlaybook(event) {
  event.preventDefault();
  const steps = $("playbook-steps").value.split(/\r?\n/).map((title) => title.trim()).filter(Boolean);
  try {
    await api("/api/v1/asset-risk/playbooks", { method: "POST", body: JSON.stringify({
      title: $("playbook-title").value.trim(), case_id: $("playbook-case").value || null,
      steps: steps.map((title) => ({ title, required: true })),
    }) });
    $("playbook-form").reset();
    $("playbook-feedback").textContent = "Playbook started. Each step is recorded as an auditable analyst action.";
    await refreshDashboard();
    showToast("Response playbook started.");
  } catch (error) { $("playbook-feedback").textContent = error.message; showToast(error.message, "error"); }
}
async function handleAssetRiskAction(event) {
  const asset = event.target.closest("[data-asset-select]");
  if (asset) {
    $("finding-asset").value = asset.dataset.assetSelect;
    await loadAssetFindings(asset.dataset.assetSelect);
    return;
  }
  const finding = event.target.closest("[data-finding-status]");
  if (finding) {
    try {
      await api("/api/v1/asset-risk/findings/" + encodeURIComponent(finding.dataset.findingStatus), {
        method: "PATCH", body: JSON.stringify({ status: finding.dataset.nextStatus }),
      });
      await loadAssetFindings($("finding-asset").value);
      showToast("Vulnerability status updated.");
    } catch (error) { showToast(error.message, "error"); }
  }
}
async function handlePlaybookAction(event) {
  const button = event.target.closest("[data-playbook-run]");
  if (!button) return;
  button.disabled = true;
  try {
    await api("/api/v1/asset-risk/playbooks/" + encodeURIComponent(button.dataset.playbookRun) +
      "/steps/" + button.dataset.stepIndex, {
        method: "PATCH", body: JSON.stringify({ completed: button.dataset.completed === "true" }),
      });
    state.playbooks = await api("/api/v1/asset-risk/playbooks?limit=100");
    renderPlaybooks();
    showToast("Playbook checklist updated and audit logged.");
  } catch (error) { showToast(error.message, "error"); button.disabled = false; }
}

function setActiveNav() {
  const current = location.hash.replace("#", "") || "overview";
  document.querySelectorAll("[data-nav]").forEach((link) => {
    link.classList.toggle("active", link.dataset.nav === current);
  });
  $("page-breadcrumb").textContent = current === "team" ? "Team & access" :
    current === "alerts" ? "Alert queue" : current === "events" ? "Event telemetry" :
    current === "sources" ? "Data source health" : current === "operations" ? "Operational health" :
    current === "connectors" ? "Integration registry" : current === "schedules" ? "Detection schedules" :
    current === "cases" ? "Incident cases" : current === "detection-rules" ? "Detection rule library" :
    current === "audit" ? "Security audit trail" : current === "threat-intel" ? "Threat intelligence" : current === "entity-correlation" ? "Entity correlation" : current === "asset-risk" ? "Asset risk" : current === "response-playbooks" ? "Response playbooks" : "Overview";
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
$("schedule-create-form").addEventListener("submit", createDetectionSchedule);
$("schedules-grid").addEventListener("click", handleScheduleAction);
$("schedule-history").addEventListener("click", handleScheduleAction);
$("verify-audit").addEventListener("click", verifyAuditChain);
$("run-retention").addEventListener("click", runRetentionNow);
$("retention-policies").addEventListener("click", (event) => {
  const button = event.target.closest("[data-retention-save]");
  if (button) saveRetentionPolicy(button.dataset.retentionSave);
});
$("connector-create-form").addEventListener("submit", createConnector);
$("connector-list").addEventListener("click", handleConnectorAction);
$("case-create-toggle").addEventListener("click", () => { $("case-create-form").hidden = !$("case-create-form").hidden; });
$("case-create-form").addEventListener("submit", createCase);
$("case-list").addEventListener("click", (event) => {
  const row = event.target.closest("[data-case-id]");
  if (row) selectCase(row.dataset.caseId);
});
$("case-detail").addEventListener("click", handleCaseDetailClick);
$("case-detail").addEventListener("submit", addCaseNote);
$("indicator-form").addEventListener("submit", createIndicator);
$("asset-form").addEventListener("submit", createAsset);
$("finding-form").addEventListener("submit", createFinding);
$("playbook-form").addEventListener("submit", createPlaybook);
$("asset-inventory").addEventListener("click", handleAssetRiskAction);
$("finding-list").addEventListener("click", handleAssetRiskAction);
$("playbook-list").addEventListener("click", handlePlaybookAction);
$("refresh-assets").addEventListener("click", refreshDashboard);
$("finding-asset").addEventListener("change", () => { if ($("finding-asset").value) loadAssetFindings($("finding-asset").value); });
$("indicator-list").addEventListener("click", handleIndicatorAction);
$("refresh-intel").addEventListener("click", refreshDashboard);
$("refresh-entities").addEventListener("click", refreshEntities);
$("entity-type").addEventListener("change", refreshEntities);
$("entity-search").addEventListener("input", renderEntities);
$("detection-rule-list").addEventListener("click", (event) => {
  const button = event.target.closest("[data-rule-save]");
  if (button) saveDetectionRule(button.dataset.ruleSave);
});
$("connector-type").addEventListener("change", () => {
  const examples = {
    wazuh: '{ "manager_url": "https://wazuh.example.internal" }',
    wazuh_manager: '{ "endpoint": "https://wazuh.example.internal/security/events", "allowed_hosts": ["wazuh.example.internal"], "interval_seconds": 60 }',
    wazuh_indexer: '{ "endpoint": "https://indexer.example.internal:9200/wazuh-alerts-*/_search", "allowed_hosts": ["indexer.example.internal"], "auth_scheme": "basic", "page_size": 500, "lookback": "now-7d", "interval_seconds": 60 }',
    misp: '{ "endpoint": "https://misp.example.internal/attributes/restSearch", "allowed_hosts": ["misp.example.internal"], "auth_header": "X-MISP-Auth", "page_size": 1000, "interval_seconds": 300 }',
    opencti: '{ "endpoint": "https://opencti.example.internal/graphql", "allowed_hosts": ["opencti.example.internal"], "interval_seconds": 300 }',
    response_webhook: '{ "endpoint": "https://response.example.internal/actions", "allowed_hosts": ["response.example.internal"] }',
    syslog: '{ "host": "syslog.example.internal", "port": 514, "transport": "udp" }',
    http_event: '{ "ingest_path": "/api/v1/events/ingest" }',
    generic: "{}",
  };
  $("connector-config").value = examples[$("connector-type").value] || "{}";
});
$("run-event-query").addEventListener("click", () => runEventQuery());
$("reset-event-query").addEventListener("click", () => {
  $("event-query-text").value = "";
  $("event-query-severity").value = "";
  $("event-query-source").value = "";
  $("event-query-time").value = "24";
  $("event-query-group").value = "";
  state.queryResult = null;
  state.pendingSavedQuery = null;
  $("query-feedback").textContent = "Showing the latest event activity.";
  renderEvents();
});
$("save-event-query").addEventListener("click", saveEventQuery);
$("saved-query-select").addEventListener("change", loadSavedQuery);
$("event-query-text").addEventListener("keydown", (event) => {
  if (event.key === "Enter") runEventQuery();
});

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
$("workspace-select").addEventListener("change", (event) => switchWorkspace(event.target.value));
$("oidc-login-button").addEventListener("click", () => {
  window.location.assign("/api/v1/auth/oidc/login");
});
async function loadAuthMethods() {
  try {
    const methods = await api("/api/v1/auth/methods");
    $("oidc-login-button").hidden = !methods.oidc_enabled;
  } catch (_) {
    $("oidc-login-button").hidden = true;
  }
}
window.addEventListener("hashchange", setActiveNav);
setActiveNav();
loadAuthMethods();
bootstrap();
window.setInterval(() => { if (state.token) refreshDashboard(); }, 60000);
