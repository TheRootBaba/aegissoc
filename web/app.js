const $ = (id) => document.getElementById(id);
const state = { alerts: [], events: [], eventStats: {}, alertStats: {}, selectedId: null, token: null, user: null };
const esc = (value) => String(value ?? "—").replace(/[&<>"']/g, (char) => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[char]));
const date = (value) => value ? new Date(value).toLocaleString() : "—";
const pill = (value, prefix="") => '<span class="pill '+prefix+esc(value)+'">'+esc(String(value).replaceAll("_"," "))+'</span>';
async function api(path, options={}) {
  const response = await fetch(path, {headers:{"Content-Type":"application/json",...(state.token?{Authorization:"Bearer "+state.token}:{}),...(options.headers||{})},...options});
  const body = response.status === 204 ? null : await response.json().catch(()=>null);
  if (!response.ok) throw new Error(body?.detail || response.statusText || "Request failed");
  return body;
}
function toast(message) { const el=$("toast"); el.textContent=message; el.classList.add("show"); setTimeout(()=>el.classList.remove("show"),2800); }
function renderMetrics() {
  const open=state.alertStats.by_status?.open||0;
  const high=(state.alertStats.by_severity?.high||0)+(state.alertStats.by_severity?.critical||0);
  const progress=(state.alertStats.by_status?.acknowledged||0)+(state.alertStats.by_status?.in_progress||0);
  $("metric-open").textContent=open; $("metric-high").textContent=high;
  $("metric-events").textContent=state.eventStats.total_events??state.events.length; $("metric-progress").textContent=progress;
  $("nav-alert-count").textContent=open; $("alert-count").textContent=(state.alertStats.total_alerts??state.alerts.length)+" alerts";
  $("event-count").textContent=state.events.length+" events";
}
function renderAlerts() {
  const filter=$("severity-filter").value;
  const attack=$("attack-filter").value;
  const rows=state.alerts.filter(a=>(!filter||a.severity===filter)&&(!attack||a.attack_technique_id===attack));
  $("alerts-body").innerHTML=rows.length?rows.map(a=>'<tr class="alert-row '+(a.id===state.selectedId?"selected":"")+'" data-id="'+esc(a.id)+'"><td><div class="title-cell">'+esc(a.title)+'</div><div class="sub-cell">'+esc(a.rule_id)+' · '+esc(a.attack_technique_id||"Unmapped")+' · '+esc(a.hostname)+'</div></td><td>'+pill(a.severity,"sev-")+'</td><td>'+pill(a.status,"status-")+'</td><td>'+esc(a.source_ip)+'</td><td>'+esc(date(a.last_seen))+'</td></tr>').join(""):'<tr><td colspan="5" class="empty">No alerts match this filter.</td></tr>';
  document.querySelectorAll(".alert-row").forEach(row=>row.addEventListener("click",()=>selectAlert(row.dataset.id)));
}
function renderEvents() {
  $("events-body").innerHTML=state.events.length?state.events.slice(0,25).map(e=>'<tr><td><div class="title-cell">'+esc(e.event_type)+'</div><div class="sub-cell">'+esc(e.source)+'</div></td><td>'+pill(e.severity,"sev-")+'</td><td>'+esc(e.hostname)+'</td><td>'+esc(e.source_ip)+'</td><td>'+esc(date(e.timestamp))+'</td></tr>').join(""):'<tr><td colspan="5" class="empty">No events ingested yet.</td></tr>';
}
async function refresh() {
  try {
    const [alerts,events,eventStats,alertStats]=await Promise.all([api("/api/v1/alerts?limit=200"),api("/api/v1/events?limit=25"),api("/api/v1/events/stats"),api("/api/v1/alerts/stats")]);
    state.alerts=alerts; state.events=events; state.eventStats=eventStats; state.alertStats=alertStats;
    $("health-pill").classList.remove("offline"); $("health-pill").innerHTML="<i></i> API operational";
    renderMetrics();renderAlerts();renderEvents();
    if(state.selectedId && state.alerts.some(a=>a.id===state.selectedId)) await selectAlert(state.selectedId,false);
  } catch(error) {
    $("health-pill").classList.add("offline"); $("health-pill").textContent="● API unavailable"; toast(error.message);
  }
}
async function selectAlert(id,rerender=true) {
  state.selectedId=id; if(rerender)renderAlerts();
  const panel=$("detail-panel"); panel.innerHTML='<div class="empty">Loading investigation…</div>';
  try {
    const [a,notes,history]=await Promise.all([api("/api/v1/alerts/"+id),api("/api/v1/alerts/"+id+"/notes"),api("/api/v1/alerts/"+id+"/history")]);
    panel.innerHTML='<div class="detail-head"><div><div class="eyebrow">'+esc(a.rule_id)+'</div><h3>'+esc(a.title)+'</h3><div class="detail-meta">'+esc(a.id)+'</div></div>'+pill(a.severity,"sev-")+'</div>'+
      '<p class="detail-meta" style="line-height:1.7;margin-top:12px">'+esc(a.description)+'</p>'+
      '<div class="detail-grid"><div><label>SOURCE IP</label><strong>'+esc(a.source_ip)+'</strong></div><div><label>TARGET HOST</label><strong>'+esc(a.hostname)+'</strong></div><div><label>EVENT COUNT</label><strong>'+esc(a.event_count)+'</strong></div><div><label>USERNAMES</label><strong>'+esc(a.username)+'</strong></div><div><label>FIRST SEEN</label><strong>'+esc(date(a.first_seen))+'</strong></div><div><label>LAST SEEN</label><strong>'+esc(date(a.last_seen))+'</strong></div></div>'+
      '<div class="attack-card"><div class="eyebrow">MITRE ATT&amp;CK MAPPING</div><strong>'+esc(a.attack_technique_id||'Not mapped')+' · '+esc(a.attack_technique_name||'—')+'</strong><span>'+esc(a.attack_tactic||'No tactic assigned')+'</span>'+(a.attack_technique_id?'<a href="https://attack.mitre.org/techniques/'+encodeURIComponent(a.attack_technique_id)+'/" target="_blank" rel="noopener noreferrer">Open technique ↗</a>':'')+'</div>'+
      '<div class="field"><label class="form-label" for="status-input">WORKFLOW STATUS</label><select id="status-input"><option value="open">Open</option><option value="acknowledged">Acknowledged</option><option value="in_progress">In progress</option><option value="resolved">Resolved</option><option value="false_positive">False positive</option></select></div>'+
      '<div class="field"><label class="form-label" for="assignee-input">ASSIGNED ANALYST</label><input id="assignee-input" maxlength="120" placeholder="Unassigned" value="'+esc(a.assigned_to||"")+'"></div>'+
      '<div class="detail-meta">Analyst identity is verified by the API token.</div>'+
      '<div class="subsection"><h4>TRIGGERING EVIDENCE</h4><p class="detail-meta" style="line-height:1.7;word-break:break-all">'+esc(a.evidence_event_ids.join(" · "))+"</p></div>"+
      '<div class="detail-actions"><button class="button primary" id="save-alert">Save changes</button><span class="detail-meta">'+esc(a.status.replaceAll("_"," "))+'</span></div>'+
      '<div class="subsection"><h4>INVESTIGATION NOTES</h4><div id="notes-list">'+(notes.length?notes.map(n=>'<div class="note-item"><strong>'+esc(n.author)+'</strong><time> · '+esc(date(n.created_at))+'</time><p>'+esc(n.body)+'</p></div>').join(""):'<p class="detail-meta">No notes yet.</p>')+'</div>'+
      '<div class="field"><textarea id="note-input" maxlength="10000" placeholder="Record evidence, triage decisions, and investigation findings…"></textarea></div><button class="button secondary" id="add-note">Add investigation note</button></div>'+
      '<div class="subsection"><h4>AUDIT HISTORY</h4><div>'+(history.length?history.map(h=>'<div class="history-item"><strong>'+esc(h.action)+'</strong><time> · '+esc(h.actor)+' · '+esc(date(h.created_at))+'</time><p>'+esc(JSON.stringify(h.details))+'</p></div>').join(""):'<p class="detail-meta">No audit entries yet.</p>')+'</div></div>';
    $("status-input").value=a.status;
    $("save-alert").addEventListener("click",async()=>{
      try{await api("/api/v1/alerts/"+id,{method:"PATCH",body:JSON.stringify({status:$("status-input").value,assigned_to:$("assignee-input").value.trim()||null})});toast("Alert updated and audit recorded.");await refresh();}
      catch(error){toast(error.message);}
    });
    $("add-note").addEventListener("click",async()=>{
      try{await api("/api/v1/alerts/"+id+"/notes",{method:"POST",body:JSON.stringify({body:$("note-input").value})});toast("Investigation note saved.");await selectAlert(id);}
      catch(error){toast(error.message);}
    });
  } catch(error){panel.innerHTML='<div class="detail-empty"><h3>Could not load alert</h3><p>'+esc(error.message)+'</p></div>';}
}
$("refresh-button").addEventListener("click",refresh);
$("severity-filter").addEventListener("change",renderAlerts);
$("attack-filter").addEventListener("change",renderAlerts);
$("run-detections").addEventListener("click",async()=>{
  const button=$("run-detections");button.disabled=true;button.textContent="Running…";
  try{const result=await api("/api/v1/detections/run",{method:"POST",body:JSON.stringify({window_minutes:10,threshold:5})});toast("Detection run complete · "+result.alerts_created+" created · "+result.alerts_updated+" updated.");await refresh();}
  catch(error){toast(error.message);}
  finally{button.disabled=false;button.textContent="▶ Run detections";}
});
refresh();
