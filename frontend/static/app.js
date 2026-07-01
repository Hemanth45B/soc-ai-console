const state = { alerts: [], activeAlertId: null, statusFilter: "" };

const $ = (sel) => document.querySelector(sel);

async function api(path, opts = {}) {
  const res = await fetch(path, {
    headers: { "Content-Type": "application/json" },
    ...opts,
  });
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error(body.detail || `Request failed: ${res.status}`);
  }
  return res.json();
}

function escapeHtml(str) {
  return (str ?? "").toString()
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

// ---------- Logs ----------

async function refreshLogs(query = "") {
  const logs = await api(`/api/logs/search?q=${encodeURIComponent(query)}&limit=40`);
  $("#logList").innerHTML = logs.map(l => `
    <div class="log-item">
      <span class="log-meta">${escapeHtml(l.host || l.source_ip || "-")}</span>
      ${escapeHtml(l.raw_log)}
    </div>
  `).join("") || `<div class="empty-state">No logs yet. Ingest the sample dataset to get started.</div>`;
}

// ---------- Alerts ----------

function severityBadge(sev) {
  return `<span class="badge badge-${sev}">${sev}</span>`;
}

function statusPill(status) {
  const gate = status === "pending_human_review";
  return `<span class="status-pill ${gate ? "gate" : ""}">${status.replace(/_/g, " ")}</span>`;
}

async function refreshAlerts() {
  const q = state.statusFilter ? `?status=${state.statusFilter}` : "";
  state.alerts = await api(`/api/alerts${q}`);
  renderAlertList();
  await refreshStats();
}

function renderAlertList() {
  const list = $("#alertList");
  if (!state.alerts.length) {
    list.innerHTML = `<div class="empty-state">No alerts yet.</div>`;
    return;
  }
  list.innerHTML = state.alerts.map(a => `
    <div class="alert-card ${a.id === state.activeAlertId ? "active" : ""}" data-id="${a.id}">
      <div class="alert-card-top">
        ${severityBadge(a.severity)}
        ${statusPill(a.status)}
      </div>
      <div class="alert-title">${escapeHtml(a.title)}</div>
      <div class="alert-meta">#${a.id} · ${escapeHtml(a.rule_name || "manual")} · ${new Date(a.created_at).toLocaleString()}</div>
    </div>
  `).join("");

  list.querySelectorAll(".alert-card").forEach(card => {
    card.addEventListener("click", () => openAlert(Number(card.dataset.id)));
  });
}

async function refreshStats() {
  const stats = await api("/api/stats");
  $("#statLogs").textContent = stats.total_logs;
  $("#statAlerts").textContent = stats.total_alerts;
  $("#statPending").textContent = stats.by_status.pending_human_review || 0;
}

async function openAlert(id) {
  state.activeAlertId = id;
  renderAlertList();
  const alert = await api(`/api/alerts/${id}`);
  renderDetail(alert);
}

function renderDetail(a) {
  const panel = $("#detailPanel");
  const iocs = safeParseArray(a.ai_iocs);
  const gate = a.status === "pending_human_review";

  panel.innerHTML = `
    <div class="panel-head">
      <h2>Alert #${a.id}</h2>
      ${severityBadge(a.severity)}
    </div>
    <div class="detail-title">${escapeHtml(a.title)}</div>
    <div class="detail-desc">${escapeHtml(a.description || "")}</div>

    ${gate ? `
      <div class="gate-banner">
        <span class="gate-dot"></span>
        HUMAN REVIEW REQUIRED — severity or confidence crossed the auto-close threshold
      </div>
    ` : ""}

    ${a.ai_verdict ? `
      <div class="section-label">AI Verdict</div>
      <div>${severityBadge(verdictColor(a.ai_verdict))} <span style="font-family:var(--mono);font-size:12px;color:var(--text-dim)">${escapeHtml(a.ai_verdict)}</span></div>

      <div class="section-label">Confidence</div>
      <div class="confidence-row">
        <div class="confidence-bar-track"><div class="confidence-bar-fill" style="width:${a.ai_confidence || 0}%"></div></div>
        <div class="confidence-num">${a.ai_confidence ?? 0}%</div>
      </div>

      <div class="section-label">Analyst Reasoning (AI-generated)</div>
      <div class="reasoning-box">${escapeHtml(a.ai_reasoning)}</div>

      <div class="section-label">Recommended Action</div>
      <div class="reasoning-box">${escapeHtml(a.ai_recommended_action)}</div>

      ${iocs.length ? `
        <div class="section-label">Extracted IOCs</div>
        <div class="ioc-list">${iocs.map(i => `<span class="ioc-chip">${escapeHtml(i)}</span>`).join("")}</div>
      ` : ""}
    ` : `<div class="empty-state">Not triaged yet.</div>`}

    <div class="section-label">Related Log Lines</div>
    <div class="related-logs">
      ${(a.related_logs || []).map(l => `<div class="log-item">${escapeHtml(l.raw_log)}</div>`).join("") || `<div class="empty-state">None</div>`}
    </div>

    <div class="action-row">
      ${!a.ai_verdict ? `<button class="primary-btn" id="btnTriage">Run AI Triage</button>` : ""}
      ${gate ? `<button class="primary-btn" id="btnApprove">Approve AI Verdict</button>
                 <button class="danger-btn" id="btnOverride">Override → False Positive</button>` : ""}
      ${a.status !== "resolved" ? `<button class="ghost-btn" id="btnResolve">Mark Resolved</button>` : ""}
    </div>
  `;

  $("#btnTriage")?.addEventListener("click", () => runTriage(a.id));
  $("#btnApprove")?.addEventListener("click", () => decide(a.id, "approve"));
  $("#btnOverride")?.addEventListener("click", () => override(a.id));
  $("#btnResolve")?.addEventListener("click", () => resolve(a.id));
}

function verdictColor(verdict) {
  if (verdict === "true_positive") return "critical";
  if (verdict === "false_positive") return "low";
  return "medium";
}

function safeParseArray(json) {
  try { return JSON.parse(json || "[]"); } catch { return []; }
}

async function runTriage(id) {
  setIngestStatus("Running AI triage…");
  try {
    await api(`/api/alerts/${id}/triage`, { method: "POST" });
    await refreshAlerts();
    await openAlert(id);
    setIngestStatus("");
  } catch (e) {
    setIngestStatus(e.message);
  }
}

async function decide(id) {
  await api(`/api/alerts/${id}/approve`, { method: "POST", body: JSON.stringify({}) });
  await refreshAlerts();
  await openAlert(id);
}

async function override(id) {
  await api(`/api/alerts/${id}/override`, {
    method: "POST",
    body: JSON.stringify({ verdict: "false_positive", note: "Analyst determined false positive" }),
  });
  await refreshAlerts();
  await openAlert(id);
}

async function resolve(id) {
  await api(`/api/alerts/${id}/resolve`, { method: "POST" });
  await refreshAlerts();
  await openAlert(id);
}

// ---------- Sample data ingestion ----------

function setIngestStatus(text) { $("#ingestStatus").textContent = text; }

async function ingestSample() {
  setIngestStatus("Loading sample dataset…");
  try {
    const res = await api("/api/load-sample", { method: "POST" });
    setIngestStatus(`Loaded ${res.ingested} logs, created ${res.alerts_created} alerts.`);
    await refreshLogs();
    await refreshAlerts();
  } catch (e) {
    setIngestStatus(e.message);
  }
}

// ---------- Wiring ----------

$("#searchForm").addEventListener("submit", (e) => {
  e.preventDefault();
  refreshLogs($("#searchInput").value.trim());
});

$("#filterStatus").addEventListener("change", (e) => {
  state.statusFilter = e.target.value;
  refreshAlerts();
});

$("#loadSampleBtn").addEventListener("click", ingestSample);

refreshLogs();
refreshAlerts();
setInterval(refreshStats, 15000);
