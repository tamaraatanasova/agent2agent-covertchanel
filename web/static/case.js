/* global fetch */

const el = (id) => document.getElementById(id);

function caseIdFromPath() {
  const parts = window.location.pathname.split("/").filter(Boolean);
  return parts[0] === "case" ? parts[1] : null;
}

async function fetchJson(url, options) {
  const res = await fetch(url, options);
  const ct = (res.headers.get("content-type") || "").toLowerCase();
  const isJson = ct.includes("application/json") || ct.includes("application/problem+json");
  if (isJson) {
    const data = await res.json();
    if (!res.ok) throw new Error((data && data.detail) || (data && data.error && data.error.message) || `HTTP ${res.status}`);
    return data;
  }
  const text = await res.text();
  throw new Error(text || `HTTP ${res.status}`);
}

function pretty(obj) {
  return JSON.stringify(obj, null, 2);
}

function relativeTime(isoStr) {
  if (!isoStr) return "";
  try {
    const d = new Date(isoStr);
    if (Number.isNaN(d.getTime())) return isoStr;
    const sec = Math.floor((Date.now() - d) / 1000);
    if (sec < 60) return "just now";
    if (sec < 3600) return `${Math.floor(sec / 60)} min ago`;
    if (sec < 86400) return `${Math.floor(sec / 3600)} h ago`;
    if (sec < 604800) return `${Math.floor(sec / 86400)} d ago`;
    return d.toLocaleDateString();
  } catch {
    return isoStr;
  }
}

function fmtAlert(a) {
  if (!a) return "";
  const type = a.type || "UNKNOWN";
  if (type === "TIMING") return { html: true, cls: "timing", text: `TIMING ${a.key || "—"} score=${Number(a.score || 0).toFixed(2)} (${a.reason || ""})` };
  if (type === "COVERT_PROTOCOL") return { html: true, cls: "covert", text: `COVERT_PROTOCOL ${a.edge || "—"} (envelope)` };
  if (type === "RATE_LIMIT") return { html: true, cls: "rate-limit", text: `RATE_LIMIT ${a.edge || "—"}` };
  if (type === "DEGRADED_MODE") return { html: true, cls: "degraded", text: `DEGRADED ${a.agent || "—"} ${a.reason || ""}` };
  return { html: false, text: pretty(a) };
}

function summarizeReport(report) {
  if (!report) return "No report.";
  const lines = [];
  if (report.severity) lines.push(`Severity: ${report.severity}`);
  if (report.executive_summary) lines.push(String(report.executive_summary));
  const metrics = report.metrics || {};
  const m = [];
  if (metrics.event_count != null) m.push(`events=${metrics.event_count}`);
  if (metrics.unique_hosts != null) m.push(`hosts=${metrics.unique_hosts}`);
  if (metrics.intel_matches != null) m.push(`intel=${metrics.intel_matches}`);
  if (m.length) lines.push(`Metrics: ${m.join("  ")}`);
  const recs = report.recommendations || [];
  if (recs.length) {
    lines.push("Recommendations:");
    for (const r of recs.slice(0, 8)) lines.push(`- ${r}`);
  }
  return lines.join("\n");
}

function summarizeAnalysis(analysis) {
  if (!analysis) return "No analysis.";
  const lines = [];
  if (analysis.severity) lines.push(`Severity: ${analysis.severity}`);

  const f = analysis.findings || {};
  const bullets = f.bullets || [];
  for (const b of bullets) lines.push(`- ${b}`);

  const trace = analysis.trace || {};
  const msgCounts = trace.message_counts || {};
  const alertCounts = trace.alert_counts || {};
  const lat = trace.avg_latency_ms || {};

  const parts = [];
  if (Object.keys(msgCounts).length) parts.push(`messages=${prettyInline(msgCounts)}`);
  if (Object.keys(alertCounts).length) parts.push(`alerts=${prettyInline(alertCounts)}`);
  if (Object.keys(lat).length) parts.push(`avg_latency_ms=${prettyInline(lat)}`);
  if (parts.length) {
    lines.push("");
    lines.push("Trace:");
    for (const p of parts) lines.push(`- ${p}`);
  }

  const actions = analysis.actions || {};
  const recs = actions.recommendations || [];
  const blocked = actions.blocked || [];
  if (recs.length || blocked.length) {
    lines.push("");
    lines.push("Actions:");
    if (recs.length) lines.push(`- recommendations=${recs.length}`);
    if (blocked.length) lines.push(`- blocked=${blocked.length} (policy)`);
  }

  return lines.join("\n");
}

function summarizeCovert(covert) {
  if (!covert) return "No covert channel activity recorded for this case.";
  if (covert.error) return `Error: ${covert.error}`;

  const isDemoCase = covert.bits_len != null || covert.bits_hash || Array.isArray(covert.modes);
  if (!isDemoCase) {
    const lines = [];
    if (covert.trigger_index != null || covert.triggered_at) {
      const idx = covert.trigger_index != null ? `#${covert.trigger_index}` : "";
      const at = covert.triggered_at ? ` at ${covert.triggered_at}` : "";
      lines.push(`Triggered: ${idx}${at}`.trim());
    }
    if (covert.channel) lines.push(`Channel: ${covert.channel}`);
    if (covert.topology) lines.push(`Topology: ${covert.topology}`);
    if (covert.message) lines.push(`Message: ${covert.message}`);
    if (covert.decoded && covert.decoded !== covert.message) lines.push(`Decoded: ${covert.decoded}`);
    return lines.join("\n") || "Covert channel activity recorded.";
  }

  const lines = [];
  lines.push(`Channel: ${covert.channel}`);
  if (covert.topology) lines.push(`Topology: ${covert.topology}`);
  if (covert.bits_len != null) lines.push(`Bits: ${covert.bits_len}`);
  if (covert.bits_hash) lines.push(`Token id: ${covert.bits_hash}`);
  if (covert.message) lines.push(`Message (sent): ${covert.message}`);
  lines.push("Note: underlying bits are redacted in the case JSON view.");
  lines.push(`Modes: ${(covert.modes || []).join(", ") || "n/a"}`);
  for (const m of covert.modes || []) {
    const r = covert[m] || {};
    const met = r.metrics || null;
    const ber = met ? `${(met.ber * 100).toFixed(1)}%` : "n/a";
    const acc = met ? `${(met.accuracy * 100).toFixed(1)}%` : "n/a";
    const n = met ? `${met.sample_count}` : "n/a";
    lines.push(`- ${m}: BER=${ber} acc=${acc} n=${n}`);
  }
  return lines.join("\n");
}

function prettyInline(obj) {
  try {
    return JSON.stringify(obj);
  } catch {
    return String(obj);
  }
}

function renderMessages(messages, filterText) {
  const q = (filterText || "").trim().toLowerCase();
  const rows = [];
  for (const m of messages || []) {
    const type = m.type || "";
    const from = m.from_agent || "";
    const to = m.to_agent || "";
    const task = (m.task && m.task.name) || "";
    const timing = (m.result && m.result.timing) || {};
    const total = timing.total_ms != null ? `${Number(timing.total_ms).toFixed(1)}ms` : "";
    const alert = timing.alert ? "ALERT" : "";
    const covert = m.covert_payload ? "COVERT" : "";
    const key = `${type} ${from} ${to} ${task} ${alert} ${covert}`.toLowerCase();
    if (q && !key.includes(q)) continue;
    rows.push({ type, from, to, task, total, covert: !!m.covert_payload, raw: m });
  }

  if (rows.length === 0) return "<div class=\"muted\">No messages match filter.</div>";

  const html = [];
  html.push("<div class=\"table\">");
  html.push("<div class=\"tr th\"><div>Type</div><div>From</div><div>To</div><div>Task</div><div>Total</div></div>");
  for (const r of rows) {
    const covertTag = r.covert ? '<span class="msg-covert">covert</span>' : "";
    html.push(
      `<details class="tr">` +
      `<summary class="tds">` +
      `<div class="td mono">${escapeHtml(r.type)}${covertTag}</div>` +
      `<div class="td mono">${escapeHtml(r.from)}</div>` +
      `<div class="td mono">${escapeHtml(r.to)}</div>` +
      `<div class="td mono">${escapeHtml(r.task || "-")}</div>` +
      `<div class="td mono">${escapeHtml(r.total || "-")}</div>` +
      `</summary>` +
      `<pre class="code">${escapeHtml(pretty(r.raw))}</pre>` +
      `</details>`
    );
  }
  html.push("</div>");
  return html.join("");
}

function escapeHtml(s) {
  return String(s)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll("\"", "&quot;")
    .replaceAll("'", "&#039;");
}

let caseData = null;

async function loadCase() {
  const id = caseIdFromPath();
  if (!id) {
    el("overview").textContent = "Missing case id in URL.";
    return;
  }
  el("caseId").textContent = id;
  el("rawLink").href = `/cases/${id}`;
  document.body.classList.add("case-loading");
  el("overview").innerHTML = '<span class="overview-spinner"></span>Loading…';

  try {
    const data = await fetchJson(`/cases/${id}`);
    caseData = data;
    document.body.classList.remove("case-loading");

    const report = data.final_report || null;
    const severity = (report && report.severity) ? String(report.severity).toLowerCase() : "info";
    const sevEl = el("severityBadge");
    if (sevEl) {
      sevEl.textContent = severity;
      sevEl.className = "severity-badge severity-" + (["low", "medium", "high", "critical", "info"].includes(severity) ? severity : "info");
    }

    const created = data.created_at ? String(data.created_at) : "—";
    const relTime = relativeTime(created);
    el("overview").classList.remove("muted");
    el("overview").innerHTML = `Created: ${created} <span class="relative-time">(${relTime})</span><br>Messages: ${(data.messages || []).length}<br>Alerts: ${(data.alerts || []).length}`;

    const alerts = data.alerts || [];
    const alertsCountEl = el("alertsCount");
    if (alertsCountEl) {
      alertsCountEl.textContent = alerts.length ? `(${alerts.length})` : "";
      alertsCountEl.classList.toggle("has-alerts", alerts.length > 0);
    }
    el("alertsBox").classList.toggle("muted", alerts.length === 0);
    if (alerts.length === 0) {
      el("alertsBox").textContent = "No alerts.";
    } else {
      const alertHtml = alerts.map((a) => {
        const f = fmtAlert(a);
        if (f.html) return `<div class="alert-item ${f.cls}"><span class="alert-type">${escapeHtml((a.type || "").replace(/_/g, " "))}</span>${escapeHtml(f.text)}</div>`;
        return `<div class="alert-item"><pre class="code" style="margin:0;padding:0;background:transparent;border:none">${escapeHtml(f.text)}</pre></div>`;
      }).join("");
      el("alertsBox").innerHTML = alertHtml;
    }

    el("reportBox").classList.toggle("muted", !report);
    el("reportBox").textContent = summarizeReport(report);

    const analysis = data.analysis || null;
    el("analysisBox").classList.toggle("muted", !analysis);
    el("analysisBox").textContent = summarizeAnalysis(analysis);

    const covert = analysis ? analysis.covert : null;
    const covertBox = el("covertCaseBox");
    if (covertBox) {
      covertBox.classList.toggle("muted", !covert);
      covertBox.textContent = summarizeCovert(covert);
    }

    el("outputsBox").classList.toggle("muted", !data.agent_outputs);
    el("outputsBox").textContent = data.agent_outputs ? pretty(data.agent_outputs) : "—";

    applyFilter();
  } catch (e) {
    document.body.classList.remove("case-loading");
    throw e;
  }
}

function applyFilter() {
  if (!caseData) return;
  const filterText = el("filter") ? el("filter").value || "" : "";
  el("messagesBox").classList.remove("muted");
  el("messagesBox").innerHTML = renderMessages(caseData.messages || [], filterText);
}

function wire() {
  el("refreshBtn").addEventListener("click", () => void loadCase());
  el("filter").addEventListener("input", () => applyFilter());
  el("copyCaseIdBtn").addEventListener("click", () => {
    const id = caseIdFromPath();
    if (!id) return;
    navigator.clipboard.writeText(id).then(() => {
      const btn = el("copyCaseIdBtn");
      btn.classList.add("copied");
      btn.textContent = "Copied!";
      setTimeout(() => { btn.classList.remove("copied"); btn.textContent = "Copy ID"; }, 1500);
    });
  });
}

window.addEventListener("DOMContentLoaded", () => {
  wire();
  void loadCase().catch((e) => {
    document.body.classList.remove("case-loading");
    el("overview").classList.remove("muted");
    el("overview").textContent = `Error: ${String(e)}`;
  });
});
