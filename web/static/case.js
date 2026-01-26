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

function fmtAlert(a) {
  if (!a) return "";
  if (a.type === "TIMING") return `TIMING ${a.key} score=${Number(a.score).toFixed(2)} (${a.reason})`;
  if (a.type === "RATE_LIMIT") return `RATE_LIMIT ${a.edge}`;
  return pretty(a);
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
    const key = `${type} ${from} ${to} ${task} ${alert}`.toLowerCase();
    if (q && !key.includes(q)) continue;
    rows.push({ type, from, to, task, total, raw: m });
  }

  if (rows.length === 0) return "<div class=\"muted\">No messages match filter.</div>";

  const html = [];
  html.push("<div class=\"table\">");
  html.push("<div class=\"tr th\"><div>Type</div><div>From</div><div>To</div><div>Task</div><div>Total</div></div>");
  for (const r of rows) {
    html.push(
      `<details class="tr">` +
      `<summary class="tds">` +
      `<div class="td mono">${escapeHtml(r.type)}</div>` +
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

async function loadCase() {
  const id = caseIdFromPath();
  if (!id) {
    el("overview").textContent = "Missing case id in URL.";
    return;
  }
  el("caseId").textContent = id;
  el("rawLink").href = `/cases/${id}`;

  const data = await fetchJson(`/cases/${id}`);

  const created = data.created_at ? String(data.created_at) : "—";
  el("overview").classList.remove("muted");
  el("overview").textContent = `Created: ${created}\nMessages: ${(data.messages || []).length}\nAlerts: ${(data.alerts || []).length}`;

  const alerts = data.alerts || [];
  el("alertsBox").classList.toggle("muted", alerts.length === 0);
  el("alertsBox").textContent = alerts.length ? alerts.map(fmtAlert).join("\n") : "No alerts.";

  const report = data.final_report || null;
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

  const filterText = el("filter").value || "";
  el("messagesBox").classList.remove("muted");
  el("messagesBox").innerHTML = renderMessages(data.messages || [], filterText);
}

function wire() {
  el("refreshBtn").addEventListener("click", () => void loadCase());
  el("filter").addEventListener("input", () => void loadCase());
}

window.addEventListener("DOMContentLoaded", () => {
  wire();
  void loadCase().catch((e) => {
    el("overview").classList.remove("muted");
    el("overview").textContent = `Error: ${String(e)}`;
  });
});
