/* global fetch */

let sessionId = null;
let latestCaseId = null;

const el = (id) => document.getElementById(id);

async function fetchJson(url, options) {
  const res = await fetch(url, options);
  const ct = (res.headers.get("content-type") || "").toLowerCase();
  const isJson = ct.includes("application/json") || ct.includes("application/problem+json");

  if (isJson) {
    const data = await res.json();
    if (!res.ok) {
      const msg =
        (data && data.error && data.error.message) ||
        (data && data.detail) ||
        `Request failed (${res.status})`;
      throw new Error(msg);
    }
    return data;
  }

  const text = await res.text();
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}: ${text || "Request failed"}`);
  throw new Error(`Unexpected non-JSON response: ${text || res.statusText}`);
}

function addBubble(kind, text) {
  const bubble = document.createElement("div");
  bubble.className = `bubble ${kind}`;
  bubble.textContent = text;
  el("messages").appendChild(bubble);
  el("messages").scrollTop = el("messages").scrollHeight;
}

function setAlerts(alerts) {
  const box = el("alerts");
  if (!alerts || alerts.length === 0) {
    box.classList.add("muted");
    box.textContent = "No alerts yet.";
    return;
  }
  box.classList.remove("muted");
  box.textContent = alerts
    .map((a) => {
      if (a.type === "TIMING") return `TIMING: ${a.key} score=${a.score.toFixed(2)} (${a.reason})`;
      if (a.type === "RATE_LIMIT") return `RATE_LIMIT: ${a.edge}`;
      return JSON.stringify(a);
    })
    .join("\n");
}

function setCaseLink(caseId) {
  latestCaseId = caseId;
  const link = el("caseLink");
  link.textContent = caseId;
  link.href = `/case/${caseId}`;
}

function setCovertResult(payload) {
  const box = el("covert");
  const summary = el("covertSummary");
  const chart = el("covertChart");
  const tokenNote = el("tokenNote");
  box.classList.remove("muted");
  if (!payload) {
    if (summary) {
      summary.classList.add("muted");
      summary.textContent = "No covert result.";
    }
    box.textContent = "No covert result.";
    return;
  }

  if (summary) {
    summary.classList.remove("muted");
    summary.innerHTML = "";
  }
  if (tokenNote) tokenNote.classList.remove("muted");

  if (payload.error) {
    if (summary) {
      summary.classList.remove("muted");
      summary.textContent = `Error: ${payload.error}`;
    }
    box.classList.add("muted");
    box.textContent = `Error: ${payload.error}`;
    if (chart && chart.getContext) chart.getContext("2d").clearRect(0, 0, chart.width, chart.height);
    return;
  }

  const lines = [];
  const nbits = payload.bits_len != null ? payload.bits_len : (payload.bits ? payload.bits.length : 0);
  const h = payload.bits_hash ? ` hash=${payload.bits_hash}` : "";
  lines.push(`bits=${nbits}${h}`);

  if (payload.baseline && payload.defended) {
    if (summary) renderSummary(summary, payload);
    if (chart) renderChart(chart, payload);
    lines.push(formatRun("baseline (no mitigation)", payload.baseline));
    lines.push("");
    lines.push(formatRun("defended (mitigation always)", payload.defended));
    box.textContent = lines.join("\n");
    return;
  }

  if (payload.per_bit) {
    if (summary) renderSummary(summary, payload);
    if (chart) renderChart(chart, payload);
    lines.push(formatRun(payload.mode || "run", payload));
    box.textContent = lines.join("\n");
    return;
  }

  box.textContent = JSON.stringify(payload, null, 2);
}

function renderSummary(root, payload) {
  const channel = payload.channel || (payload.baseline ? "timing" : "timing");

  const baseline = payload.baseline || payload;
  const defended = payload.defended || null;

  const metricKey = channel === "size" ? "observer_size_bytes" : "observer_total_ms";

  const baseMetrics = (((baseline.decode || {})[metricKey] || {}).metrics) || null;
  const defMetrics = defended ? ((((defended.decode || {})[metricKey] || {}).metrics) || null) : null;

  const baseBer = baseMetrics ? baseMetrics.ber : null;
  const defBer = defMetrics ? defMetrics.ber : null;
  const baseAcc = baseMetrics ? baseMetrics.accuracy : null;
  const defAcc = defMetrics ? defMetrics.accuracy : null;

  const blocked = payload.blocked != null ? payload.blocked : null;

  root.appendChild(kpi("Channel", channel.toUpperCase(), "badge"));
  if (payload.bits_hash) root.appendChild(kpi("Token id", payload.bits_hash, "badge"));
  if (blocked != null) {
    root.appendChild(kpi("Blocked bits", String(blocked), blocked > 0 ? "badge ok" : "badge"));
    return;
  }

  root.appendChild(
    kpi(
      "Baseline BER",
      baseBer == null ? "n/a" : `${(baseBer * 100).toFixed(1)}%`,
      baseBer != null && baseBer < 0.25 ? "badge bad" : "badge"
    )
  );
  if (defended) {
    root.appendChild(
      kpi(
        "Defended BER",
        defBer == null ? "n/a" : `${(defBer * 100).toFixed(1)}%`,
        defBer != null && defBer > (baseBer ?? 0) ? "badge ok" : "badge"
      )
    );
  } else {
    root.appendChild(kpi("Accuracy", baseAcc == null ? "n/a" : `${(baseAcc * 100).toFixed(1)}%`, "badge"));
  }

  if (defended && baseAcc != null && defAcc != null) {
    const delta = defAcc - baseAcc;
    root.appendChild(kpi("Accuracy Δ", `${(delta * 100).toFixed(1)}%`, delta < 0 ? "badge ok" : "badge"));
  }
}

function kpi(label, value, badgeClass) {
  const card = document.createElement("div");
  card.className = "kpi";
  const top = document.createElement("div");
  top.className = "kpi-top";
  const l = document.createElement("div");
  l.className = "kpi-label";
  l.textContent = label;
  const b = document.createElement("div");
  b.className = `badge ${badgeClass || ""}`.trim();
  b.textContent = value;
  top.appendChild(l);
  top.appendChild(b);
  card.appendChild(top);
  return card;
}

function renderChart(canvas, payload) {
  const ctx = canvas.getContext && canvas.getContext("2d");
  if (!ctx) return;

  const channel = payload.channel || "timing";
  const metric = channel === "size" ? "output_size_bytes" : "total_ms";

  const series = [];
  if (payload.baseline) series.push({ name: "baseline", data: (payload.baseline.per_bit || []).map((r) => r[metric] ?? 0), color: "rgba(99,102,241,0.95)" });
  if (payload.defended) series.push({ name: "defended", data: (payload.defended.per_bit || []).map((r) => r[metric] ?? 0), color: "rgba(16,185,129,0.95)" });
  if (!payload.baseline && payload.per_bit) series.push({ name: "run", data: (payload.per_bit || []).map((r) => r[metric] ?? 0), color: "rgba(99,102,241,0.95)" });

  const w = canvas.width;
  const h = canvas.height;
  ctx.clearRect(0, 0, w, h);

  const all = series.flatMap((s) => s.data).filter((x) => Number.isFinite(x));
  const max = Math.max(1, ...all);
  const min = Math.min(0, ...all);

  // background grid
  ctx.fillStyle = "rgba(0,0,0,0)";
  ctx.strokeStyle = "rgba(255,255,255,0.08)";
  ctx.lineWidth = 1;
  for (let i = 0; i <= 4; i++) {
    const y = Math.round((h - 20) * (i / 4) + 10);
    ctx.beginPath();
    ctx.moveTo(10, y);
    ctx.lineTo(w - 10, y);
    ctx.stroke();
  }

  const plotX0 = 10;
  const plotY0 = 10;
  const plotW = w - 20;
  const plotH = h - 20;
  const scaleY = (v) => plotY0 + plotH - ((v - min) / (max - min || 1)) * plotH;
  const scaleX = (i, n) => plotX0 + (i / Math.max(1, n - 1)) * plotW;

  for (const s of series) {
    const n = s.data.length;
    if (n < 2) continue;
    ctx.strokeStyle = s.color;
    ctx.lineWidth = 2;
    ctx.beginPath();
    for (let i = 0; i < n; i++) {
      const x = scaleX(i, n);
      const y = scaleY(s.data[i]);
      if (i === 0) ctx.moveTo(x, y);
      else ctx.lineTo(x, y);
    }
    ctx.stroke();
  }

  // label
  ctx.fillStyle = "rgba(255,255,255,0.6)";
  ctx.font = "12px Inter, system-ui, -apple-system, sans-serif";
  ctx.fillText(metric, 14, 18);
}

function formatRun(title, run) {
  const per = run.per_bit || [];
  const flagged = per.filter((x) => x.alert).length;
  const m = (((run.decode || {}).observer_total_ms || {}).metrics) || null;
  const mSize = (((run.decode || {}).observer_size_bytes || {}).metrics) || null;
  const acc = m ? (m.accuracy * 100).toFixed(1) + "%" : "n/a";
  const ber = m ? (m.ber * 100).toFixed(1) + "%" : "n/a";
  const thr = m ? m.threshold_ms.toFixed(1) + "ms" : "n/a";
  const berSize = mSize ? (mSize.ber * 100).toFixed(1) + "%" : null;
  const n = m ? String(m.sample_count) : "n/a";

  const out = [];
  out.push(`${title}: flagged=${flagged} decode_accuracy=${acc} BER=${ber} threshold=${thr} n=${n}`);
  if (berSize !== null) out.push(`observer_size_BER=${berSize}`);
  out.push("i  elapsed_ms  total_ms  sizeB  alert");
  for (const r of per.slice(0, 24)) {
    const e = (r.elapsed_ms ?? 0).toFixed(1).padStart(8);
    const t = (r.total_ms ?? 0).toFixed(1).padStart(8);
    const s = String(r.output_size_bytes ?? "").padStart(5);
    const a = r.alert ? "YES" : "no";
    out.push(`${String(r.i).padStart(2)}  ${e}  ${t}  ${s}  ${a}`);
  }
  if (per.length > 24) out.push("…");
  return out.join("\n");
}

async function loadAgents() {
  const box = el("agentList");
  try {
    const data = await fetchJson("/agents");
    const agents = data.agents || [];
    box.classList.remove("muted");
    box.innerHTML = "";
    if (agents.length === 0) {
      box.textContent = "No agents configured.";
      return;
    }
    const ul = document.createElement("div");
    ul.className = "agent-status";
    for (const a of agents) {
      const row = document.createElement("div");
      row.className = "agent-row";
      const dot = document.createElement("span");
      const online = a.mode === "local" ? true : Boolean(a.online);
      dot.className = online ? "dot ok" : "dot bad";

      const meta = document.createElement("div");
      meta.className = "agent-meta";
      const name = document.createElement("div");
      name.className = "agent-name";
      name.textContent = a.name;
      const desc = document.createElement("div");
      desc.className = "agent-desc";
      desc.textContent = a.description || a.url || "";
      meta.appendChild(name);
      meta.appendChild(desc);

      row.appendChild(dot);
      row.appendChild(meta);
      ul.appendChild(row);
    }
    box.appendChild(ul);
  } catch (e) {
    box.classList.add("muted");
    box.textContent = `Failed to load agents: ${String(e)}`;
  }
}

async function refreshCase(caseId) {
  try {
    const data = await fetchJson(`/cases/${caseId}`);
    setAlerts(data.alerts || []);
  } catch {
    // ignore
  }
}

async function createSession() {
  try {
    const data = await fetchJson("/host/sessions", { method: "POST" });
    sessionId = data.session_id;
    el("sessionId").textContent = sessionId;
    addBubble("assistant", data.welcome);
  } catch (e) {
    addBubble("system", `Failed to create session: ${String(e)}`);
  }
}

async function sendMessage(text) {
  el("sendBtn").disabled = true;
  el("covertBtn").disabled = true;
  addBubble("user", text);
  addBubble("system", "Host agent routing tasks to agents…");

  try {
    const data = await fetchJson(`/host/sessions/${sessionId}/messages`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ text }),
    });

    if (data.case_id) setCaseLink(data.case_id);
    if (data.alerts) setAlerts(data.alerts);
    if (data.case_id) void refreshCase(data.case_id);

    addBubble("assistant", data.reply || "No reply.");
  } catch (e) {
    addBubble("system", `Error: ${String(e)}`);
  } finally {
    el("sendBtn").disabled = false;
    el("covertBtn").disabled = false;
  }
}

async function runCovertDemo() {
  el("sendBtn").disabled = true;
  el("covertBtn").disabled = true;
  addBubble("system", "Running covert experiment…");
  try {
    const channel = (el("covertChannel") && el("covertChannel").value) || "timing";
    const bits = buildBits();
    const compare = Boolean(el("compareMode").checked);
    const server_generate_bits = Boolean(el("serverBits") && el("serverBits").checked);
    const bits_len = Math.max(8, Math.min(256, parseInt(el("bitsLen").value || "64", 10)));
    const min_response_ms = parseInt(el("minRespMs").value || "400", 10);
    const jitter_ms_low = parseInt(el("jitterLow").value || "10", 10);
    const jitter_ms_high = parseInt(el("jitterHigh").value || "40", 10);

    const data = await fetchJson("/demo/covert", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        channel,
        compare,
        server_generate_bits,
        bits_len,
        bits: server_generate_bits ? null : bits,
        min_response_ms,
        jitter_ms_low,
        jitter_ms_high,
      }),
    });
    if (data.case_id) setCaseLink(data.case_id);
    setCovertResult(data);
    addBubble("assistant", "Experiment complete. See the Covert Timing Lab panel for decode metrics and per-bit latency.");
  } catch (e) {
    setCovertResult({ bits: buildBits(), channel: (el("covertChannel") && el("covertChannel").value) || "timing", error: String(e) });
    addBubble("system", `Error: ${String(e)}`);
  } finally {
    el("sendBtn").disabled = false;
    el("covertBtn").disabled = false;
  }
}

function buildBits() {
  const pattern = el("bitsPattern").value;
  const n = Math.max(8, Math.min(256, parseInt(el("bitsLen").value || "64", 10)));

  if (pattern === "custom") {
    const s = (el("bitsCustom").value || "").trim();
    if (!/^[01]{8,256}$/.test(s)) return "0101100110010110";
    return s;
  }

  if (pattern === "zeros") return "0".repeat(n);
  if (pattern === "ones") return "1".repeat(n);

  if (pattern === "random") {
    let out = "";
    for (let i = 0; i < n; i++) out += Math.random() < 0.5 ? "0" : "1";
    return out;
  }

  // alternating default
  let out = "";
  for (let i = 0; i < n; i++) out += i % 2 === 0 ? "0" : "1";
  return out;
}

function clearChat() {
  el("messages").innerHTML = "";
  addBubble("system", "Cleared.");
}

function wire() {
  el("sendBtn").addEventListener("click", () => {
    const text = el("input").value.trim();
    if (!text) return;
    el("input").value = "";
    void sendMessage(text);
  });

  el("input").addEventListener("keydown", (e) => {
    if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) {
      e.preventDefault();
      const text = el("input").value.trim();
      if (!text) return;
      el("input").value = "";
      void sendMessage(text);
    }
  });

  el("covertBtn").addEventListener("click", () => void runCovertDemo());
  el("clearBtn").addEventListener("click", () => clearChat());
}

window.addEventListener("DOMContentLoaded", () => {
  wire();
  void loadAgents();
  void createSession();
});
