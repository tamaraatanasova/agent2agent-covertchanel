/* global fetch */

let sessionId = null;
let latestCaseId = null;
let authToken = null;
let authUser = null;
let authMode = "login";

const el = (id) => document.getElementById(id);

const SAMPLES = {
  assistant_today: "I'm Tamara — show my calendar for today.",
  assistant_add: "I'm Tamara — add 10am Gym today.",
  assistant_work: "I'm Tamara — I'm working every day from 9 to 5 in Imbrium from Monday to Friday.",
  assistant_everyday: "I'm Tamara — every day at 9:00 go to work.",
  assistant_search: "I'm Tamara — add 14:00 Dentist tomorrow, then search for Dentist.",
};

const calendarState = {
  viewDate: new Date(),
  selectedDate: new Date(),
  itemsByDay: {},
  loading: false,
};

let calendarRefreshTimer = null;
const CALENDAR_VIEW_SUFFIXES = ["", "Modal"];

async function fetchJson(url, options = {}) {
  const opts = options || {};
  const headers = new Headers(opts.headers || {});
  if (authToken) headers.set("x-auth-token", authToken);
  opts.headers = headers;

  const res = await fetch(url, opts);
  const ct = (res.headers.get("content-type") || "").toLowerCase();
  const isJson = ct.includes("application/json") || ct.includes("application/problem+json");

  if (isJson) {
    const data = await res.json();
    if (!res.ok) {
      const msg = formatErrorMessage(data, res.status);
      throw new Error(msg);
    }
    return data;
  }

  const text = await res.text();
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}: ${text || "Request failed"}`);
  throw new Error(`Unexpected non-JSON response: ${text || res.statusText}`);
}

function formatErrorMessage(data, status) {
  if (data && data.error && data.error.message != null) {
    return String(data.error.message);
  }
  const detail = data ? data.detail : null;
  if (detail != null) {
    if (typeof detail === "string") return detail;
    if (Array.isArray(detail)) {
      const parts = detail
        .map((item) => {
          if (!item) return "";
          if (typeof item === "string") return item;
          if (typeof item === "object") return item.msg || item.message || JSON.stringify(item);
          return String(item);
        })
        .filter(Boolean);
      if (parts.length) return parts.join(" | ");
    } else if (typeof detail === "object") {
      return detail.msg || detail.message || JSON.stringify(detail);
    } else {
      return String(detail);
    }
  }
  return `Request failed (${status || "error"})`;
}

function setAuthMessage(text, isError = false) {
  const msg = el("authMessage");
  if (!msg) return;
  msg.textContent = text || "";
  if (isError) {
    msg.classList.remove("muted");
  } else {
    msg.classList.add("muted");
  }
}

function errorText(err) {
  if (err && typeof err === "object" && err.message) return String(err.message);
  return String(err);
}

function toDateKey(dateObj) {
  const y = dateObj.getFullYear();
  const m = String(dateObj.getMonth() + 1).padStart(2, "0");
  const d = String(dateObj.getDate()).padStart(2, "0");
  return `${y}-${m}-${d}`;
}

function fromDateKey(key) {
  if (!key || typeof key !== "string") return null;
  const parts = key.split("-").map((x) => parseInt(x, 10));
  if (parts.length !== 3 || parts.some((n) => Number.isNaN(n))) return null;
  return new Date(parts[0], parts[1] - 1, parts[2]);
}

function formatMonthLabel(dateObj) {
  try {
    return dateObj.toLocaleString(undefined, { month: "long", year: "numeric" });
  } catch {
    return dateObj.toDateString();
  }
}

function parseTimeToMinutes(timeStr) {
  if (!timeStr || typeof timeStr !== "string") return null;
  const parts = timeStr.split(":");
  if (parts.length !== 2) return null;
  const h = parseInt(parts[0], 10);
  const m = parseInt(parts[1], 10);
  if (Number.isNaN(h) || Number.isNaN(m)) return null;
  return h * 60 + m;
}

function minutesToTime(minutes) {
  const safe = ((minutes % (24 * 60)) + (24 * 60)) % (24 * 60);
  const h = Math.floor(safe / 60);
  const m = safe % 60;
  return `${String(h).padStart(2, "0")}:${String(m).padStart(2, "0")}`;
}

function formatDuration(minutes) {
  if (!minutes || !Number.isFinite(minutes)) return "";
  const total = Math.max(1, Math.min(24 * 60, Math.round(minutes)));
  const h = Math.floor(total / 60);
  const m = total % 60;
  if (h && m) return `${h}h ${m}m`;
  if (h) return `${h}h`;
  return `${m}m`;
}

function formatTimeRange(timeStr, durationMinutes) {
  if (!timeStr) return "";
  if (!durationMinutes) return timeStr;
  const start = parseTimeToMinutes(timeStr);
  if (start == null) return timeStr;
  const end = start + durationMinutes;
  return `${timeStr}–${minutesToTime(end)}`;
}

function describeEventTime(item) {
  const timeStr = item && item.time ? String(item.time) : "";
  const duration = item && item.duration_minutes ? Number(item.duration_minutes) : null;
  const range = formatTimeRange(timeStr, duration);
  const durLabel = formatDuration(duration);
  return { timeStr, duration, range, durLabel };
}

function getMonthRange(dateObj) {
  const start = new Date(dateObj.getFullYear(), dateObj.getMonth(), 1);
  const end = new Date(dateObj.getFullYear(), dateObj.getMonth() + 1, 0);
  return { start, end };
}

function sortCalendarItems(items) {
  if (!Array.isArray(items)) return [];
  return items.sort((a, b) => {
    const ta = (a && a.time) || "99:99";
    const tb = (b && b.time) || "99:99";
    if (ta === tb) {
      const da = a && a.duration_minutes ? Number(a.duration_minutes) : 0;
      const db = b && b.duration_minutes ? Number(b.duration_minutes) : 0;
      if (da !== db) return da - db;
      return String((a && a.title) || "").localeCompare(String((b && b.title) || ""));
    }
    return ta.localeCompare(tb);
  });
}

function groupCalendarItems(items) {
  const grouped = {};
  if (!Array.isArray(items)) return grouped;
  items.forEach((item) => {
    if (!item || !item.day) return;
    const key = String(item.day);
    if (!grouped[key]) grouped[key] = [];
    grouped[key].push(item);
  });
  Object.keys(grouped).forEach((key) => {
    grouped[key] = sortCalendarItems(grouped[key]);
  });
  return grouped;
}

function getCalendarViewElements(suffix) {
  const s = suffix || "";
  return {
    status: el(`calendarStatus${s}`),
    label: el(`calendarLabel${s}`),
    grid: el(`calendarGrid${s}`),
    detailLabel: el(`calendarDetailLabel${s}`),
    detailMeta: el(`calendarDetailMeta${s}`),
    detailList: el(`calendarDetailList${s}`),
  };
}

function setCalendarStatus(text, isError = false) {
  CALENDAR_VIEW_SUFFIXES.forEach((suffix) => {
    const status = el(`calendarStatus${suffix}`);
    if (!status) return;
    status.textContent = text || "";
    status.classList.toggle("muted", !isError);
  });
}

function renderCalendarView(view) {
  if (!view || !view.grid || !view.label) return;

  const viewDate = calendarState.viewDate || new Date();
  view.label.textContent = formatMonthLabel(viewDate);

  view.grid.innerHTML = "";
  const year = viewDate.getFullYear();
  const month = viewDate.getMonth();
  const first = new Date(year, month, 1);
  const daysInMonth = new Date(year, month + 1, 0).getDate();
  const startOffset = (first.getDay() + 6) % 7; // Monday start

  const todayKey = toDateKey(new Date());
  const selectedKey = calendarState.selectedDate ? toDateKey(calendarState.selectedDate) : null;

  for (let i = 0; i < startOffset; i += 1) {
    const empty = document.createElement("div");
    empty.className = "calendar-cell empty";
    empty.setAttribute("aria-hidden", "true");
    view.grid.appendChild(empty);
  }

  for (let day = 1; day <= daysInMonth; day += 1) {
    const dateObj = new Date(year, month, day);
    const key = toDateKey(dateObj);
    const cell = document.createElement("button");
    cell.type = "button";
    cell.className = "calendar-cell";
    cell.dataset.date = key;

    if (key === todayKey) cell.classList.add("today");
    if (selectedKey && key === selectedKey) cell.classList.add("selected");

    const number = document.createElement("div");
    number.className = "day-number";
    number.textContent = String(day);
    cell.appendChild(number);

    const items = calendarState.itemsByDay[key] || [];
    if (items.length) {
      const list = document.createElement("div");
      list.className = "calendar-events";
      items.slice(0, 2).forEach((it) => {
        const row = document.createElement("div");
        row.className = "calendar-event";
        const desc = describeEventTime(it);
        const timeLabel = desc.range ? `${desc.range} ` : (desc.timeStr ? `${desc.timeStr} ` : "");
        row.textContent = `${timeLabel}${it.title || "Untitled"}`;
        list.appendChild(row);
      });
      if (items.length > 2) {
        const more = document.createElement("div");
        more.className = "calendar-event more";
        more.textContent = `+${items.length - 2} more`;
        list.appendChild(more);
      }
      cell.appendChild(list);
    }

    cell.addEventListener("click", () => selectCalendarDay(key));
    view.grid.appendChild(cell);
  }
}

function renderCalendar() {
  CALENDAR_VIEW_SUFFIXES.forEach((suffix) => {
    renderCalendarView(getCalendarViewElements(suffix));
  });
}

function renderCalendarDetailView(view, dateKey) {
  if (!view || !view.detailLabel || !view.detailMeta || !view.detailList) return;

  const key = dateKey || (calendarState.selectedDate ? toDateKey(calendarState.selectedDate) : null);
  if (!key) {
    view.detailLabel.textContent = "Select a day";
    view.detailMeta.textContent = "—";
    view.detailList.classList.add("muted");
    view.detailList.textContent = "No events yet.";
    return;
  }

  const dateObj = fromDateKey(key);
  if (!dateObj) return;
  view.detailLabel.textContent = dateObj.toLocaleDateString(undefined, { weekday: "long", month: "long", day: "numeric", year: "numeric" });

  const items = calendarState.itemsByDay[key] || [];
  view.detailMeta.textContent = items.length ? `${items.length} item${items.length === 1 ? "" : "s"}` : "No events";
  view.detailList.innerHTML = "";

  if (!items.length) {
    view.detailList.classList.add("muted");
    view.detailList.textContent = "No events for this day.";
    return;
  }

  view.detailList.classList.remove("muted");
  items.forEach((it) => {
    const desc = describeEventTime(it);
    const row = document.createElement("div");
    row.className = "calendar-detail-item";

    const time = document.createElement("div");
    time.className = "calendar-detail-time";
    time.textContent = desc.range || desc.timeStr || "—";

    const title = document.createElement("div");
    title.className = "calendar-detail-title-text";
    title.textContent = it.title || "Untitled";

    const duration = document.createElement("div");
    duration.className = "calendar-detail-duration";
    duration.textContent = desc.durLabel || "";

    const timeline = document.createElement("div");
    timeline.className = "calendar-detail-timeline";
    const block = document.createElement("div");
    block.className = "calendar-detail-block";
    const startMinutes = desc.timeStr ? parseTimeToMinutes(desc.timeStr) : null;
    const durMinutes = desc.duration || 0;
    if (startMinutes != null) {
      const left = (startMinutes / (24 * 60)) * 100;
      const width = durMinutes ? Math.max(2, (durMinutes / (24 * 60)) * 100) : 2;
      block.style.left = `${left}%`;
      block.style.width = `${Math.min(100 - left, width)}%`;
    } else {
      block.style.left = "0%";
      block.style.width = "6%";
      block.classList.add("no-time");
    }
    timeline.appendChild(block);

    row.appendChild(time);
    row.appendChild(title);
    if (desc.durLabel) row.appendChild(duration);
    row.appendChild(timeline);
    view.detailList.appendChild(row);
  });
}

function renderCalendarDetail(dateKey) {
  CALENDAR_VIEW_SUFFIXES.forEach((suffix) => {
    renderCalendarDetailView(getCalendarViewElements(suffix), dateKey);
  });
}

function selectCalendarDay(key) {
  const dateObj = fromDateKey(key);
  if (!dateObj) return;
  calendarState.selectedDate = dateObj;
  renderCalendar();
  renderCalendarDetail(key);
}

function applyAssistantState(state) {
  if (!state || typeof state !== "object") return;
  const dayKey = typeof state.day === "string" ? state.day : null;
  if (dayKey) {
    const dateObj = fromDateKey(dayKey);
    if (dateObj) {
      calendarState.selectedDate = dateObj;
      if (calendarState.viewDate.getMonth() !== dateObj.getMonth() || calendarState.viewDate.getFullYear() !== dateObj.getFullYear()) {
        calendarState.viewDate = new Date(dateObj.getFullYear(), dateObj.getMonth(), 1);
      }
    }
  }
  if (dayKey && Array.isArray(state.items)) {
    calendarState.itemsByDay[dayKey] = sortCalendarItems(state.items.slice());
  }
  renderCalendar();
  renderCalendarDetail(dayKey);
}

async function refreshCalendar() {
  if (!authToken) {
    calendarState.itemsByDay = {};
    setCalendarStatus("Sign in to load calendar.");
    renderCalendar();
    renderCalendarDetail(null);
    return;
  }

  const { start, end } = getMonthRange(calendarState.viewDate);
  const startKey = toDateKey(start);
  const endKey = toDateKey(end);
  calendarState.loading = true;
  setCalendarStatus("Loading…");
  try {
    const data = await fetchJson(`/calendar/range?start=${encodeURIComponent(startKey)}&end=${encodeURIComponent(endKey)}`);
    const items = Array.isArray(data.items) ? data.items : [];
    calendarState.itemsByDay = groupCalendarItems(items);
    setCalendarStatus(`${items.length} event${items.length === 1 ? "" : "s"}`);
  } catch (e) {
    setCalendarStatus(`Calendar error: ${errorText(e)}`, true);
  } finally {
    calendarState.loading = false;
    renderCalendar();
    renderCalendarDetail();
  }
}

function scheduleCalendarRefresh() {
  if (calendarRefreshTimer) {
    clearTimeout(calendarRefreshTimer);
  }
  calendarRefreshTimer = setTimeout(() => {
    calendarRefreshTimer = null;
    void refreshCalendar();
  }, 250);
}

function initCalendar() {
  calendarState.viewDate = new Date();
  calendarState.selectedDate = new Date();
  calendarState.itemsByDay = {};
  renderCalendar();
  renderCalendarDetail();
  return refreshCalendar();
}

function resetCalendar() {
  calendarState.viewDate = new Date();
  calendarState.selectedDate = new Date();
  calendarState.itemsByDay = {};
  setCalendarStatus("Sign in to load calendar.");
  renderCalendar();
  renderCalendarDetail();
}

function changeCalendarMonth(delta) {
  const current = calendarState.viewDate || new Date();
  calendarState.viewDate = new Date(current.getFullYear(), current.getMonth() + delta, 1);
  renderCalendar();
  void refreshCalendar();
}

function wireCalendar() {
  const prevBtn = el("calendarPrevBtn");
  const nextBtn = el("calendarNextBtn");
  const todayBtn = el("calendarTodayBtn");
  const openBtn = el("calendarOpenBtn");
  const prevBtnModal = el("calendarPrevBtnModal");
  const nextBtnModal = el("calendarNextBtnModal");
  const todayBtnModal = el("calendarTodayBtnModal");
  const modal = el("calendarModal");
  const modalClose = el("calendarModalClose");
  const modalBackdrop = el("calendarModalBackdrop");

  if (prevBtn) prevBtn.addEventListener("click", () => changeCalendarMonth(-1));
  if (nextBtn) nextBtn.addEventListener("click", () => changeCalendarMonth(1));
  if (todayBtn) {
    todayBtn.addEventListener("click", () => {
      calendarState.viewDate = new Date();
      calendarState.selectedDate = new Date();
      renderCalendar();
      void refreshCalendar();
    });
  }
  if (openBtn && modal) {
    openBtn.addEventListener("click", () => openCalendarModal());
  }
  if (prevBtnModal) prevBtnModal.addEventListener("click", () => changeCalendarMonth(-1));
  if (nextBtnModal) nextBtnModal.addEventListener("click", () => changeCalendarMonth(1));
  if (todayBtnModal) {
    todayBtnModal.addEventListener("click", () => {
      calendarState.viewDate = new Date();
      calendarState.selectedDate = new Date();
      renderCalendar();
      void refreshCalendar();
    });
  }
  if (modalClose) modalClose.addEventListener("click", () => closeCalendarModal());
  if (modalBackdrop) modalBackdrop.addEventListener("click", () => closeCalendarModal());
}

function setScreen(signedIn) {
  const authScreen = el("authScreen");
  const appScreen = el("appScreen");
  if (authScreen) authScreen.classList.toggle("hidden", signedIn);
  if (appScreen) appScreen.classList.toggle("hidden", !signedIn);
}

function setAuthMode(mode) {
  authMode = mode === "register" ? "register" : "login";
  const display = el("authDisplayName");
  const submit = el("authSubmitBtn");
  const loginTab = el("authLoginTab");
  const registerTab = el("authRegisterTab");
  if (display) display.classList.toggle("hidden", authMode !== "register");
  if (submit) submit.textContent = authMode === "register" ? "Create account" : "Login";
  if (loginTab) loginTab.classList.toggle("active", authMode === "login");
  if (registerTab) registerTab.classList.toggle("active", authMode === "register");
  setAuthMessage("");
}

function setAuthState(user) {
  authUser = user || null;
  const status = el("authStatus");
  const logoutBtn = el("authLogoutBtn");
  const submitBtn = el("authSubmitBtn");
  const loginTab = el("authLoginTab");
  const registerTab = el("authRegisterTab");
  const usernameInput = el("authUsername");
  const passwordInput = el("authPassword");
  const displayInput = el("authDisplayName");

  const signedIn = Boolean(user);
  if (status) status.textContent = signedIn ? `Signed in as ${user.display_name}` : "Sign in to continue.";
  if (logoutBtn) logoutBtn.classList.toggle("hidden", !signedIn);
  if (submitBtn) submitBtn.classList.toggle("hidden", signedIn);
  if (loginTab) loginTab.disabled = signedIn;
  if (registerTab) registerTab.disabled = signedIn;
  [usernameInput, passwordInput, displayInput].forEach((input) => {
    if (!input) return;
    input.disabled = signedIn;
  });
  if (displayInput) {
    if (signedIn) {
      displayInput.classList.add("hidden");
    } else {
      displayInput.classList.toggle("hidden", authMode !== "register");
    }
  }
  if (!signedIn) setAuthMode(authMode);
  setScreen(signedIn);
}

async function enterApp() {
  setScreen(true);
  if (el("messages")) el("messages").innerHTML = "";
  setAlerts([]);
  setCaseLink("");
  await loadAgents();
  await createSession();
  await initCalendar();
}

async function bindSessionUser() {
  if (!sessionId || !authToken) return;
  try {
    await fetchJson(`/host/sessions/${sessionId}/user`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({}),
    });
  } catch (e) {
    setAuthMessage(`Failed to bind user: ${errorText(e)}`, true);
  }
}

async function submitAuth() {
  const username = (el("authUsername") && el("authUsername").value || "").trim();
  const password = (el("authPassword") && el("authPassword").value || "").trim();
  const displayName = (el("authDisplayName") && el("authDisplayName").value || "").trim();

  if (!username || !password) {
    setAuthMessage("Username and password are required.", true);
    return;
  }

  const endpoint = authMode === "register" ? "/auth/register" : "/auth/login";
  const payload = { username, password };
  if (authMode === "register" && displayName) payload.display_name = displayName;

  try {
    setAuthMessage(authMode === "register" ? "Creating account..." : "Signing in...");
    const data = await fetchJson(endpoint, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(payload),
    });
    authToken = data.token;
    localStorage.setItem("authToken", authToken);
    setAuthState(data.user);
    await enterApp();
    await bindSessionUser();
    addBubble("system", `Signed in as ${data.user.display_name}.`);
  } catch (e) {
    setAuthMessage(errorText(e), true);
  }
}

async function logoutAuth() {
  try {
    if (authToken) {
      await fetchJson("/auth/logout", { method: "POST" });
    }
  } catch (e) {
    setAuthMessage(errorText(e), true);
  } finally {
    authToken = null;
    authUser = null;
    localStorage.removeItem("authToken");
    setAuthState(null);
    sessionId = null;
    latestCaseId = null;
    setCaseLink("");
    if (el("messages")) el("messages").innerHTML = "";
    resetCalendar();
    setAuthMessage("Signed out.");
  }
}

async function initAuth() {
  authToken = localStorage.getItem("authToken");
  if (authToken) {
    try {
      const data = await fetchJson("/auth/me");
      setAuthState(data.user);
      await enterApp();
      await bindSessionUser();
      return;
    } catch {
      authToken = null;
      localStorage.removeItem("authToken");
    }
  } else {
    authToken = null;
  }
  setAuthMode("login");
  setAuthState(null);
}

function addBubble(kind, text) {
  const bubble = document.createElement("div");
  bubble.className = `bubble ${kind}`;
  bubble.textContent = text;
  el("messages").appendChild(bubble);
  el("messages").scrollTop = el("messages").scrollHeight;
  return bubble;
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
  if (!caseId) {
    link.textContent = "—";
    link.href = "#";
  } else {
    link.textContent = caseId;
    link.href = `/case/${caseId}`;
  }
  const copyBtn = el("copyCaseBtn");
  if (copyBtn) copyBtn.disabled = !caseId;
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
  if (payload.topology) lines.push(`topology=${payload.topology}`);
  if (payload.message) lines.push(`message_sent=${payload.message}`);

  if (payload.baseline && payload.defended) {
    if (summary) renderSummary(summary, payload);
    if (chart) renderChart(chart, payload);
    const bm = payload.baseline && payload.baseline.decoded_message && payload.baseline.decoded_message.observer_total_ms;
    const dm = payload.defended && payload.defended.decoded_message && payload.defended.decoded_message.observer_total_ms;
    if (bm) lines.push(`decoded_message_baseline=${bm}`);
    if (dm) lines.push(`decoded_message_defended=${dm}`);
    if (bm || dm) lines.push("");
    lines.push(formatRun("baseline (no mitigation)", payload.baseline));
    lines.push("");
    lines.push(formatRun("defended (mitigation always)", payload.defended));
    box.textContent = lines.join("\n");
    return;
  }

  if (payload.per_bit) {
    if (summary) renderSummary(summary, payload);
    if (chart) renderChart(chart, payload);
    const m = payload.decoded_message && payload.decoded_message.observer_total_ms;
    if (m) lines.push(`decoded_message=${m}`);
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

function makeTaskId() {
  if (window.crypto && typeof window.crypto.randomUUID === "function") return window.crypto.randomUUID();
  return `task_${Math.random().toString(16).slice(2)}_${Date.now().toString(16)}`;
}

function pickPart(parts, kind) {
  if (!Array.isArray(parts)) return null;
  for (const p of parts) {
    if (p && typeof p === "object" && p.kind === kind) return p;
  }
  return null;
}

async function sendMessageStream(text) {
  const taskId = makeTaskId();
  const payload = {
    jsonrpc: "2.0",
    id: taskId,
    method: "message/sendSubscribe",
    params: {
      message: {
        contextId: sessionId,
        taskId,
        parts: [{ kind: "text", text }],
      },
    },
  };

  const headers = { "content-type": "application/json", accept: "text/event-stream" };
  if (authToken) headers["x-auth-token"] = authToken;
  const res = await fetch("/a2a/rpc", {
    method: "POST",
    headers,
    body: JSON.stringify(payload),
  });

  if (!res.ok) {
    const ct = (res.headers.get("content-type") || "").toLowerCase();
    if (ct.includes("application/json")) {
      const data = await res.json();
      const msg = formatErrorMessage(data, res.status);
      throw new Error(msg);
    }
    const t = await res.text();
    throw new Error(`${res.status} ${res.statusText}: ${t || "Request failed"}`);
  }

  const statusBubble = addBubble("system", "Stream: submitted…");
  const decoder = new TextDecoder("utf-8");
  const reader = res.body.getReader();
  let buf = "";

  const handleEvent = (event, data) => {
    if (event === "TaskStatusUpdateEvent") {
      const st = data && data.status ? data.status : null;
      const state = st && st.state ? st.state : "working";
      statusBubble.textContent = `Stream: ${state}…`;
      return;
    }

    if (event === "TaskArtifactUpdateEvent") {
      const art = data && data.artifact ? data.artifact : null;
      const parts = art && art.parts ? art.parts : [];
      const dataPart = pickPart(parts, "data");
      const textPart = pickPart(parts, "text");
      const resp = dataPart && dataPart.data ? dataPart.data : null;
      const reply = (resp && resp.reply) || (textPart && textPart.text) || "No reply.";

      if (resp && resp.case_id) setCaseLink(resp.case_id);
      if (resp && resp.alerts) setAlerts(resp.alerts);
      if (resp && resp.case_id) void refreshCase(resp.case_id);

      addBubble("assistant", reply);
      if (resp && resp.assistant) applyAssistantState(resp.assistant);
      scheduleCalendarRefresh();
      // Covert channel auto-demo is intentionally hidden from the chat UI.
      return;
    }
  };

  while (true) {
    const { value, done } = await reader.read();
    if (done) break;
    buf += decoder.decode(value, { stream: true });

    const frames = buf.split("\n\n");
    buf = frames.pop() || "";
    for (const frame of frames) {
      const lines = frame.split("\n");
      let event = "";
      const dataLines = [];
      for (const line of lines) {
        if (!line || line.startsWith(":")) continue;
        if (line.startsWith("event:")) event = line.slice(6).trim();
        if (line.startsWith("data:")) dataLines.push(line.slice(5).trim());
      }
      if (!dataLines.length) continue;
      const raw = dataLines.join("\n");
      let obj = null;
      try {
        obj = JSON.parse(raw);
      } catch {
        // ignore
      }
      handleEvent(event, obj);
    }
  }
}

async function sendMessage(text) {
  el("sendBtn").disabled = true;
  const covertBtn = el("covertBtn");
  if (covertBtn) covertBtn.disabled = true;
  addBubble("user", text);
  const useStream = Boolean(el("streamToggle") && el("streamToggle").checked);
  if (!useStream) addBubble("system", "Host agent routing tasks to agents…");

  try {
    if (useStream) {
      await sendMessageStream(text);
      return;
    }

    const data = await fetchJson(`/host/sessions/${sessionId}/messages`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ text }),
    });

    if (data.case_id) setCaseLink(data.case_id);
    if (data.alerts) setAlerts(data.alerts);
    if (data.case_id) void refreshCase(data.case_id);

    addBubble("assistant", data.reply || "No reply.");
    if (data.assistant) applyAssistantState(data.assistant);
    scheduleCalendarRefresh();
    // Covert channel auto-demo is intentionally hidden from the chat UI.
  } catch (e) {
    addBubble("system", `Error: ${String(e)}`);
  } finally {
    el("sendBtn").disabled = false;
    if (covertBtn) covertBtn.disabled = false;
  }
}

async function runCovertDemo() {
  el("sendBtn").disabled = true;
  el("covertBtn").disabled = true;
  addBubble("system", "Running covert experiment…");
  try {
    const channel = (el("covertChannel") && el("covertChannel").value) || "timing";
    const topology = Boolean(el("meshMode") && el("meshMode").checked) ? "mesh" : "single";
    const message = ((el("covertMessage") && el("covertMessage").value) || "HELLO").trim() || "HELLO";
    if (topology === "mesh" && channel !== "timing") throw new Error("Mesh mode supports timing channel only.");
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
        topology,
        message,
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
    const baseline = data.baseline || data;
    const decodedObj = baseline && typeof baseline.decoded_message === "object" ? baseline.decoded_message : null;
    let decoded = null;
    if (decodedObj) {
      if (channel === "size" || channel === "storage") {
        decoded = decodedObj.observer_size_bytes || decodedObj.observer_total_ms || decodedObj.agent_elapsed_ms;
      } else {
        decoded = decodedObj.observer_total_ms || decodedObj.agent_elapsed_ms || decodedObj.observer_size_bytes;
      }
    }
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

function openModal() {
  const modal = el("modal");
  if (!modal) return;
  modal.classList.remove("hidden");
  modal.setAttribute("aria-hidden", "false");
}

function closeModal() {
  const modal = el("modal");
  if (!modal) return;
  modal.classList.add("hidden");
  modal.setAttribute("aria-hidden", "true");
}

function openCalendarModal() {
  const modal = el("calendarModal");
  if (!modal) return;
  modal.classList.remove("hidden");
  modal.setAttribute("aria-hidden", "false");
  renderCalendar();
  renderCalendarDetail();
  void refreshCalendar();
}

function closeCalendarModal() {
  const modal = el("calendarModal");
  if (!modal) return;
  modal.classList.add("hidden");
  modal.setAttribute("aria-hidden", "true");
}

async function copyCaseId() {
  if (!latestCaseId) return;
  try {
    await navigator.clipboard.writeText(latestCaseId);
    addBubble("system", `Copied report id: ${latestCaseId}`);
  } catch {
    addBubble("system", "Copy failed (clipboard permission).");
  }
}

function loadSample() {
  const sel = el("sampleSelect");
  const input = el("input");
  if (!sel || !input) return;
  const key = sel.value || "assistant_today";
  input.value = SAMPLES[key] || SAMPLES.assistant_today;
  input.focus();
  addBubble("system", "Loaded sample prompt into the input box.");
}

function wire() {
  wireCalendar();
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

  const covertBtn = el("covertBtn");
  if (covertBtn) covertBtn.addEventListener("click", () => void runCovertDemo());
  el("clearBtn").addEventListener("click", () => clearChat());

  const commandsBtn = el("commandsBtn");
  if (commandsBtn) commandsBtn.addEventListener("click", () => openModal());
  const modalClose = el("modalClose");
  if (modalClose) modalClose.addEventListener("click", () => closeModal());
  const modalBackdrop = el("modalBackdrop");
  if (modalBackdrop) modalBackdrop.addEventListener("click", () => closeModal());

  const loadBtn = el("loadSampleBtn");
  if (loadBtn) loadBtn.addEventListener("click", () => loadSample());

  const copyBtn = el("copyCaseBtn");
  if (copyBtn) copyBtn.addEventListener("click", () => void copyCaseId());

  const loginTab = el("authLoginTab");
  if (loginTab) loginTab.addEventListener("click", () => setAuthMode("login"));
  const registerTab = el("authRegisterTab");
  if (registerTab) registerTab.addEventListener("click", () => setAuthMode("register"));
  const submitBtn = el("authSubmitBtn");
  if (submitBtn) submitBtn.addEventListener("click", () => void submitAuth());
  const logoutBtn = el("authLogoutBtn");
  if (logoutBtn) logoutBtn.addEventListener("click", () => void logoutAuth());

  const authInputs = [el("authUsername"), el("authPassword"), el("authDisplayName")].filter(Boolean);
  authInputs.forEach((input) => {
    input.addEventListener("keydown", (e) => {
      if (e.key === "Enter") {
        e.preventDefault();
        void submitAuth();
      }
    });
  });

  window.addEventListener("keydown", (e) => {
    if (e.key === "Escape") {
      closeModal();
      closeCalendarModal();
    }
  });
}

window.addEventListener("DOMContentLoaded", () => {
  wire();
  void initAuth();
});
