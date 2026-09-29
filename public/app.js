"use strict";

const scenarios = window.SCENARIOS;

const SIGNALS = [
  ["unusual_payment", "Unusual payment"],
  ["sensitive_info", "Sensitive info"],
  ["remote_access", "Remote access"],
  ["threat_consequence", "Threat"],
  ["authority_claim", "Authority claim"],
  ["urgency_pressure", "Urgency"],
  ["secrecy_isolation", "Secrecy"],
];

const SHORT = {
  unusual_payment: "PAYMENT",
  sensitive_info: "SENSITIVE",
  remote_access: "REMOTE",
  threat_consequence: "THREAT",
  authority_claim: "AUTHORITY",
  urgency_pressure: "URGENCY",
  secrecy_isolation: "SECRECY",
};

// Must match the weights in src/server.js.
const WEIGHTS = {
  unusual_payment: 0.22,
  sensitive_info: 0.2,
  remote_access: 0.16,
  threat_consequence: 0.12,
  authority_claim: 0.12,
  urgency_pressure: 0.1,
  secrecy_isolation: 0.08,
};

const NEUTRALS = ["#0a0a0a", "#3a3a38", "#6b6b6b", "#9a9a96", "#c0c0bc", "#d8d8d2", "#e6e6e3"];
const SPEEDS = [0.5, 1, 2, 4];

const els = {
  scenarioList: document.getElementById("scenario-list"),
  customPanel: document.getElementById("custom-panel"),
  customInput: document.getElementById("custom-input"),
  customPreview: document.getElementById("custom-preview"),
  customLoad: document.getElementById("custom-load"),
  loadedStrip: document.getElementById("loaded-strip"),
  minimap: document.getElementById("minimap"),
  counter: document.getElementById("counter"),
  reviewBadge: document.getElementById("review-badge"),
  transcript: document.getElementById("transcript"),
  keyPlay: document.getElementById("key-play"),
  keyPlayIcon: document.getElementById("key-play-icon"),
  keyPlayLabel: document.getElementById("key-play-label"),
  led: document.getElementById("led"),
  keyBack: document.getElementById("key-back"),
  keyFwd: document.getElementById("key-fwd"),
  keyEnd: document.getElementById("key-end"),
  keyReset: document.getElementById("key-reset"),
  keySpeed: document.getElementById("key-speed"),
  lcdScore: document.getElementById("lcd-score"),
  bandWord: document.getElementById("band-word"),
  alertReadout: document.getElementById("alert-readout"),
  stamp: document.getElementById("stamp"),
  riskValue: document.getElementById("risk-value"),
  verdictValue: document.getElementById("verdict-value"),
  gap: document.getElementById("gap"),
  timeline: document.getElementById("timeline"),
  sortToggle: document.getElementById("sort-toggle"),
  viewToggle: document.getElementById("view-toggle"),
  meters: document.getElementById("meters"),
  heatmap: document.getElementById("heatmap"),
  contribSegments: document.getElementById("contrib-segments"),
  contribLegend: document.getElementById("contrib-legend"),
  errorBanner: document.getElementById("error-banner"),
  ariaLive: document.getElementById("aria-live"),
};

const state = {
  name: "",
  source: "preset",
  customOpen: false,
  lines: [],
  history: [],
  current: 0,
  completed: false,
  playing: false,
  timer: null,
  speed: 1,
  gen: 0,
  sort: false,
  view: "meters",
  flashTurn: null,
  results: {},
  baseInterval: 1500,
};

const zeroSignals = () => Object.fromEntries(SIGNALS.map(([k]) => [k, 0]));
const snapshot0 = () => ({ riskScore: 0, verdict: 0, signals: zeroSignals() });

const pad = (n, w = 2) => String(n).padStart(w, "0");
const pct = (v) => `${Math.round(v * 100)}%`;
const snap = (k) => state.history[k] || snapshot0();
const curSnap = () => snap(state.current);
const bandOf = (r) => (r >= 0.7 ? "alert" : r >= 0.3 ? "watch" : "clear");
const verdictLabel = (v) => (v >= 0.7 ? "SCAM" : v >= 0.3 ? "SUSPECT" : "CLEAR");
const reveal = () => (state.completed ? state.lines.length : state.current);

function alertTurn() {
  for (let k = 1; k <= state.lines.length; k++) {
    const h = state.history[k];
    if (h && h.riskScore >= 0.7) return k;
  }
  return 0;
}

function lerpColor(a, b, t) {
  const c = a.map((x, i) => Math.round(x + (b[i] - x) * t));
  return `rgb(${c[0]},${c[1]},${c[2]})`;
}

// Light grey -> ink below the alert threshold, ink -> orange above it.
function heatColor(v) {
  if (v >= 0.7) return lerpColor([10, 10, 10], [255, 90, 31], Math.min(1, (v - 0.7) / 0.3));
  return lerpColor([230, 230, 227], [10, 10, 10], Math.min(1, v / 0.7));
}

/* ---------------- API ---------------- */

async function analyze(lines) {
  clearError();
  const res = await fetch("/api/analyze", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ lines }),
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    throw new Error(data.detail || data.error || `Request failed (${res.status})`);
  }
  return data;
}

/* ---------------- history ---------------- */

function resetForLoad() {
  state.current = 0;
  state.completed = false;
  state.flashTurn = null;
  state.sort = false;
  state.history = new Array(state.lines.length + 1).fill(null);
  state.history[0] = snapshot0();
  render();
  computeHistory();
}

async function computeHistory() {
  const gen = ++state.gen;
  const jobs = [];
  for (let k = 1; k <= state.lines.length; k++) jobs.push(computeTurn(k, gen));
  await Promise.allSettled(jobs);
}

async function computeTurn(k, gen) {
  try {
    const s = await analyze(state.lines.slice(0, k));
    if (gen !== state.gen) return;
    state.history[k] = s;
    render();
  } catch (err) {
    if (gen !== state.gen) return;
    showError(err.message);
  }
}

/* ---------------- actions ---------------- */

async function goTo(k, opts = {}) {
  const { flash = true } = opts;
  k = Math.max(0, Math.min(state.lines.length, k));
  if (k > 0 && !state.history[k]) {
    await computeTurn(k, state.gen);
  }
  state.current = k;
  if (k === state.lines.length) {
    state.completed = true;
    if (state.history[k]) state.results[state.name] = state.history[k].riskScore;
  }
  state.flashTurn = flash ? k : null;
  render();
  if (flash) {
    const ft = k;
    setTimeout(() => {
      if (state.flashTurn === ft) state.flashTurn = null;
      const el = els.transcript.querySelector(`.turn-row[data-turn="${ft}"]`);
      if (el) el.classList.remove("flash");
    }, 250);
  }
}

function playPause() {
  if (state.playing) {
    stop();
    return;
  }
  if (state.current >= state.lines.length) {
    state.completed = false;
    goTo(0, { flash: false });
  }
  state.playing = true;
  render();
  tick();
}

async function tick() {
  if (!state.playing) return;
  if (state.current >= state.lines.length) {
    stop();
    return;
  }
  await goTo(state.current + 1);
  if (!state.playing) return;
  state.timer = setTimeout(tick, Math.max(100, state.baseInterval / state.speed));
}

function stop() {
  state.playing = false;
  clearTimeout(state.timer);
  render();
}

function stepFwd() {
  if (state.playing) stop();
  if (state.current < state.lines.length) goTo(state.current + 1);
}

function stepBack() {
  if (state.playing) stop();
  if (state.current > 0) goTo(state.current - 1, { flash: false });
}

function jumpEnd() {
  if (state.playing) stop();
  goTo(state.lines.length);
}

function resetAll() {
  if (state.playing) stop();
  state.completed = false;
  goTo(0, { flash: false });
}

function cycleSpeed() {
  const i = SPEEDS.indexOf(state.speed);
  state.speed = SPEEDS[(i + 1) % SPEEDS.length];
  render();
}

/* ---------------- scenario / custom ---------------- */

function loadScenario(i) {
  state.customOpen = false;
  els.customPanel.hidden = true;
  const s = scenarios[i];
  state.name = s.name;
  state.source = "preset";
  state.lines = s.lines;
  resetForLoad();
}

function loadCustom(lines) {
  state.customOpen = true;
  els.customPanel.hidden = false;
  state.name = "Custom";
  state.source = "custom";
  state.lines = lines;
  resetForLoad();
}

function selectCustomRow() {
  state.customOpen = true;
  els.customPanel.hidden = false;
  render();
  els.customInput.focus();
}

function parseCustom(text) {
  const lines = [];
  const problems = [];
  text.split("\n").forEach((raw, i) => {
    const t = raw.trim();
    if (!t) return;
    const m = t.match(/^(caller|callee)\s*:\s*(.+)$/i);
    if (!m) {
      problems.push(i);
      return;
    }
    lines.push({ speaker: m[1].toLowerCase(), text: m[2].trim() });
  });
  return { lines, problems };
}

function updateCustomPreview() {
  const { lines, problems } = parseCustom(els.customInput.value);
  const counts = { caller: 0, callee: 0 };
  for (const l of lines) counts[l.speaker] += 1;
  let text = lines.length
    ? `✓ ${lines.length} turn${lines.length > 1 ? "s" : ""} parsed · ${counts.caller} caller · ${counts.callee} callee`
    : "0 turns parsed";
  if (problems.length) {
    text += ` · ⚠ line${problems.length > 1 ? "s" : ""} ${problems.map((i) => i + 1).join(", ")} need "Caller:" or "Callee:"`;
  }
  els.customPreview.textContent = text;
  els.customLoad.disabled = lines.length === 0;
}

function useCustom() {
  const { lines } = parseCustom(els.customInput.value);
  if (lines.length === 0) return;
  loadCustom(lines);
}

/* ---------------- error ---------------- */

function showError(message) {
  els.errorBanner.textContent = message;
  els.errorBanner.classList.add("has-error");
  els.errorBanner.hidden = false;
}

function clearError() {
  els.errorBanner.hidden = true;
  els.errorBanner.classList.remove("has-error");
}

/* ---------------- render ---------------- */

function render() {
  renderScenarios();
  renderLoadedStrip();
  renderMinimap();
  renderTranscript();
  renderScore();
  renderTimeline();
  renderMeters();
  renderContribution();
  renderTransport();
}

function renderScenarios() {
  els.scenarioList.innerHTML = "";
  scenarios.forEach((s, i) => {
    const row = document.createElement("li");
    row.className = "scenario-row";
    if (state.source === "preset" && state.name === s.name) row.classList.add("selected");
    row.append(scenarioName(s.name), scenarioRight(s.lines.length, state.results[s.name]));
    row.addEventListener("click", () => loadScenario(i));
    els.scenarioList.appendChild(row);
  });
  const customRow = document.createElement("li");
  customRow.className = "scenario-row";
  if (state.customOpen) customRow.classList.add("selected");
  customRow.append(
    scenarioName("custom"),
    scenarioRight(state.source === "custom" ? state.lines.length : 0, state.results["Custom"]),
  );
  customRow.addEventListener("click", selectCustomRow);
  els.scenarioList.appendChild(customRow);
}

function scenarioName(text) {
  const el = document.createElement("span");
  el.className = "scenario-name";
  el.textContent = text;
  return el;
}

function scenarioRight(turns, score) {
  const wrap = document.createElement("span");
  wrap.className = "scenario-right";
  const t = document.createElement("span");
  t.className = "scenario-turns";
  t.textContent = turns ? pad(turns) : "—";
  wrap.appendChild(t);
  if (score != null) {
    const s = document.createElement("span");
    s.className = "scenario-score";
    s.textContent = `LAST ${pct(score)}`;
    wrap.appendChild(s);
  }
  return wrap;
}

function renderLoadedStrip() {
  const name = state.source === "custom" ? "custom" : state.name;
  const kind = state.source === "custom" ? "custom" : "preset";
  els.loadedStrip.textContent = `LOADED: ${name.toUpperCase()} · ${state.lines.length} TURNS · ${kind.toUpperCase()}`;
}

function renderMinimap() {
  els.minimap.innerHTML = "";
  const N = state.lines.length;
  const rv = reveal();
  for (let k = 1; k <= N; k++) {
    const cell = document.createElement("button");
    cell.className = "mini-cell";
    const h = state.history[k];
    if (h && k <= rv) {
      cell.style.background = heatColor(h.riskScore);
    }
    if (k === state.current) cell.classList.add("active");
    cell.setAttribute("aria-label", `seek to turn ${k}`);
    cell.addEventListener("click", () => goTo(k));
    els.minimap.appendChild(cell);
  }
  els.counter.textContent = `${pad(state.current)}/${pad(N)}`;
  els.reviewBadge.hidden = !state.completed;
}

function renderTranscript() {
  const box = els.transcript;
  box.innerHTML = "";
  const at = alertTurn();
  const N = state.lines.length;
  const rv = reveal();
  for (let k = 1; k <= N; k++) {
    const line = state.lines[k - 1];
    const h = snap(k);
    const prev = snap(k - 1);
    const row = document.createElement("div");
    row.className = "turn-row";
    row.dataset.turn = k;
    if (k > state.current) row.classList.add("future");
    else if (k === state.current) row.classList.add("current");
    else row.classList.add("past");
    if (k === at && k <= rv) row.classList.add("alert");
    if (k === state.flashTurn) row.classList.add("flash");

    let heatVal = 0;
    if (k <= rv) {
      const riskDelta = h.riskScore - prev.riskScore;
      heatVal = riskDelta > 0.01 ? Math.min(1, riskDelta / 0.5) : 0;
    }
    row.style.setProperty("--heat", String(heatVal));

    const lineNo = document.createElement("div");
    lineNo.className = "line-no";
    lineNo.textContent = pad(k);

    const speaker = document.createElement("div");
    speaker.className = "speaker";
    speaker.textContent = line.speaker.toUpperCase();

    const text = document.createElement("div");
    text.className = "text";
    text.textContent = line.text;

    const chips = document.createElement("div");
    chips.className = "chips";
    if (k <= rv) {
      const deltas = [];
      for (const [key] of SIGNALS) {
        const d = h.signals[key] - prev.signals[key];
        if (d >= 0.15) deltas.push([key, d]);
      }
      deltas.sort((a, b) => b[1] - a[1]);
      for (const [key, d] of deltas.slice(0, 3)) {
        const c = document.createElement("span");
        c.className = "chip";
        c.textContent = `${SHORT[key]} +${Math.round(d * 100)}`;
        chips.appendChild(c);
      }
    }

    row.append(lineNo, speaker, text, chips);
    row.tabIndex = 0;
    row.addEventListener("click", () => goTo(k));
    row.addEventListener("keydown", (e) => {
      if (e.code === "Enter" || e.code === "Space") {
        e.preventDefault();
        goTo(k);
      }
    });
    box.appendChild(row);
  }
  const cur = box.querySelector(".turn-row.current");
  if (cur) {
    box.scrollTop = cur.offsetTop - box.clientHeight / 2 + cur.clientHeight / 2;
  } else {
    box.scrollTop = 0;
  }
}

function renderScore() {
  const s = curSnap();
  const risk = state.current > 0 ? s.riskScore : 0;
  const verdict = state.current > 0 ? s.verdict : null;
  const band = bandOf(risk);
  const rv = reveal();

  els.lcdScore.textContent = String(Math.round(risk * 100)).padStart(3, " ");
  els.lcdScore.classList.toggle("hot", band === "alert");
  els.bandWord.textContent = band;

  if (verdict == null) {
    els.stamp.textContent = "— awaiting —";
    els.stamp.className = "stamp awaiting";
  } else {
    const label = verdictLabel(verdict);
    els.stamp.textContent = label;
    els.stamp.className = `stamp ${label.toLowerCase()}`;
  }

  els.riskValue.textContent = pct(risk);
  els.verdictValue.textContent = verdict == null ? "—" : pct(verdict);

  if (verdict == null) {
    els.gap.textContent = "";
  } else {
    const d = Math.round((verdict - risk) * 100);
    els.gap.textContent = Math.abs(d) < 1 ? "EVEN" : d > 0 ? `MODEL AHEAD BY ${Math.abs(d)}` : `SIGNALS AHEAD BY ${Math.abs(d)}`;
  }

  const at = alertTurn();
  if (at > 0 && at <= rv) {
    els.alertReadout.className = "alert-readout fired";
    els.alertReadout.innerHTML = `<span class="alert-big">ALERT @ TURN ${pad(at)}</span><span class="alert-sub">we would have warned the victim here</span>`;
  } else {
    els.alertReadout.className = "alert-readout pending";
    els.alertReadout.innerHTML = `<span class="alert-big">no alert yet</span><span class="alert-sub">keep watching the call</span>`;
  }

  renderLeds();

  if (state.current > 0) {
    const announce = `${Math.round(risk * 100)} percent risk, ${band} band`;
    els.ariaLive.textContent = at > 0 && at <= rv ? `${announce}, alert at turn ${at}` : announce;
  }
}

function renderLeds() {
  const N = state.lines.length;
  const computing = N > 0 && state.history.slice(1).some((h) => !h);
  const status =
    N > 0 && state.current === N && !computing
      ? "done"
      : state.playing || computing
        ? "live"
        : "idle";
  document.querySelectorAll(".led-led").forEach((el) => {
    el.classList.toggle("on", el.dataset.led === status);
  });
  document.body.classList.toggle("scanning", computing);
}

function renderTimeline() {
  const N = state.lines.length;
  if (N === 0) {
    els.timeline.innerHTML = "";
    return;
  }
  const rv = reveal();
  const W = 320;
  const H = 128;
  const padX = 20;
  const padY = 12;
  const x = (k) => (N <= 1 ? W / 2 : padX + ((k - 1) / (N - 1)) * (W - 2 * padX));
  const y = (v) => padY + (1 - v) * (H - 2 * padY);

  const parts = [];
  parts.push(`<line x1="${padX}" y1="${y(0.7)}" x2="${W - padX}" y2="${y(0.7)}" class="th alert"/>`);
  parts.push(`<line x1="${padX}" y1="${y(0.3)}" x2="${W - padX}" y2="${y(0.3)}" class="th watch"/>`);

  const cPts = [];
  const vPts = [];
  for (let k = 1; k <= rv; k++) {
    const h = state.history[k];
    if (!h) continue;
    cPts.push(`${x(k).toFixed(1)},${y(h.riskScore).toFixed(1)}`);
    vPts.push(`${x(k).toFixed(1)},${y(h.verdict).toFixed(1)}`);
  }
  if (cPts.length) parts.push(`<polyline points="${cPts.join(" ")}" class="line composed"/>`);
  if (vPts.length) parts.push(`<polyline points="${vPts.join(" ")}" class="line verdict"/>`);
  for (let k = 1; k <= rv; k++) {
    const h = state.history[k];
    if (h) parts.push(`<circle cx="${x(k)}" cy="${y(h.riskScore)}" r="2" class="dot"/>`);
  }
  const at = alertTurn();
  if (at > 0 && at <= rv && state.history[at]) {
    parts.push(`<circle cx="${x(at)}" cy="${y(state.history[at].riskScore)}" r="3.5" class="alert-dot"/>`);
  }
  if (state.current > 0) {
    parts.push(`<line x1="${x(state.current)}" y1="${padY}" x2="${x(state.current)}" y2="${H - padY}" class="playhead"/>`);
  }

  els.timeline.innerHTML = `<svg viewBox="0 0 ${W} ${H}" preserveAspectRatio="none" class="timeline-svg" role="img" aria-label="Score timeline">${parts.join("")}</svg>`;
  const svg = els.timeline.querySelector("svg");
  svg.addEventListener("click", (e) => {
    const r = svg.getBoundingClientRect();
    const fx = (e.clientX - r.left) / r.width;
    const k = Math.max(1, Math.min(N, Math.round(1 + fx * (N - 1))));
    goTo(k);
  });
}

function peakSignals() {
  const peak = zeroSignals();
  for (let k = 1; k <= state.current; k++) {
    const h = state.history[k];
    if (!h) continue;
    for (const key of Object.keys(peak)) peak[key] = Math.max(peak[key], h.signals[key]);
  }
  return peak;
}

function renderMeters() {
  if (state.view !== "meters") {
    els.meters.hidden = true;
    els.heatmap.hidden = false;
    renderHeatmap();
    return;
  }
  els.meters.hidden = false;
  els.heatmap.hidden = true;

  const s = curSnap();
  const cur = state.current > 0 ? s.signals : zeroSignals();
  const peak = peakSignals();
  const prev = snap(state.current - 1).signals;

  let order = SIGNALS.slice();
  if (state.sort) order.sort((a, b) => cur[b[0]] - cur[a[0]]);

  els.meters.innerHTML = "";
  for (const [key, label] of order) {
    const v = cur[key];
    const row = document.createElement("div");
    row.className = "meter-row";
    if (v < 0.1) row.classList.add("dim");

    const name = document.createElement("span");
    name.className = "meter-name";
    name.textContent = label.toLowerCase();

    const track = document.createElement("span");
    track.className = "meter-track";
    const litCount = Math.round(v * 20);
    for (let i = 0; i < 20; i++) {
      const c = document.createElement("span");
      c.className = "seg";
      const lit = i < litCount;
      c.classList.toggle("lit", lit);
      c.classList.toggle("hot", lit && (i + 0.5) / 20 >= 0.7);
      track.appendChild(c);
    }
    const mk = document.createElement("span");
    mk.className = "peak";
    mk.style.left = `${Math.max(0, Math.min(1, peak[key])) * 100}%`;
    track.appendChild(mk);

    const val = document.createElement("span");
    val.className = "meter-value";
    val.textContent = `${pad(Math.round(v * 100))}%`;

    row.append(name, track, val);

    const d = v - prev[key];
    if (state.flashTurn === state.current && state.current > 0 && d >= 0.05) {
      const f = document.createElement("span");
      f.className = "flash-delta";
      f.textContent = `+${Math.round(d * 100)}`;
      row.appendChild(f);
    }

    els.meters.appendChild(row);
  }
}

function renderHeatmap() {
  const N = state.lines.length;
  els.heatmap.innerHTML = "";
  if (N === 0) return;
  const rv = reveal();

  const head = document.createElement("div");
  head.className = "heat-row heat-head";
  head.style.setProperty("--n", N);
  const spacer = document.createElement("span");
  spacer.className = "heat-label";
  head.appendChild(spacer);
  for (let k = 1; k <= N; k++) {
    const c = document.createElement("button");
    c.className = "heat-col-head" + (k === state.current ? " active" : "");
    c.textContent = pad(k);
    c.addEventListener("click", () => goTo(k));
    head.appendChild(c);
  }
  els.heatmap.appendChild(head);

  for (const [key, label] of SIGNALS) {
    const row = document.createElement("div");
    row.className = "heat-row";
    row.style.setProperty("--n", N);
    const name = document.createElement("span");
    name.className = "heat-label";
    name.textContent = label.toLowerCase();
    row.appendChild(name);
    for (let k = 1; k <= N; k++) {
      const cell = document.createElement("button");
      cell.type = "button";
      cell.className = "heat-cell";
      const h = state.history[k];
      if (h && k <= rv) {
        cell.style.background = heatColor(h.signals[key]);
      }
      if (k === state.current) cell.classList.add("active");
      cell.setAttribute("aria-label", `${label.toLowerCase()} at turn ${k}`);
      cell.addEventListener("click", () => goTo(k));
      row.appendChild(cell);
    }
    els.heatmap.appendChild(row);
  }
}

function renderContribution() {
  els.contribSegments.innerHTML = "";
  els.contribLegend.innerHTML = "";
  const s = curSnap();
  const risk = state.current > 0 ? s.riskScore : 0;
  if (risk <= 0) return;
  const sig = state.current > 0 ? s.signals : zeroSignals();
  const order = SIGNALS.slice().sort(
    (a, b) => WEIGHTS[b[0]] * sig[b[0]] - WEIGHTS[a[0]] * sig[a[0]],
  );
  SIGNALS.forEach(([key], i) => {
    const contrib = WEIGHTS[key] * sig[key];
    if (contrib < 0.005) return;
    const color = sig[key] >= 0.7 ? "#ff5a1f" : NEUTRALS[i % NEUTRALS.length];
    const seg = document.createElement("span");
    seg.className = "contrib-seg";
    seg.style.width = `${contrib * 100}%`;
    seg.style.background = color;
    seg.title = `${SHORT[key]} ${Math.round(contrib * 100)}`;
    els.contribSegments.appendChild(seg);

    const li = document.createElement("span");
    li.className = "contrib-legend-item";
    const swatch = document.createElement("span");
    swatch.className = "contrib-swatch";
    swatch.style.background = color;
    li.append(swatch, document.createTextNode(`${SHORT[key].toLowerCase()} ${Math.round(contrib * 100)}`));
    els.contribLegend.appendChild(li);
  });
  void order;
}

function renderTransport() {
  const atEnd = state.current === state.lines.length && state.lines.length > 0;
  els.keyPlayLabel.textContent = atEnd ? "replay" : state.playing ? "pause" : "play";
  els.keyPlayIcon.textContent = state.playing ? "▮▮" : atEnd ? "↻" : "▶";
  els.led.classList.toggle("on", state.playing);
  els.keySpeed.textContent = `${state.speed}×`;
  els.viewToggle.textContent = state.view === "meters" ? "dist" : "meters";
  els.sortToggle.classList.toggle("on", state.sort);
  els.viewToggle.classList.toggle("on", state.view === "dist");
}

/* ---------------- init ---------------- */

function init() {
  els.keyPlay.addEventListener("click", playPause);
  els.keyBack.addEventListener("click", stepBack);
  els.keyFwd.addEventListener("click", stepFwd);
  els.keyEnd.addEventListener("click", jumpEnd);
  els.keyReset.addEventListener("click", resetAll);
  els.keySpeed.addEventListener("click", cycleSpeed);
  els.sortToggle.addEventListener("click", () => {
    state.sort = !state.sort;
    render();
  });
  els.viewToggle.addEventListener("click", () => {
    state.view = state.view === "meters" ? "dist" : "meters";
    render();
  });
  els.customInput.addEventListener("input", updateCustomPreview);
  els.customLoad.addEventListener("click", useCustom);

  window.addEventListener("keydown", (e) => {
    if (e.target.matches("textarea, input, select, button")) {
      if (e.target.tagName === "BUTTON" && e.code === "Space") return;
      return;
    }
    if (e.code === "Space") {
      e.preventDefault();
      playPause();
    } else if (e.code === "ArrowLeft") {
      e.preventDefault();
      stepBack();
    } else if (e.code === "ArrowRight") {
      e.preventDefault();
      stepFwd();
    } else if (e.code === "Home") {
      e.preventDefault();
      resetAll();
    } else if (e.code === "End") {
      e.preventDefault();
      jumpEnd();
    }
  });

  loadScenario(0);
}

init();
