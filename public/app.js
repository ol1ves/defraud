const scenarios = window.SCENARIOS;

const SIGNAL_LABELS = {
  unusual_payment: "Unusual payment",
  sensitive_info: "Sensitive info",
  remote_access: "Remote access",
  threat_consequence: "Threat",
  authority_claim: "Authority claim",
  urgency_pressure: "Urgency",
  secrecy_isolation: "Secrecy",
};

const els = {
  select: document.getElementById("scenario-select"),
  progress: document.getElementById("progress"),
  play: document.getElementById("play-btn"),
  step: document.getElementById("step-btn"),
  end: document.getElementById("end-btn"),
  reset: document.getElementById("reset-btn"),
  interval: document.getElementById("interval-input"),
  transcript: document.getElementById("transcript"),
  riskScore: document.getElementById("risk-score"),
  verdict: document.getElementById("verdict"),
  signals: document.getElementById("signals"),
  customInput: document.getElementById("custom-input"),
  customBtn: document.getElementById("custom-btn"),
  customStatus: document.getElementById("custom-status"),
  errorBanner: document.getElementById("error-banner"),
};

let current = { name: "", lines: [] };
let index = 0;
let timer = null;

function buildSignals() {
  els.signals.innerHTML = "";
  for (const [key, label] of Object.entries(SIGNAL_LABELS)) {
    const row = document.createElement("div");
    row.className = "signal-row";
    row.innerHTML = `
      <span class="signal-name">${label}</span>
      <span class="signal-track"><span class="signal-fill" data-signal="${key}"></span></span>
      <span class="signal-value" data-signal="${key}">0%</span>
    `;
    els.signals.appendChild(row);
  }
}

function renderTranscript(lines) {
  els.transcript.innerHTML = "";
  lines.forEach((line, i) => {
    const turn = document.createElement("div");
    turn.className = `turn ${line.speaker}${i === lines.length - 1 ? " latest" : ""}`;
    const who = document.createElement("span");
    who.className = "who";
    who.textContent = line.speaker;
    turn.appendChild(who);
    turn.appendChild(document.createTextNode(line.text));
    els.transcript.appendChild(turn);
  });
  els.transcript.scrollTop = els.transcript.scrollHeight;
}

function renderScore(data) {
  const pct = (value) => `${Math.round(value * 100)}%`;
  els.riskScore.textContent = pct(data.riskScore);
  els.verdict.textContent = pct(data.verdict);
  for (const [key, value] of Object.entries(data.signals)) {
    const fill = els.signals.querySelector(`.signal-fill[data-signal="${key}"]`);
    const label = els.signals.querySelector(`.signal-value[data-signal="${key}"]`);
    if (fill) fill.style.width = pct(value);
    if (label) label.textContent = pct(value);
  }
}

function resetScore() {
  els.riskScore.textContent = "0%";
  els.verdict.textContent = "—";
  for (const key of Object.keys(SIGNAL_LABELS)) {
    const fill = els.signals.querySelector(`.signal-fill[data-signal="${key}"]`);
    const label = els.signals.querySelector(`.signal-value[data-signal="${key}"]`);
    if (fill) fill.style.width = "0%";
    if (label) label.textContent = "0%";
  }
}

function showError(message) {
  els.errorBanner.textContent = message;
  els.errorBanner.classList.add("has-error");
  els.errorBanner.hidden = false;
}

function clearError() {
  els.errorBanner.hidden = true;
  els.errorBanner.classList.remove("has-error");
}

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

function stop() {
  if (timer) {
    clearInterval(timer);
    timer = null;
  }
  els.play.textContent = "Play";
}

function updateProgress() {
  els.progress.textContent = `${index} / ${current.lines.length}`;
}

async function step() {
  if (index >= current.lines.length) return;
  index += 1;
  updateProgress();
  const revealed = current.lines.slice(0, index);
  renderTranscript(revealed);
  try {
    renderScore(await analyze(revealed));
  } catch (err) {
    showError(err.message);
  }
}

async function jumpToEnd() {
  stop();
  if (current.lines.length === 0) return;
  index = current.lines.length;
  updateProgress();
  renderTranscript(current.lines);
  try {
    renderScore(await analyze(current.lines));
  } catch (err) {
    showError(err.message);
  }
}

function reset() {
  stop();
  index = 0;
  updateProgress();
  renderTranscript([]);
  resetScore();
}

function loadScenario(scenario) {
  stop();
  current = { name: scenario.name, lines: scenario.lines };
  index = 0;
  updateProgress();
  renderTranscript([]);
  resetScore();
}

function play() {
  if (timer) {
    stop();
    return;
  }
  if (index >= current.lines.length) {
    index = 0;
    updateProgress();
    renderTranscript([]);
    resetScore();
  }
  const intervalMs = Math.max(100, Number(els.interval.value) || 1500);
  els.play.textContent = "Pause";
  timer = setInterval(async () => {
    if (index >= current.lines.length) {
      stop();
      return;
    }
    await step();
  }, intervalMs);
}

function parseCustom(text) {
  const lines = [];
  for (const raw of text.split("\n")) {
    const trimmed = raw.trim();
    if (!trimmed) continue;
    const match = trimmed.match(/^(caller|callee)\s*:\s*(.+)$/i);
    if (!match) {
      return { error: `Each line needs "Caller:" or "Callee:" first. Offending line: "${trimmed}"` };
    }
    lines.push({ speaker: match[1].toLowerCase(), text: match[2].trim() });
  }
  if (lines.length === 0) {
    return { error: "Transcript is empty." };
  }
  return { lines };
}

function useCustom() {
  const parsed = parseCustom(els.customInput.value);
  if (parsed.error) {
    els.customStatus.textContent = parsed.error;
    return;
  }
  els.customStatus.textContent = "";
  loadScenario({ name: "Custom transcript", lines: parsed.lines });
  els.select.value = "__custom";
}

function init() {
  buildSignals();
  scenarios.forEach((scenario, i) => {
    const option = document.createElement("option");
    option.value = String(i);
    option.textContent = scenario.name;
    els.select.appendChild(option);
  });
  const customOption = document.createElement("option");
  customOption.value = "__custom";
  customOption.textContent = "Custom transcript";
  els.select.appendChild(customOption);

  els.select.addEventListener("change", () => {
    if (els.select.value === "__custom") {
      useCustom();
      return;
    }
    loadScenario(scenarios[Number(els.select.value)]);
  });

  els.play.addEventListener("click", play);
  els.step.addEventListener("click", step);
  els.end.addEventListener("click", jumpToEnd);
  els.reset.addEventListener("click", reset);
  els.customBtn.addEventListener("click", useCustom);

  loadScenario(scenarios[0]);
}

init();
