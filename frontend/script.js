const $ = (s) => document.querySelector(s);
const esc = (s) =>
  String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

/* =========================================================
   ANALOG SPEEDOMETER GAUGE
   0..100 mapped to a 270° sweep: starts bottom-left (135°),
   passes over the top, ends bottom-right (45°).
   ========================================================= */
const CX = 200, CY = 200;
const COLORS = { safe: "#10B981", warn: "#F59E0B", danger: "#EF4444" };
const ZONES = [
  { from: 0, to: 40, cls: "safe" },
  { from: 40, to: 70, cls: "warn" },
  { from: 70, to: 100, cls: "danger" },
];

const angle = (v) => ((135 + v * 2.7) * Math.PI) / 180;
const pt = (r, v) => [CX + r * Math.cos(angle(v)), CY + r * Math.sin(angle(v))];
const arc = (r, v1, v2) => {
  const [x1, y1] = pt(r, v1);
  const [x2, y2] = pt(r, v2);
  const large = (v2 - v1) * 2.7 > 180 ? 1 : 0;
  return `M${x1.toFixed(2)} ${y1.toFixed(2)} A${r} ${r} 0 ${large} 1 ${x2.toFixed(2)} ${y2.toFixed(2)}`;
};
const zoneOf = (score) => (score < 40 ? "safe" : score < 70 ? "warn" : "danger");

function buildGauge() {
  let s = `
    <circle cx="200" cy="200" r="185" fill="#0A0D14" stroke="#1E293B" stroke-width="3"/>
    <circle cx="200" cy="200" r="175" fill="none" stroke="#1E293B" stroke-width="1"/>`;

  ZONES.forEach((z) => (s += `<path class="zone ${z.cls}" d="${arc(160, z.from, z.to)}"/>`));

  for (let v = 0; v <= 100; v += 2) {
    const major = v % 10 === 0;
    const [x1, y1] = pt(146, v);
    const [x2, y2] = pt(major ? 126 : 137, v);
    s += `<line x1="${x1.toFixed(2)}" y1="${y1.toFixed(2)}" x2="${x2.toFixed(2)}" y2="${y2.toFixed(2)}"
           stroke="${major ? "#F8FAFC" : "#94A3B8"}" stroke-width="${major ? 2.5 : 1.2}" stroke-linecap="round"/>`;
    if (major) {
      const [tx, ty] = pt(106, v);
      s += `<text class="tick-label" x="${tx.toFixed(2)}" y="${ty.toFixed(2)}">${v}</text>`;
    }
  }

  s += `
    <text class="g-label" x="200" y="246">RISK INDEX</text>
    <text class="g-score" id="g-score" x="200" y="292">0</text>
    <text class="g-verdict" id="g-verdict" x="200" y="324">AWAITING SCAN</text>
    <g transform="translate(200,200)">
      <g id="needle"><polygon points="-26,-3.5 0,-5 136,0 0,5 -26,3.5"/></g>
      <circle r="16" fill="#121824" stroke="#1E293B" stroke-width="3"/>
      <circle r="5" fill="#06B6D4"/>
    </g>`;

  $("#gauge").innerHTML = s;
}

let shownScore = 0;

function setNeedle(value, color) {
  $("#needle").style.transform = `rotate(${135 + value * 2.7}deg)`;
  if (color) $("#gauge").style.setProperty("--needle", color);
}

function animateCounter(from, to, ms = 1400) {
  const t0 = performance.now();
  const el = $("#g-score");
  const tick = (now) => {
    const p = Math.min((now - t0) / ms, 1);
    const eased = 1 - Math.pow(1 - p, 3);
    el.textContent = Math.round(from + (to - from) * eased);
    if (p < 1) requestAnimationFrame(tick);
  };
  requestAnimationFrame(tick);
}

function highlightZone(cls) {
  document.querySelectorAll(".zone").forEach((z) => {
    z.classList.remove("active", "dim");
    if (cls) z.classList.add(z.classList.contains(cls) ? "active" : "dim");
  });
}

function setGauge(score, verdictText) {
  const cls = zoneOf(score);
  setNeedle(score, COLORS[cls]);
  animateCounter(shownScore, score);
  shownScore = score;
  const vt = $("#g-verdict");
  vt.textContent = verdictText;
  vt.style.fill = COLORS[cls];
  highlightZone(cls);
}

function resetGauge() {
  setNeedle(0, "#F8FAFC");
  animateCounter(shownScore, 0, 600);
  shownScore = 0;
  $("#g-verdict").textContent = "AWAITING SCAN";
  $("#g-verdict").style.fill = "#94A3B8";
  highlightZone(null);
}

/* =========================================================
   RENDERING
   ========================================================= */
const VERDICT_LABEL = { safe: "SAFE", suspicious: "SUSPICIOUS", phishing: "DANGER · PHISHING" };
const VERDICT_CLASS = { safe: "v-safe", suspicious: "v-suspicious", phishing: "v-phishing" };

const list = (items, cls = "") =>
  items && items.length ? `<ul class="list ${cls}">${items.map((i) => `<li>${esc(i)}</li>`).join("")}</ul>` : "";

function renderSummary(d) {
  const ai = d.ai;
  let html = `<span class="verdict-pill ${VERDICT_CLASS[d.verdict]}">${VERDICT_LABEL[d.verdict]}</span>
    <div class="target">${esc(d.final_url)}</div>`;
  if (d.ai_error) html += `<div class="notice">⚠ ${esc(d.ai_error)}</div>`;
  if (ai) {
    html += `<p class="summary-text">${esc(ai.summary)}</p>`;
    if (ai.malicious_indicators.length)
      html += `<div class="block-title">Malicious indicators</div>${list(ai.malicious_indicators, "bad")}`;
    if (ai.benign_findings.length)
      html += `<div class="block-title">Benign findings</div>${list(ai.benign_findings, "ok")}`;
    if (ai.recommendations.length)
      html += `<div class="block-title">Recommendations</div>${list(ai.recommendations)}`;
    html += `<div class="block-title">AI confidence: ${Math.round(ai.confidence * 100)}% · Rule-based score: ${d.baseline_score}</div>`;
  }
  $("#summary").className = "";
  $("#summary").innerHTML = html;
}

function renderSSL(s) {
  if (!s.enabled) return `<div class="kv"><div><span>HTTPS</span><span class="bad">Not used</span></div></div>`;
  if (!s.valid)
    return `<div class="kv"><div><span>Certificate</span><span class="bad">Invalid</span></div>
            <div><span>Reason</span><span>${esc(s.error)}</span></div></div>`;
  const dl = s.days_left < 14 ? "warnc" : "good";
  return `<div class="kv">
    <div><span>Certificate</span><span class="good">Valid</span></div>
    <div><span>Issuer</span><span>${esc(s.issuer)}</span></div>
    <div><span>Subject</span><span>${esc(s.subject)}</span></div>
    <div><span>Expires in</span><span class="${dl}">${s.days_left} days</span></div>
    <div><span>Cert age</span><span>${s.age_days} days</span></div>
    <div><span>Protocol</span><span>${esc(s.protocol)}</span></div>
    <div><span>Cipher</span><span>${esc(s.cipher)}</span></div></div>`;
}

function renderHeaders(hs) {
  return hs
    .map(
      (h) => `<div class="hdr-row"><span class="mark ${h.present ? "good" : "warnc"}">${h.present ? "✓" : "✗"}</span>
        <span>${esc(h.name)}</span></div>`
    )
    .join("");
}

function renderSignals(d) {
  const p = d.page;
  let html = `<div class="kv">
    <div><span>HTTP status</span><span>${d.status}</span></div>
    <div><span>Response time</span><span>${d.response_ms} ms</span></div>
    <div><span>Redirects</span><span>${d.redirects.length}</span></div>
    <div><span>Page title</span><span>${esc(p.title) || "–"}</span></div>
    <div><span>Forms / password fields</span><span class="${p.password_inputs ? "warnc" : ""}">${p.forms} / ${p.password_inputs}</span></div>
    <div><span>Forms to other domains</span><span class="${p.external_form_actions.length ? "bad" : ""}">${esc(p.external_form_actions.join(", ")) || "None"}</span></div>
  </div>`;
  if (d.url_signals.length) html += `<div class="block-title">URL red flags</div>${list(d.url_signals, "bad")}`;
  else html += `<div class="block-title">URL red flags</div>${list(["No suspicious URL patterns"], "ok")}`;
  return html;
}

function renderResult(d) {
  renderSummary(d);
  $("#ssl").innerHTML = renderSSL(d.ssl);
  $("#headers").innerHTML = renderHeaders(d.headers);
  $("#signals").innerHTML = renderSignals(d);
  $("#details").classList.remove("hidden");
  setGauge(d.score, VERDICT_LABEL[d.verdict]);
}

/* =========================================================
   HISTORY & HEALTH
   ========================================================= */
async function loadHistory() {
  try {
    const items = await (await fetch("/api/history")).json();
    const box = $("#history");
    if (!items.length) {
      box.className = "muted";
      box.textContent = "No scans yet (or MongoDB is not connected).";
      return;
    }
    box.className = "";
    box.innerHTML = items
      .map((i) => {
        const c = COLORS[zoneOf(i.score)];
        return `<div class="hist-row" data-url="${esc(i.url)}">
          <span class="hist-score" style="color:${c};border-color:${c}">${i.score}</span>
          <span class="hist-url">${esc(i.url)}</span>
          <span class="hist-time">${new Date(i.scanned_at).toLocaleString()}</span></div>`;
      })
      .join("");
    box.querySelectorAll(".hist-row").forEach((r) =>
      r.addEventListener("click", () => {
        $("#url-input").value = r.dataset.url;
        window.scrollTo({ top: 0, behavior: "smooth" });
        $("#url-input").focus();
      })
    );
  } catch {
    /* ignore */
  }
}

async function loadHealth() {
  try {
    const h = await (await fetch("/api/health")).json();
    $("#chip-ai").textContent = h.gemini ? "Gemini ✓" : "Gemini key missing";
    $("#chip-ai").className = "chip " + (h.gemini ? "ok" : "off");
    $("#chip-db").textContent = h.database ? "MongoDB ✓" : "MongoDB offline";
    $("#chip-db").className = "chip " + (h.database ? "ok" : "off");
  } catch {
    /* ignore */
  }
}

/* =========================================================
   SCAN FLOW
   ========================================================= */
function setLoading(on) {
  $("#scan-btn").disabled = on;
  $("#scan-btn").classList.toggle("loading", on);
  $(".btn-label").textContent = on ? "Scanning…" : "Scan URL";
}

function showError(msg) {
  const e = $("#error");
  e.textContent = msg;
  e.classList.remove("hidden");
}

$("#scan-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const url = $("#url-input").value.trim();
  if (!url) return;

  setLoading(true);
  $("#error").classList.add("hidden");
  highlightZone(null);
  $("#g-verdict").textContent = "SCANNING…";
  $("#g-verdict").style.fill = "#06B6D4";
  setNeedle(100, "#06B6D4"); // rev up like a real speedometer while the scan runs

  try {
    const res = await fetch("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(typeof data.detail === "string" ? data.detail : "Invalid input");
    renderResult(data);
    loadHistory();
  } catch (err) {
    showError(err.message || "Scan failed");
    resetGauge();
  } finally {
    setLoading(false);
  }
});

buildGauge();
loadHealth();
loadHistory();