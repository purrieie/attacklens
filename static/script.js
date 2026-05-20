/* ═══════════════════════════════════════════════════════════════════
   ATT&CKLens — Frontend JavaScript
   Handles: form submit, loader, rendering, PDF export, MITRE filter
   ═══════════════════════════════════════════════════════════════════ */

"use strict";

// ── Loader steps ─────────────────────────────────────────────────────
const LOADER_STEPS = [
  { text: "INITIALIZING ANALYSIS ENGINE…", pct: 10 },
  { text: "CONNECTING TO GROQ INFERENCE…", pct: 25 },
  { text: "ANALYZING THREAT SCENARIO…",    pct: 45 },
  { text: "MAPPING MITRE ATT&CK FRAMEWORK…", pct: 65 },
  { text: "EXTRACTING INDICATORS OF COMPROMISE…", pct: 80 },
  { text: "SCORING RISK & SEVERITY…",      pct: 90 },
  { text: "COMPILING SOC REPORT…",         pct: 98 },
];

let loaderInterval = null;
let currentAnalysis = null;  // store last result for PDF export

// ── DOM refs ──────────────────────────────────────────────────────────
const analyzeBtn    = document.getElementById("analyzeBtn");
const clearBtn      = document.getElementById("clearBtn");
const scenarioInput = document.getElementById("scenarioInput");
const loader        = document.getElementById("loader");
const loaderStep    = document.getElementById("loaderStep");
const loaderBar     = document.getElementById("loaderBar");
const results       = document.getElementById("results");
const exportPdfBtn  = document.getElementById("exportPdfBtn");

// ── Loader helpers ────────────────────────────────────────────────────
function startLoader() {
  loader.style.display = "flex";
  let idx = 0;
  loaderStep.textContent = LOADER_STEPS[0].text;
  loaderBar.style.width  = LOADER_STEPS[0].pct + "%";

  loaderInterval = setInterval(() => {
    idx = (idx + 1) % LOADER_STEPS.length;
    loaderStep.textContent = LOADER_STEPS[idx].text;
    loaderBar.style.width  = LOADER_STEPS[idx].pct + "%";
  }, 900);
}

function stopLoader() {
  clearInterval(loaderInterval);
  loaderBar.style.width = "100%";
  setTimeout(() => { loader.style.display = "none"; }, 300);
}

// ── Escape HTML ───────────────────────────────────────────────────────
function esc(str) {
  return String(str || "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

// ── Render helpers ────────────────────────────────────────────────────
function setList(id, items) {
  const el = document.getElementById(id);
  if (!el) return;
  if (!items || items.length === 0) {
    el.innerHTML = '<li style="color:var(--dim);font-style:italic">None identified.</li>';
    return;
  }
  el.innerHTML = items.map(i => `<li>${esc(i)}</li>`).join("");
}

// ── Severity display ──────────────────────────────────────────────────
function renderSeverity(data) {
  const sev   = data.severity || "Unknown";
  const score = data.severity_score || "—";
  const cls   = data.threat_classification || "Unknown Threat";

  document.getElementById("threatClass").textContent = cls;
  const badge = document.getElementById("severityBadge");
  badge.textContent = sev.toUpperCase();
  badge.className   = `severity-badge sev-${sev}`;
  document.getElementById("riskScore").textContent = `RISK SCORE: ${score}/10`;
}

// ── Executive summary ─────────────────────────────────────────────────
function renderSummary(data) {
  const el = document.getElementById("execSummary");
  el.innerHTML = `<p style="color:var(--light);line-height:1.75;">${esc(data.executive_summary || "No summary available.")}</p>`;
}

// ── Attack timeline ───────────────────────────────────────────────────
function renderTimeline(data) {
  const tl   = data.attack_flow_timeline || [];
  const cont = document.getElementById("timeline");
  if (!tl.length) {
    cont.innerHTML = '<p style="color:var(--dim);">No timeline data.</p>';
    return;
  }
  cont.innerHTML = tl.map((step, i) => `
    <div class="timeline-item" style="animation-delay:${i * 0.08}s">
      <div class="timeline-dot"></div>
      <div class="timeline-phase">${esc(step.phase || "PHASE")}</div>
      <div class="timeline-time">${esc(step.timestamp_label || "")}</div>
      <div class="timeline-desc">${esc(step.description || "")}</div>
    </div>
  `).join("");
}

// ── MITRE mapping ─────────────────────────────────────────────────────
let allMitre = [];
let activeFilter = "All";

function renderMitreCards(items) {
  const grid = document.getElementById("mitreGrid");
  if (!items || !items.length) {
    grid.innerHTML = '<p style="color:var(--dim);">No MITRE techniques mapped.</p>';
    return;
  }

  grid.innerHTML = items.map((m, i) => {
    const type = m.type || "Technique";
    const url  = m.url || `https://attack.mitre.org/`;
    return `
      <div class="mitre-card" style="animation-delay:${i * 0.06}s">
        <span class="mitre-card-type type-${esc(type)}">${esc(type)}</span>
        <div class="mitre-card-id">${esc(m.id || "")}</div>
        <div class="mitre-card-name">${esc(m.name || "")}</div>
        <div class="mitre-card-desc">${esc(m.description || "")}</div>
        <a class="mitre-card-link" href="${esc(url)}" target="_blank" rel="noopener">
          ↗ View on MITRE ATT&amp;CK
        </a>
      </div>`;
  }).join("");
}

function buildMitreFilter(mitre) {
  allMitre = mitre || [];
  const types = ["All", ...new Set(allMitre.map(m => m.type || "Technique"))];
  const filt  = document.getElementById("mitreFilter");
  filt.innerHTML = types.map(t => `
    <button class="filter-btn ${t === activeFilter ? "active" : ""}"
            data-type="${esc(t)}">${esc(t)}
    </button>`).join("");

  filt.querySelectorAll(".filter-btn").forEach(btn => {
    btn.addEventListener("click", () => {
      activeFilter = btn.dataset.type;
      filt.querySelectorAll(".filter-btn").forEach(b => b.classList.remove("active"));
      btn.classList.add("active");
      const filtered = activeFilter === "All"
        ? allMitre
        : allMitre.filter(m => m.type === activeFilter);
      renderMitreCards(filtered);
    });
  });

  renderMitreCards(allMitre);
}

// ── IOC tables ────────────────────────────────────────────────────────
function renderIOCs(data) {
  const iocs = data.iocs || {};
  const categories = [
    { key: "ip_addresses",  label: "IP ADDRESSES" },
    { key: "domains",       label: "DOMAINS" },
    { key: "urls",          label: "URLS" },
    { key: "emails",        label: "EMAIL ADDRESSES" },
    { key: "file_hashes",   label: "FILE HASHES" },
    { key: "filenames",     label: "SUSPICIOUS FILENAMES" },
  ];

  const cont = document.getElementById("iocContainer");
  let html = "";
  let anyFound = false;

  for (const cat of categories) {
    const items = iocs[cat.key] || [];
    if (!items.length) continue;
    anyFound = true;
    html += `<div class="ioc-section">
      <div class="ioc-label">${cat.label} (${items.length})</div>
      <table class="ioc-table">
        ${items.map(item => `
          <tr>
            <td>${esc(item)}</td>
            <td style="width:30px;text-align:center">
              <span class="ioc-copy" title="Copy" data-value="${esc(item)}">⧉</span>
            </td>
          </tr>`).join("")}
      </table>
    </div>`;
  }

  if (!anyFound) {
    html = `<p class="ioc-empty">No specific IOCs were found in the scenario text. Extract from live logs for real IOCs.</p>`;
  }

  cont.innerHTML = html;

  // Copy-to-clipboard
  cont.querySelectorAll(".ioc-copy").forEach(btn => {
    btn.addEventListener("click", () => {
      navigator.clipboard.writeText(btn.dataset.value).then(() => {
        const orig = btn.textContent;
        btn.textContent = "✓";
        btn.style.color = "var(--green)";
        setTimeout(() => { btn.textContent = orig; btn.style.color = ""; }, 1500);
      });
    });
  });
}

// ── Main render ───────────────────────────────────────────────────────
function renderResults(data) {
  renderSeverity(data);
  renderSummary(data);
  renderTimeline(data);
  buildMitreFilter(data.mitre_mapping);
  renderIOCs(data);

  setList("potentialImpact",       data.potential_impact);
  setList("persistenceMechanisms", data.persistence_mechanisms);
  setList("lateralMovement",       data.lateral_movement_indicators);
  setList("controlFailures",       data.security_control_failures);
  setList("detectionOpportunities",data.detection_opportunities);
  setList("mitigationRecs",        data.mitigation_recommendations);
  setList("threatHunting",         data.threat_hunting_suggestions);
  setList("logSources",            data.recommended_log_sources);

  results.style.display = "block";
  results.classList.add("fade-in");
  results.scrollIntoView({ behavior: "smooth", block: "start" });
}

// ── Analyze: call backend ─────────────────────────────────────────────
analyzeBtn.addEventListener("click", async () => {
  const scenario = scenarioInput.value.trim();
  if (!scenario) {
    alert("Please enter an incident scenario.");
    return;
  }
  if (scenario.length < 20) {
    alert("Please provide more detail about the incident.");
    return;
  }

  results.style.display = "none";
  startLoader();
  analyzeBtn.disabled = true;

  try {
    const resp = await fetch("/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ scenario }),
    });

    const data = await resp.json();
    stopLoader();

    if (!resp.ok) {
      alert("Error: " + (data.error || "Unknown error from server."));
      return;
    }

    currentAnalysis = data;
    renderResults(data);
  } catch (err) {
    stopLoader();
    alert("Failed to connect to backend: " + err.message);
  } finally {
    analyzeBtn.disabled = false;
  }
});

// ── Clear ─────────────────────────────────────────────────────────────
clearBtn.addEventListener("click", () => {
  scenarioInput.value = "";
  results.style.display = "none";
  currentAnalysis = null;
  scenarioInput.focus();
});

// ── PDF Export ────────────────────────────────────────────────────────
exportPdfBtn.addEventListener("click", async () => {
  if (!currentAnalysis) {
    alert("No analysis to export yet.");
    return;
  }

  const orig = exportPdfBtn.textContent;
  exportPdfBtn.textContent = "⏳ Generating PDF…";
  exportPdfBtn.disabled = true;

  try {
    const resp = await fetch("/export-pdf", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(currentAnalysis),
    });

    if (!resp.ok) {
      const err = await resp.json();
      alert("PDF error: " + (err.error || "Unknown error"));
      return;
    }

    // Trigger browser download
    const blob = await resp.blob();
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement("a");
    const ts   = new Date().toISOString().slice(0, 19).replace(/[T:]/g, "-");
    a.href     = url;
    a.download = `ATTACKLens_Report_${ts}.pdf`;
    a.click();
    URL.revokeObjectURL(url);
  } catch (err) {
    alert("Failed to generate PDF: " + err.message);
  } finally {
    exportPdfBtn.textContent = orig;
    exportPdfBtn.disabled = false;
  }
});

// ── Keyboard shortcut: Ctrl+Enter to analyze ─────────────────────────
scenarioInput.addEventListener("keydown", e => {
  if ((e.ctrlKey || e.metaKey) && e.key === "Enter") {
    analyzeBtn.click();
  }
});
