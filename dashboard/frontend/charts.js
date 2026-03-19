// charts.js

const API = "http://localhost:5000";

let chartSeverity = null;
let chartHosts    = null;
let chartScatter  = null;

const COLORS = {
  critical: "rgba(255, 77,  77,  0.85)",
  high:     "rgba(249, 115, 22,  0.85)",
  medium:   "rgba(250, 204, 21,  0.85)",
  low:      "rgba(96,  165, 250, 0.85)",
  info:     "rgba(167, 139, 250, 0.85)",
};

const CHART_DEFAULTS = {
  color:     "#e6edf3",
  font:      { family: "Segoe UI, system-ui, sans-serif", size: 12 },
};

Chart.defaults.color     = CHART_DEFAULTS.color;
Chart.defaults.font      = CHART_DEFAULTS.font;
Chart.defaults.borderColor = "#30363d";

function destroyChart(instance) {
  if (instance) { try { instance.destroy(); } catch (_) {} }
}

// ── Severity Donut ─────────────────────────────────────────────────────────────
function buildSeverityChart(bySeverity) {
  destroyChart(chartSeverity);
  const ctx    = document.getElementById("chart-severity").getContext("2d");
  const labels = ["Critical", "High", "Medium", "Low"];
  const data   = labels.map(l => bySeverity[l] || 0);
  chartSeverity = new Chart(ctx, {
    type: "doughnut",
    data: {
      labels,
      datasets: [{
        data,
        backgroundColor: [COLORS.critical, COLORS.high, COLORS.medium, COLORS.low],
        borderWidth: 2,
        borderColor: "#161b22",
      }]
    },
    options: {
      responsive: true,
      plugins: {
        legend: { position: "bottom", labels: { padding: 14, font: { size: 11 } } },
        tooltip: {
          callbacks: {
            label: ctx => ` ${ctx.label}: ${ctx.parsed} (${((ctx.parsed / ctx.dataset.data.reduce((a,b)=>a+b,0))*100).toFixed(1)}%)`
          }
        }
      }
    }
  });
}

// ── Top Hosts Bar ─────────────────────────────────────────────────────────────
function buildHostsChart(byHost) {
  destroyChart(chartHosts);
  const ctx    = document.getElementById("chart-hosts").getContext("2d");
  const labels = byHost.map(h => h.host || "unknown");
  const data   = byHost.map(h => h.cnt);
  chartHosts = new Chart(ctx, {
    type: "bar",
    data: {
      labels,
      datasets: [{
        label: "Vulnerabilities",
        data,
        backgroundColor: COLORS.high,
        borderRadius: 4,
      }]
    },
    options: {
      responsive: true,
      indexAxis: "y",
      plugins: { legend: { display: false } },
      scales: {
        x: { grid: { color: "#30363d" }, ticks: { color: "#8b949e" } },
        y: { grid: { display: false }, ticks: { color: "#e6edf3", font: { size: 11 } } },
      }
    }
  });
}

// ── CVSS vs EPSS Scatter ──────────────────────────────────────────────────────
async function buildScatterChart() {
  destroyChart(chartScatter);
  const ctx = document.getElementById("chart-scatter").getContext("2d");

  let points = [];
  try {
    const resp = await fetch(`${API}/api/risk-scores?limit=100`);
    const data = await resp.json();
    points = (data.data || []).map(v => ({
      x:     parseFloat(v.cvss_score || 0),
      y:     parseFloat(v.epss_score || 0) * 100,
      label: v.cve || v.name || "",
      sev:   (v.severity || "Low").toLowerCase(),
    }));
  } catch (_) {}

  const colorFn = sev => COLORS[sev] || COLORS.low;

  chartScatter = new Chart(ctx, {
    type: "scatter",
    data: {
      datasets: [{
        label: "Vulnerabilities",
        data:  points,
        pointBackgroundColor: points.map(p => colorFn(p.sev)),
        pointRadius: 6,
        pointHoverRadius: 9,
      }]
    },
    options: {
      responsive: true,
      plugins: {
        legend: { display: false },
        tooltip: {
          callbacks: {
            label: ctx => `${ctx.raw.label || ""} | CVSS: ${ctx.raw.x.toFixed(1)} | EPSS: ${ctx.raw.y.toFixed(1)}%`
          }
        }
      },
      scales: {
        x: {
          title: { display: true, text: "CVSS Score", color: "#8b949e" },
          min: 0, max: 10,
          grid: { color: "#30363d" }, ticks: { color: "#8b949e" },
        },
        y: {
          title: { display: true, text: "EPSS %", color: "#8b949e" },
          min: 0,
          grid: { color: "#30363d" }, ticks: { color: "#8b949e" },
        },
      }
    }
  });
}

// ── Build All ─────────────────────────────────────────────────────────────────
async function buildCharts(stats) {
  if (stats && stats.by_severity) buildSeverityChart(stats.by_severity);
  if (stats && stats.by_host)     buildHostsChart(stats.by_host);
  await buildScatterChart();
}

window.buildCharts = buildCharts;
