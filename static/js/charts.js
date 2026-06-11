/* Shared Chart.js helpers */

/* ── Global Chart.js defaults (fintech palette) ─────────────────────────── */
Chart.defaults.font.family = "'Inter', system-ui, sans-serif";
Chart.defaults.font.size   = 11;
Chart.defaults.color       = "#6B7280";
Chart.defaults.plugins.legend.labels.boxWidth = 10;
Chart.defaults.plugins.legend.labels.padding  = 14;
Chart.defaults.plugins.tooltip.backgroundColor = "#22334A";
Chart.defaults.plugins.tooltip.padding         = 10;
Chart.defaults.plugins.tooltip.cornerRadius    = 6;
Chart.defaults.scale.grid.color  = "#F0EDE8";
Chart.defaults.scale.ticks.color = "#9CA3AF";

const PALETTE = {
  navy:  "#22334A",
  slate: "#4F647A",
  ok:    "#557A5B",
  warn:  "#C6A26B",
  muted: "#A8B4BF",
};

/* ── Performance Line Chart ──────────────────────────────────────────────── */
function buildPerfChart(canvasId, labels, datasets) {
  const ctx = document.getElementById(canvasId);
  if (!ctx) return;
  if (ctx._chart) ctx._chart.destroy();

  // Apply refined palette to datasets
  const colors = [PALETTE.muted, PALETTE.navy, PALETTE.ok];
  datasets.forEach((ds, i) => {
    ds.borderColor     = ds.borderColor || colors[i % colors.length];
    ds.borderWidth     = 1.5;
    ds.pointRadius     = 3;
    ds.pointBackgroundColor = ds.borderColor;
    ds.tension         = 0.35;
    ds.fill            = false;
    ds.backgroundColor = "transparent";
  });

  ctx._chart = new Chart(ctx, {
    type: "line",
    data: { labels, datasets },
    options: {
      responsive: true,
      plugins: {
        legend: { position: "top" },
      },
      scales: {
        x: {
          title: { display: true, text: ctx.dataset.xlabel || "Input" },
          grid: { display: false },
        },
        y: {
          title: { display: true, text: "Time (ms)" },
          beginAtZero: true,
        },
      },
    },
  });
}

/* ── Bar Chart (Security / Merkle) ──────────────────────────────────────── */
function buildBarChart(canvasId, labels, datasets, xlabel) {
  const ctx = document.getElementById(canvasId);
  if (!ctx) return;
  if (ctx._chart) ctx._chart.destroy();
  ctx._chart = new Chart(ctx, {
    type: "bar",
    data: { labels, datasets },
    options: {
      responsive: true,
      plugins: { legend: { position: "top" } },
      scales: {
        x: { title: { display: true, text: xlabel || "X" }, grid: { display: false } },
        y: { title: { display: true, text: "Security Bits" }, beginAtZero: true },
      },
    },
  });
}

/* ── Avalanche Grid ──────────────────────────────────────────────────────── */
function renderAvalancheGrid(containerId, cells) {
  const container = document.getElementById(containerId);
  if (!container) return;
  container.innerHTML = "";
  cells.forEach(v => {
    const cell = document.createElement("div");
    cell.className = "av-cell " + (v ? "flipped" : "unchanged");
    container.appendChild(cell);
  });
}
