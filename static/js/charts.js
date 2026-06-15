/* ── Shared Chart.js helpers — Veritas v3 ──────────────────────────────────── */

/* ── Global defaults (fintech palette) ────────────────────────────────────── */
Chart.defaults.font.family = "'Inter', system-ui, sans-serif";
Chart.defaults.font.size   = 11;
Chart.defaults.color       = "#6B7280";
Chart.defaults.plugins.legend.labels.boxWidth = 10;
Chart.defaults.plugins.legend.labels.padding  = 16;
Chart.defaults.plugins.tooltip.backgroundColor = "#22334A";
Chart.defaults.plugins.tooltip.padding         = 12;
Chart.defaults.plugins.tooltip.cornerRadius    = 8;
Chart.defaults.plugins.tooltip.titleFont       = { weight: "600", size: 12 };
Chart.defaults.plugins.tooltip.bodyFont        = { size: 11 };
Chart.defaults.plugins.tooltip.borderColor     = "rgba(255,255,255,0.08)";
Chart.defaults.plugins.tooltip.borderWidth     = 1;
Chart.defaults.scale.grid.color  = "rgba(240,237,232,0.8)";
Chart.defaults.scale.ticks.color = "#9CA3AF";

const PALETTE = {
  navy:  "#22334A",
  slate: "#4F647A",
  ok:    "#557A5B",
  warn:  "#C6A26B",
  muted: "#A8B4BF",
  red:   "#8D5C5C",
};

/* ── Line-draw animation plugin ───────────────────────────────────────────── */
const lineDrawPlugin = {
  id: "lineDrawAnimation",
  beforeDraw(chart) {
    if (chart._animProgress === undefined) chart._animProgress = 0;
  },
  afterDatasetsDraw(chart) {
    // progress goes 0→1 driven by Chart's built-in animation onProgress
  },
};

/* ── Point fade-in plugin ─────────────────────────────────────────────────── */
const pointFadePlugin = {
  id: "pointFade",
  afterDraw(chart) {
    const p = chart._fadeProgress ?? 0;
    if (p >= 1) return;
    // overdraw points with canvas alpha — creates fade-in effect
    chart.data.datasets.forEach((ds, di) => {
      const meta = chart.getDatasetMeta(di);
      if (!meta || meta.hidden) return;
      meta.data.forEach((pt) => {
        const ctx = chart.ctx;
        ctx.save();
        ctx.globalAlpha = 1 - p;
        ctx.fillStyle   = chart.canvas.style.background || "#fff";
        ctx.beginPath();
        ctx.arc(pt.x, pt.y, (pt.options?.radius ?? 3) + 1, 0, Math.PI * 2);
        ctx.fill();
        ctx.restore();
      });
    });
  },
};

Chart.register(lineDrawPlugin, pointFadePlugin);

/* ── Performance Line Chart ───────────────────────────────────────────────── */
/**
 * @param {string}  canvasId
 * @param {string[]} labels
 * @param {object[]} datasets   – each may carry {extra} with per-label min/max/err arrays
 */
function buildPerfChart(canvasId, labels, datasets) {
  const ctx = document.getElementById(canvasId);
  if (!ctx) return;

  // Destroy previous chart with a smooth fade-out transition
  if (ctx._chart) {
    ctx._chart.destroy();
  }

  // Enrich datasets with hover and style
  const colors = [PALETTE.muted, PALETTE.navy, PALETTE.ok];
  datasets.forEach((ds, i) => {
    ds.borderColor          = ds.borderColor || colors[i % colors.length];
    ds.borderWidth          = 2;
    ds.pointRadius          = 4;
    ds.pointHoverRadius     = 7;
    ds.pointBackgroundColor = ds.borderColor;
    ds.pointHoverBackgroundColor = ds.borderColor;
    ds.pointBorderColor     = "#ffffff";
    ds.pointBorderWidth     = 1.5;
    ds.tension              = 0.38;
    ds.fill                 = false;
    ds.backgroundColor      = "transparent";
    // Store extra data for tooltip (min/max)
    ds._extra = ds.extra || null;
  });

  // Kick off fade progress so pointFadePlugin animates correctly
  ctx._fadeProgress = 1; // finished (Chart.js native animation is enough)

  ctx._chart = new Chart(ctx, {
    type: "line",
    data: { labels, datasets },
    options: {
      responsive:   true,
      animation: {
        duration: 900,
        easing:   "easeInOutQuart",
        // Draw lines progressively left-to-right
        x: { duration: 900, from: 0 },
        y: { duration: 900, from: (ctx2) => ctx2.chart.scales.y.bottom },
      },
      plugins: {
        legend: {
          position: "top",
          labels: {
            usePointStyle: true,
            pointStyleWidth: 8,
          },
        },
        tooltip: {
          mode:      "index",
          intersect: false,
          callbacks: {
            title(items) {
              return items[0]?.label ?? "";
            },
            label(item) {
              const ds    = item.dataset;
              const val   = item.parsed.y;
              let line    = ` ${ds.label}: ${val.toFixed(3)} ms`;
              // Attach min / max if the dataset carries extra arrays
              if (ds._extra) {
                const idx = item.dataIndex;
                const mn  = ds._extra.min?.[idx];
                const mx  = ds._extra.max?.[idx];
                const err = ds._extra.err?.[idx];
                if (mn !== undefined) line += `  (min ${mn.toFixed(3)} / max ${mx.toFixed(3)} ms)`;
                if (err !== undefined) line += `  ±${err.toFixed(3)} ms`;
              }
              return line;
            },
            afterBody() {
              return ["", "Averaged over 50 warm-up-excluded iterations"];
            },
          },
        },
      },
      interaction: {
        mode:      "index",
        intersect: false,
      },
      hover: {
        mode:      "index",
        intersect: false,
      },
      scales: {
        x: {
          title: { display: true, text: ctx.dataset.xlabel || "Input", font: { weight: "500" } },
          grid:  { display: false },
        },
        y: {
          title: { display: true, text: "Time (ms)", font: { weight: "500" } },
          beginAtZero: true,
          grid: { color: "rgba(240,237,232,0.8)" },
        },
      },
      // Highlight hovered points
      onHover(event, elements) {
        event.native.target.style.cursor = elements.length ? "crosshair" : "default";
      },
    },
  });

  // Animate canvas border on load
  ctx.style.transition = "box-shadow .4s ease";
  ctx.style.boxShadow  = "0 0 0 2px rgba(34,51,74,.12)";
  setTimeout(() => { ctx.style.boxShadow = ""; }, 1200);
}

/* ── Bar Chart (Security / Merkle) ────────────────────────────────────────── */
function buildBarChart(canvasId, labels, datasets, xlabel) {
  const ctx = document.getElementById(canvasId);
  if (!ctx) return;
  if (ctx._chart) ctx._chart.destroy();
  ctx._chart = new Chart(ctx, {
    type: "bar",
    data: { labels, datasets },
    options: {
      responsive: true,
      animation:  { duration: 700, easing: "easeOutQuart" },
      plugins: {
        legend: { position: "top" },
        tooltip: { mode: "index", intersect: false },
      },
      scales: {
        x: { title: { display: true, text: xlabel || "X" }, grid: { display: false } },
        y: { title: { display: true, text: "Security Bits" }, beginAtZero: true },
      },
    },
  });
}

/* ── Avalanche Grid ────────────────────────────────────────────────────────── */
function renderAvalancheGrid(containerId, cells) {
  const container = document.getElementById(containerId);
  if (!container) return;
  container.innerHTML = "";
  cells.forEach((v, idx) => {
    const cell      = document.createElement("div");
    cell.className  = "av-cell " + (v ? "flipped" : "unchanged");
    // Staggered fade-in
    cell.style.cssText = `animation-delay:${(idx * 2)}ms`;
    container.appendChild(cell);
  });
}
