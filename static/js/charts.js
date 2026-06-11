/* Shared Chart.js helpers used across pages */

function buildPerfChart(canvasId, labels, datasets) {
  const ctx = document.getElementById(canvasId);
  if (!ctx) return;
  if (ctx._chart) ctx._chart.destroy();
  ctx._chart = new Chart(ctx, {
    type: "line",
    data: { labels, datasets },
    options: {
      responsive: true,
      plugins: { legend: { position: "top" } },
      scales: {
        x: { title: { display: true, text: ctx.dataset.xlabel || "X" } },
        y: { title: { display: true, text: "Time (ms)" }, beginAtZero: true },
      },
    },
  });
}

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
        x: { title: { display: true, text: xlabel || "X" } },
        y: { title: { display: true, text: "Security Bits" }, beginAtZero: true },
      },
    },
  });
}

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
