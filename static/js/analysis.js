/* Analysis page JS */

/* ── File Size Benchmark ─────────────────────────────────────────── */
document.getElementById("btn-bench-filesize").addEventListener("click", async () => {
  const status = document.getElementById("bench-fs-status");
  status.textContent = "Running (may take ~15 seconds)…";
  try {
    const res  = await fetch("/api/performance", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ mode: "file_size" }),
    });
    const data = await res.json();
    if (data.error) { status.textContent = "Error: " + data.error; return; }

    const results = data.results;
    const labels  = results.map(r => r.file_size_kb + " KB");
    buildPerfChart("fileSizeChart", labels, [
      { label: "Hashing",      data: results.map(r => r.hash_avg),   borderColor: "#6c757d", tension: 0.3 },
      { label: "Signing",      data: results.map(r => r.sign_avg),   borderColor: "#0d6efd", tension: 0.3 },
      { label: "Verification", data: results.map(r => r.verify_avg), borderColor: "#198754", tension: 0.3 },
    ]);
    document.getElementById("fileSizeChart").dataset.xlabel = "File Size";
    status.textContent = "Done. Averaged over 5 runs per file size.";
  } catch (e) {
    status.textContent = "Failed: " + e.message;
  }
});

/* ── Key Size Benchmark ──────────────────────────────────────────── */
document.getElementById("btn-bench-keysize").addEventListener("click", async () => {
  const status = document.getElementById("bench-ks-status");
  status.textContent = "Running (generating keys for each size)…";
  try {
    const res  = await fetch("/api/performance", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ mode: "key_size" }),
    });
    const data = await res.json();
    if (data.error) { status.textContent = "Error: " + data.error; return; }

    const results = data.results;
    const labels  = results.map(r => r.key_size + "-bit");
    buildPerfChart("keySizeChart", labels, [
      { label: "Signing",      data: results.map(r => r.sign_avg),   borderColor: "#0d6efd", tension: 0.3, fill: false },
      { label: "Verification", data: results.map(r => r.verify_avg), borderColor: "#198754", tension: 0.3, fill: false },
    ]);
    status.textContent = "Done. Averaged over 5 runs per key size.";
  } catch (e) {
    status.textContent = "Failed: " + e.message;
  }
});

/* ── Manual Avalanche ────────────────────────────────────────────── */
document.getElementById("btn-run-avalanche").addEventListener("click", async () => {
  const f1 = document.getElementById("av-orig-file").files[0];
  const f2 = document.getElementById("av-mod-file").files[0];
  if (!f1 || !f2) return alert("Select both original and modified files.");

  const fd = new FormData();
  fd.append("file1", f1);
  fd.append("file2", f2);

  try {
    const res  = await fetch("/api/compare", { method: "POST", body: fd });
    const data = await res.json();
    if (data.error) return alert(data.error);

    const av = data.avalanche;
    document.getElementById("av-analysis-result").classList.remove("d-none");
    document.getElementById("av-a-hash1").textContent      = av.original_hash;
    document.getElementById("av-a-hash2").textContent      = av.modified_hash;
    document.getElementById("av-a-flip-count").textContent = av.flip_count;
    document.getElementById("av-a-flip-pct").textContent   = av.flip_percent;
    renderAvalancheGrid("av-analysis-grid", av.cells);
  } catch (e) {
    alert("Error: " + e.message);
  }
});

/* ── Attack Simulation ───────────────────────────────────────────── */
document.getElementById("btn-load-attack-analysis").addEventListener("click", async () => {
  try {
    const res  = await fetch("/api/attack_sim");
    const data = await res.json();
    const levels = data.levels;

    // Table
    let html = `<table class="table table-bordered table-sm security-table">
      <thead class="table-dark"><tr>
        <th>Key Size</th><th>Security Bits</th><th>Status</th><th>Factoring Estimate</th><th>NIST</th>
      </tr></thead><tbody>`;
    levels.forEach(l => {
      const rowCls = l.color === "danger" ? "table-danger" : l.color === "warning" ? "table-warning" : l.color === "success" ? "table-success" : "";
      html += `<tr class="${rowCls}">
        <td><strong>${l.key_size}-bit</strong></td>
        <td>${l.security_bits}</td>
        <td><span class="badge bg-${l.color}">${l.status}</span></td>
        <td class="small">${l.factoring_time}</td>
        <td class="small">${l.nist_status}</td>
      </tr>`;
    });
    html += "</tbody></table>";
    document.getElementById("attack-analysis-table").innerHTML = html;

    // Security bits bar chart
    const chart = document.getElementById("securityChart");
    chart.classList.remove("d-none");
    if (chart._chart) chart._chart.destroy();
    chart._chart = new Chart(chart, {
      type: "bar",
      data: {
        labels: levels.map(l => l.key_size + "-bit"),
        datasets: [{
          label: "Security Bits",
          data: levels.map(l => l.security_bits),
          backgroundColor: levels.map(l =>
            l.color === "danger" ? "#dc354588" : l.color === "warning" ? "#ffc10788" : l.color === "success" ? "#19875488" : "#0d6efd88"
          ),
          borderColor: levels.map(l =>
            l.color === "danger" ? "#dc3545" : l.color === "warning" ? "#ffc107" : l.color === "success" ? "#198754" : "#0d6efd"
          ),
          borderWidth: 2,
        }],
      },
      options: {
        responsive: true,
        plugins: { legend: { display: false } },
        scales: {
          x: { title: { display: true, text: "RSA Key Size" } },
          y: { title: { display: true, text: "Equivalent Security (bits)" }, beginAtZero: true },
        },
      },
    });
  } catch (e) {
    document.getElementById("attack-analysis-table").innerHTML = "<p class='text-danger'>Failed to load: " + e.message + "</p>";
  }
});

/* ═══════════════════════════════════════════════════════════════════
   v2 additions below — all original code above is unchanged
═══════════════════════════════════════════════════════════════════ */

/* ── PKI: Certificate status lookup ──────────────────────────────── */
document.getElementById("btn-pki-check").addEventListener("click", async () => {
  const certId = document.getElementById("pki-cert-id-input").value.trim();
  if (!certId) return alert("Paste a cert_id first.");
  try {
    const res  = await fetch(`/api/pki/status?cert_id=${encodeURIComponent(certId)}`);
    const data = await res.json();
    if (data.error) return alert(data.error);

    const cert = data.certificate;
    const ver  = data.verification;

    document.getElementById("pki-subject").textContent  = cert.subject;
    document.getElementById("pki-issuer").textContent   = cert.issuer;
    document.getElementById("pki-issued").textContent   = cert.issued_at;
    document.getElementById("pki-expires").textContent  = cert.expires_at;
    document.getElementById("pki-revoked").innerHTML    = ver.revoked
      ? '<span class="badge bg-danger">Yes</span>'
      : '<span class="badge bg-success">No</span>';
    document.getElementById("pki-valid").innerHTML      = ver.certificate_valid
      ? '<span class="badge bg-success">✓ Valid</span>'
      : '<span class="badge bg-danger">✗ Invalid</span>';

    const reasonEl = document.getElementById("pki-reason-badge");
    reasonEl.innerHTML = ver.reason
      ? `<span class="badge bg-warning text-dark">${ver.reason}</span>`
      : "";

    document.getElementById("pki-status-result").classList.remove("d-none");
  } catch (e) {
    alert("Error: " + e.message);
  }
});

/* ── PKI: Load CRL ───────────────────────────────────────────────── */
document.getElementById("btn-pki-crl").addEventListener("click", async () => {
  try {
    const res  = await fetch("/api/pki/crl");
    const data = await res.json();
    const list = document.getElementById("pki-crl-list");
    list.innerHTML = "";
    if (!data.revoked || data.revoked.length === 0) {
      list.innerHTML = "<li class='text-muted'>No revoked certificates.</li>";
    } else {
      data.revoked.forEach(id => {
        const li = document.createElement("li");
        li.innerHTML = `<code class="small">${id}</code>`;
        list.appendChild(li);
      });
    }
    document.getElementById("pki-crl-result").classList.remove("d-none");
  } catch (e) {
    alert("Failed to load CRL: " + e.message);
  }
});

/* ── TSA: Helper to populate the TSA panel from sign result ─────── */
window.populateTsaPanel = function(tsaToken, tsaValid) {
  if (!tsaToken) return;
  document.getElementById("tsa-placeholder").classList.add("d-none");
  document.getElementById("tsa-info").classList.remove("d-none");
  document.getElementById("tsa-timestamp").textContent = tsaToken.timestamp || "—";
  document.getElementById("tsa-name").textContent      = tsaToken.tsa      || "—";
  document.getElementById("tsa-hash").textContent      = tsaToken.hash     || "—";
  document.getElementById("tsa-valid").innerHTML       = tsaValid === true
    ? '<span class="badge bg-success">✓ Valid</span>'
    : tsaValid === false
      ? '<span class="badge bg-danger">✗ Invalid</span>'
      : '<span class="badge bg-secondary">—</span>';
};

/* ── Merkle: Compare two files ───────────────────────────────────── */
document.getElementById("btn-merkle-compare").addEventListener("click", async () => {
  const f1 = document.getElementById("merkle-file1").files[0];
  const f2 = document.getElementById("merkle-file2").files[0];
  if (!f1 || !f2) return alert("Select both files first.");

  const fd = new FormData();
  fd.append("file1", f1);
  fd.append("file2", f2);

  try {
    const res  = await fetch("/api/compare", { method: "POST", body: fd });
    const data = await res.json();
    if (data.error) return alert(data.error);

    const m = data.merkle;
    document.getElementById("merkle-orig-root").textContent   = m.original_root;
    document.getElementById("merkle-mod-root").textContent    = m.modified_root;
    document.getElementById("merkle-match").innerHTML         = m.roots_match
      ? '<span class="badge bg-success">✓ Match</span>'
      : '<span class="badge bg-danger">✗ Mismatch</span>';
    document.getElementById("merkle-orig-chunks").textContent  = m.original_chunks;
    document.getElementById("merkle-mod-chunks").textContent   = m.modified_chunks;
    document.getElementById("merkle-mismatch-count").innerHTML = m.mismatch_count > 0
      ? `<span class="badge bg-danger">${m.mismatch_count} chunks differ</span>`
      : '<span class="badge bg-success">0 — identical</span>';

    // Bar chart: chunk counts
    const ctx = document.getElementById("merkleChart");
    if (ctx._chart) ctx._chart.destroy();
    ctx._chart = new Chart(ctx, {
      type: "bar",
      data: {
        labels: ["Original Chunks", "Modified Chunks", "Mismatched Chunks"],
        datasets: [{
          label: "Count",
          data: [m.original_chunks, m.modified_chunks, m.mismatch_count],
          backgroundColor: ["#0d6efd88", "#19875488", "#dc354588"],
          borderColor:     ["#0d6efd",   "#198754",   "#dc3545"],
          borderWidth: 2,
        }],
      },
      options: {
        responsive: true,
        plugins: { legend: { display: false } },
        scales: { y: { beginAtZero: true, ticks: { stepSize: 1 } } },
      },
    });

    document.getElementById("merkle-result").classList.remove("d-none");
  } catch (e) {
    alert("Merkle compare error: " + e.message);
  }
});

