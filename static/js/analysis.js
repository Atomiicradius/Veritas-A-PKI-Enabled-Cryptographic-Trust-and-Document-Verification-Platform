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
    document.getElementById("av-analysis-result").style.display = "";  // fix: was classList.remove('d-none')
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

    // Table — use refined CSS classes instead of Bootstrap badge/table classes
    let html = `<table style="width:100%;border-collapse:collapse;" class="security-table">
      <thead><tr style="background:var(--bg-subtle);">
        <th style="padding:8px 12px;font-size:.6875rem;font-weight:600;letter-spacing:.06em;text-transform:uppercase;color:var(--text-2);border-bottom:1.5px solid var(--border);">Key Size</th>
        <th style="padding:8px 12px;font-size:.6875rem;font-weight:600;letter-spacing:.06em;text-transform:uppercase;color:var(--text-2);border-bottom:1.5px solid var(--border);">Security Bits</th>
        <th style="padding:8px 12px;font-size:.6875rem;font-weight:600;letter-spacing:.06em;text-transform:uppercase;color:var(--text-2);border-bottom:1.5px solid var(--border);">Status</th>
        <th style="padding:8px 12px;font-size:.6875rem;font-weight:600;letter-spacing:.06em;text-transform:uppercase;color:var(--text-2);border-bottom:1.5px solid var(--border);">Factoring Estimate</th>
        <th style="padding:8px 12px;font-size:.6875rem;font-weight:600;letter-spacing:.06em;text-transform:uppercase;color:var(--text-2);border-bottom:1.5px solid var(--border);">NIST</th>
      </tr></thead><tbody>`;
    levels.forEach(l => {
      const badgeCls = l.color === "danger" ? "err" : l.color === "warning" ? "warn" : "ok";
      const rowBg    = l.color === "danger" ? "#FDF5F5" : l.color === "warning" ? "#FDF8EE" : "#F5FAF6";
      html += `<tr style="border-bottom:1px solid var(--border); background:${rowBg}">
        <td style="padding:9px 12px;font-weight:600;font-size:.8125rem;">${l.key_size}-bit</td>
        <td style="padding:9px 12px;font-size:.8125rem;">${l.security_bits}</td>
        <td style="padding:9px 12px;"><span class="t-badge ${badgeCls}">${l.status}</span></td>
        <td style="padding:9px 12px;font-size:.75rem;color:var(--text-2);">${l.factoring_time}</td>
        <td style="padding:9px 12px;font-size:.75rem;color:var(--text-2);">${l.nist_status}</td>
      </tr>`;
    });
    html += "</tbody></table>";
    document.getElementById("attack-analysis-table").innerHTML = html;

    // Security bits bar chart — use fintech palette
    const chart = document.getElementById("securityChart");
    chart.style.display = "";  // fix: was classList.remove('d-none')
    if (chart._chart) chart._chart.destroy();
    chart._chart = new Chart(chart, {
      type: "bar",
      data: {
        labels: levels.map(l => l.key_size + "-bit"),
        datasets: [{
          label: "Security Bits",
          data: levels.map(l => l.security_bits),
          backgroundColor: levels.map(l =>
            l.color === "danger" ? "rgba(141,92,92,.35)" : l.color === "warning" ? "rgba(198,162,107,.35)" : "rgba(85,122,91,.35)"
          ),
          borderColor: levels.map(l =>
            l.color === "danger" ? "#8D5C5C" : l.color === "warning" ? "#C6A26B" : "#557A5B"
          ),
          borderWidth: 1.5,
        }],
      },
      options: {
        responsive: true,
        plugins: { legend: { display: false } },
        scales: {
          x: { title: { display: true, text: "RSA Key Size" }, grid: { display: false } },
          y: { title: { display: true, text: "Equivalent Security (bits)" }, beginAtZero: true },
        },
      },
    });
  } catch (e) {
    document.getElementById("attack-analysis-table").innerHTML = `<p style="color:var(--err);font-size:.8125rem;">Failed to load: ${e.message}</p>`;
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

    // Display full cert_id in a copyable element
    document.getElementById("pki-subject").textContent  = cert.subject;
    document.getElementById("pki-issuer").textContent   = cert.issuer;
    document.getElementById("pki-issued").textContent   = (cert.issued_at  || "").replace("T", " ").slice(0, 19) + " UTC";
    document.getElementById("pki-expires").textContent  = (cert.expires_at || "").replace("T", " ").slice(0, 19) + " UTC";
    document.getElementById("pki-revoked").innerHTML    = ver.revoked
      ? '<span class="t-badge err">Revoked</span>'
      : '<span class="t-badge ok">Not Revoked</span>';
    document.getElementById("pki-valid").innerHTML      = ver.certificate_valid
      ? '<span class="t-badge ok">Valid</span>'
      : '<span class="t-badge err">Invalid</span>';

    const reasonEl = document.getElementById("pki-reason-badge");
    reasonEl.innerHTML = ver.reason
      ? `<span class="t-badge warn">${ver.reason}</span>`
      : "";

    document.getElementById("pki-status-result").style.display = "";  // fix: was classList
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
      list.innerHTML = "<li style='color:var(--text-3);font-size:.8125rem;padding:4px 0;'>No revoked certificates.</li>";
    } else {
      data.revoked.forEach(id => {
        const li = document.createElement("li");
        li.style.cssText = "padding:3px 0; border-bottom:1px solid var(--border);";
        li.innerHTML = `<code class="mono" title="${id}">${id.slice(0,20)}…</code>
          <button onclick="copyToClipboard('${id}')" style="margin-left:6px;background:none;border:none;cursor:pointer;color:var(--slate);font-size:.75rem;">
            <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
            Copy
          </button>`;
        list.appendChild(li);
      });
    }
    document.getElementById("pki-crl-result").style.display = "";  // fix: was classList
  } catch (e) {
    alert("Failed to load CRL: " + e.message);
  }
});

/* ── TSA: Helper to populate the TSA panel from sign result ─────── */
window.populateTsaPanel = function(tsaToken, tsaValid) {
  if (!tsaToken) return;
  document.getElementById("tsa-placeholder").style.display = "none";  // fix: was classList
  document.getElementById("tsa-info").style.display = "";             // fix: was classList
  document.getElementById("tsa-timestamp").textContent = tsaToken.timestamp
    ? tsaToken.timestamp.replace("T", " ").slice(0, 19) + " UTC" : "—";
  document.getElementById("tsa-name").textContent      = tsaToken.tsa      || "—";
  document.getElementById("tsa-hash").textContent      = (tsaToken.hash || "").slice(0, 32) + (tsaToken.hash && tsaToken.hash.length > 32 ? "…" : "");
  document.getElementById("tsa-valid").innerHTML       = tsaValid === true
    ? '<span class="t-badge ok">Valid</span>'
    : tsaValid === false
      ? '<span class="t-badge err">Invalid</span>'
      : '<span class="t-badge pending">—</span>';
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
    document.getElementById("merkle-orig-root").textContent   = (m.original_root || "").slice(0, 32) + "…";
    document.getElementById("merkle-mod-root").textContent    = (m.modified_root  || "").slice(0, 32) + "…";
    document.getElementById("merkle-match").innerHTML         = m.roots_match
      ? '<span class="t-badge ok">Roots Match</span>'
      : '<span class="t-badge err">Roots Differ</span>';
    document.getElementById("merkle-orig-chunks").textContent  = m.original_chunks;
    document.getElementById("merkle-mod-chunks").textContent   = m.modified_chunks;

    // Show mismatched chunk indices for usability (Issue 3)
    const mismatchEl = document.getElementById("merkle-mismatch-count");
    if (m.mismatch_count === 0) {
      mismatchEl.innerHTML = '<span class="t-badge ok">0 — identical</span>';
    } else {
      const indices = (m.mismatched_chunks || []).slice(0, 20).join(", ");
      const more    = (m.mismatched_chunks || []).length > 20 ? " …" : "";
      mismatchEl.innerHTML = `<span class="t-badge err">${m.mismatch_count} chunks differ</span>
        <div style="font-size:.75rem;color:var(--text-2);margin-top:4px;">Changed indices: [${indices}${more}]</div>`;
    }

    // Bar chart — fintech palette
    const ctx = document.getElementById("merkleChart");
    ctx.style.display = "";
    if (ctx._chart) ctx._chart.destroy();
    ctx._chart = new Chart(ctx, {
      type: "bar",
      data: {
        labels: ["Original Chunks", "Modified Chunks", "Changed Chunks"],
        datasets: [{
          label: "Count",
          data: [m.original_chunks, m.modified_chunks, m.mismatch_count],
          backgroundColor: ["rgba(79,100,122,.3)", "rgba(85,122,91,.3)", "rgba(141,92,92,.35)"],
          borderColor:     ["#4F647A",             "#557A5B",            "#8D5C5C"],
          borderWidth: 1.5,
        }],
      },
      options: {
        responsive: true,
        plugins: { legend: { display: false } },
        scales: { y: { beginAtZero: true, ticks: { stepSize: 1 } }, x: { grid: { display: false } } },
      },
    });

    document.getElementById("merkle-result").style.display = "";  // fix: was classList
  } catch (e) {
    alert("Merkle compare error: " + e.message);
  }
});

