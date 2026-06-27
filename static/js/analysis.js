/* Analysis page JS */

/* ── Utility: convert ISO/UTC timestamp to Indian Standard Time (IST) ────── */
function formatToIST(utcString) {
  if (!utcString) return "\u2014";
  try {
    let dateStr = utcString;
    if (!dateStr.endsWith("Z") && !dateStr.includes("+") && !dateStr.includes("GMT")) {
      dateStr = dateStr.replace(" ", "T") + "Z";
    }
    const d = new Date(dateStr);
    if (isNaN(d.getTime())) return utcString;
    const formatter = new Intl.DateTimeFormat("en-GB", {
      timeZone: "Asia/Kolkata",
      year: "numeric",
      month: "2-digit",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      hour12: false
    });
    const parts = formatter.formatToParts(d);
    const getVal = type => parts.find(p => p.type === type).value;
    return `${getVal("year")}-${getVal("month")}-${getVal("day")} ${getVal("hour")}:${getVal("minute")}:${getVal("second")} IST`;
  } catch (e) {
    return utcString;
  }
}

/* ── Utility: set a summary-card value element ───────────────────────────── */
function _setCard(id, text) {
  const el = document.getElementById(id);
  if (el) el.textContent = text;
}


/* ── File Size Benchmark ─────────────────────────────────────────── */
document.getElementById("btn-bench-filesize").addEventListener("click", async () => {
  const status = document.getElementById("bench-fs-status");
  const btn    = document.getElementById("btn-bench-filesize");
  btn.disabled = true;
  status.textContent = "Running — 50 iterations × 6 file sizes (may take ~20 s)…";
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
      {
        label: "Hashing",
        data:  results.map(r => r.hash_avg),
        extra: {
          min: results.map(r => r.hash_min),
          max: results.map(r => r.hash_max),
          err: results.map(r => r.hash_err),
        },
      },
      {
        label: "Signing",
        data:  results.map(r => r.sign_avg),
        extra: {
          min: results.map(r => r.sign_min),
          max: results.map(r => r.sign_max),
          err: results.map(r => r.sign_err),
        },
      },
      {
        label: "Verification",
        data:  results.map(r => r.verify_avg),
        extra: {
          min: results.map(r => r.verify_min),
          max: results.map(r => r.verify_max),
          err: results.map(r => r.verify_err),
        },
      },
    ]);
    document.getElementById("fileSizeChart").dataset.xlabel = "File Size";

    /* ── Populate file-size summary cards ── */
    const fastestIdx  = results.reduce((bi, r, i) => r.hash_avg < results[bi].hash_avg ? i : bi, 0);
    const avgSign     = results.reduce((s, r) => s + r.sign_avg, 0) / results.length;
    const avgVerify   = results.reduce((s, r) => s + r.verify_avg, 0) / results.length;

    _setCard("fs-fastest-val", results[fastestIdx].hash_avg.toFixed(3) + " ms");
    _setCard("fs-fastest-sub", "at " + results[fastestIdx].file_size_kb + " KB");
    _setCard("fs-sign-val",    avgSign.toFixed(3) + " ms");
    _setCard("fs-verify-val",  avgVerify.toFixed(3) + " ms");
    document.querySelectorAll("#fs-summary-cards .bench-card").forEach(el => el.classList.add("visible"));

    status.textContent = "Done. Averaged over 50 warm-up-excluded runs per file size.";
  } catch (e) {
    status.textContent = "Failed: " + e.message;
  } finally {
    btn.disabled = false;
  }
});

/* ── Key Size Benchmark ──────────────────────────────────────────── */
document.getElementById("btn-bench-keysize").addEventListener("click", async () => {
  const status = document.getElementById("bench-ks-status");
  const btn    = document.getElementById("btn-bench-keysize");
  btn.disabled = true;
  status.textContent = "Running — 50 iterations × 2 key sizes (may take ~30 s)…";
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
      {
        label: "Signing",
        data:  results.map(r => r.sign_avg),
        extra: {
          min: results.map(r => r.sign_min),
          max: results.map(r => r.sign_max),
          err: results.map(r => r.sign_err),
        },
      },
      {
        label: "Verification",
        data:  results.map(r => r.verify_avg),
        extra: {
          min: results.map(r => r.verify_min),
          max: results.map(r => r.verify_max),
          err: results.map(r => r.verify_err),
        },
      },
    ]);

    /* ── Populate key-size summary cards ── */
    const fastestIdx = results.reduce((bi, r, i) => r.sign_avg < results[bi].sign_avg ? i : bi, 0);
    const securestIdx = results.reduce((bi, r, i) => r.key_size > results[bi].key_size ? i : bi, 0);
    // NIST recommends ≥ 2048-bit RSA
    const recR = results.find(r => r.key_size >= 2048) || results[results.length - 1];

    _setCard("ks-fastest-val", results[fastestIdx].key_size + "-bit");
    _setCard("ks-fastest-sub", results[fastestIdx].sign_avg.toFixed(3) + " ms avg sign");
    _setCard("ks-secure-val",  results[securestIdx].key_size + "-bit");
    _setCard("ks-rec-val",     recR.key_size + "-bit");
    _setCard("ks-rec-sub",     recR.sign_avg.toFixed(3) + " ms sign / " + recR.verify_avg.toFixed(3) + " ms verify");
    document.querySelectorAll("#ks-summary-cards .bench-card").forEach(el => el.classList.add("visible"));

    status.textContent = "Done. Averaged over 50 warm-up-excluded runs per key size.";
  } catch (e) {
    status.textContent = "Failed: " + e.message;
  } finally {
    btn.disabled = false;
  }
});

/* ── Manual Avalanche ────────────────────────────────────────────── */
document.getElementById("btn-run-avalanche").addEventListener("click", async () => {
  const f1 = document.getElementById("av-orig-file").files[0];
  const f2 = document.getElementById("av-mod-file").files[0];
  if (!f1 || !f2) {
    let avErr = document.getElementById("av-error");
    if (!avErr) {
      avErr = document.createElement("div"); avErr.id = "av-error"; avErr.className = "v-error"; avErr.style.marginBottom = "8px";
      document.getElementById("btn-run-avalanche").parentNode.insertBefore(avErr, document.getElementById("btn-run-avalanche"));
    }
    avErr.innerHTML = '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg> Select both original and modified files.';
    avErr.style.display = "flex";
    setTimeout(() => avErr.style.display = "none", 6000);
    return;
  }
  const avErr = document.getElementById("av-error");
  if (avErr) avErr.style.display = "none";

  const fd = new FormData();
  fd.append("file1", f1);
  fd.append("file2", f2);

  try {
    const res  = await fetch("/api/compare", { method: "POST", body: fd });
    const data = await res.json();
    if (data.error) {
      const avErr2 = document.getElementById("av-error");
      if (avErr2) { avErr2.innerHTML = '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/></svg> ' + data.error; avErr2.style.display = "flex"; }
      return;
    }

    const av = data.avalanche;
    document.getElementById("av-analysis-result").style.display = "";  // fix: was classList.remove('d-none')
    document.getElementById("av-a-hash1").textContent      = av.original_hash;
    document.getElementById("av-a-hash2").textContent      = av.modified_hash;
    document.getElementById("av-a-flip-count").textContent = av.flip_count;
    document.getElementById("av-a-flip-pct").textContent   = av.flip_percent;
    renderAvalancheGrid("av-analysis-grid", av.cells);
  } catch (e) {
    const avErr3 = document.getElementById("av-error");
    if (avErr3) { avErr3.innerHTML = '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/></svg> Error: ' + e.message; avErr3.style.display = "flex"; }
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

/* /* =================================================================
   v2 additions -- inline error helper, PKI, TSA, Merkle
================================================================= */

/* -- Phase 4: Inline error helper for analysis page ------------- */
function showPkiError(msg) {
  let el = document.getElementById("pki-error");
  if (!el) {
    el = document.createElement("div");
    el.id = "pki-error";
    el.className = "v-error";
    el.style.marginTop = "8px";
    const inputRow = document.getElementById("pki-cert-id-input").parentNode;
    inputRow.parentNode.insertBefore(el, inputRow.nextSibling);
  }
  el.innerHTML = '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg> ' + msg;
  el.style.display = "flex";
  clearTimeout(el._t);
  el._t = setTimeout(() => el.style.display = "none", 7000);
}
function hidePkiError() {
  const el = document.getElementById("pki-error");
  if (el) el.style.display = "none";
}

function showMerkleError(msg) {
  let el = document.getElementById("merkle-error");
  if (!el) {
    el = document.createElement("div");
    el.id = "merkle-error";
    el.className = "v-error";
    el.style.marginTop = "8px";
    const btn = document.getElementById("btn-merkle-compare");
    btn.parentNode.insertBefore(el, btn.nextSibling);
  }
  el.innerHTML = '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg> ' + msg;
  el.style.display = "flex";
  clearTimeout(el._t);
  el._t = setTimeout(() => el.style.display = "none", 7000);
}

/* -- PKI: Certificate status lookup + Revoke state -------------- */
let _currentCertId = null;
let _crlLoaded     = false;   // UX-07

document.getElementById("btn-pki-check").addEventListener("click", async () => {
  const certId = document.getElementById("pki-cert-id-input").value.trim();
  // BUG-06 FIX: inline error
  if (!certId) {
    showPkiError("Please paste a Certificate ID first.");
    return;
  }
  hidePkiError();

  try {
    const res  = await fetch(`/api/pki/status?cert_id=${encodeURIComponent(certId)}`);
    const data = await res.json();
    // BUG-07 FIX: inline error instead of alert
    if (data.error) {
      showPkiError(data.error);
      return;
    }

    const cert = data.certificate;
    const ver  = data.verification;
    _currentCertId = cert.cert_id;

    // UX-05 FIX: show cert_id in result table
    const certIdRow = document.getElementById("pki-cert-id-row");
    if (certIdRow) {
      certIdRow.innerHTML =
        `<code style="font-size:.6875rem;font-family:'IBM Plex Mono',monospace;color:var(--slate);">${cert.cert_id.slice(0,20)}\u2026</code>
         <button onclick="copyToClipboard('${cert.cert_id}')" title="Copy full cert_id"
           style="background:none;border:none;cursor:pointer;color:var(--slate);padding:0 2px;vertical-align:middle;">
           <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
             <rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>
           </svg>
         </button>`;
    }

    document.getElementById("pki-subject").textContent  = cert.subject;
    document.getElementById("pki-issuer").textContent   = cert.issuer;
    document.getElementById("pki-issued").textContent   = formatToIST(cert.issued_at);
    document.getElementById("pki-expires").textContent  = formatToIST(cert.expires_at);
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

    const area         = document.getElementById("pki-revoke-area");
    const revokeBtn    = document.getElementById("btn-pki-revoke");
    const revokedBadge = document.getElementById("pki-revoked-badge");
    area.style.display = "";
    if (ver.revoked) {
      revokeBtn.style.display    = "none";
      revokedBadge.style.display = "";
    } else {
      revokeBtn.style.display    = "";
      revokedBadge.style.display = "none";
    }

    document.getElementById("pki-status-result").style.display = "";
  } catch (e) {
    showPkiError("Request failed: " + e.message);
  }
});

/* -- PKI: Confirm revoke --------------------------------------- */
document.getElementById("btn-confirm-revoke").addEventListener("click", async () => {
  if (!_currentCertId) return;
  const btn = document.getElementById("btn-confirm-revoke");
  btn.disabled = true;
  btn.innerHTML = '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/></svg> Revoking\u2026';

  try {
    const res  = await fetch("/api/pki/revoke", {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body:    JSON.stringify({ cert_id: _currentCertId }),
    });
    const data = await res.json();
    document.getElementById("revokeModal").style.display = "none";

    if (data.status === "revoked" || data.status === "already_revoked") {
      document.getElementById("pki-revoked").innerHTML =
        '<span class="t-badge err">Revoked</span>';
      document.getElementById("pki-valid").innerHTML =
        '<span class="t-badge err">Invalid</span>';
      document.getElementById("pki-reason-badge").innerHTML =
        '<span class="t-badge warn">certificate_revoked</span>';

      document.getElementById("btn-pki-revoke").style.display    = "none";
      document.getElementById("pki-revoked-badge").style.display = "";

      // Auto-refresh CRL list
      document.getElementById("btn-pki-crl").click();

      // UX-06: scroll CRL into view
      setTimeout(() => {
        const crlResult = document.getElementById("pki-crl-result");
        if (crlResult) crlResult.scrollIntoView({ behavior: "smooth", block: "nearest" });
      }, 400);

      // Toast
      const toast = document.createElement("div");
      toast.textContent = data.status === "already_revoked"
        ? "Certificate was already revoked."
        : "Certificate revoked successfully.";
      toast.style.cssText =
        "position:fixed;bottom:24px;right:24px;z-index:9999;" +
        "background:var(--navy);color:#fff;padding:10px 18px;" +
        "border-radius:var(--radius-sm);font-size:.8125rem;font-weight:500;" +
        "box-shadow:var(--shadow);";
      document.body.appendChild(toast);
      setTimeout(() => toast.remove(), 2500);
    } else {
      showPkiError("Revocation failed: " + (data.error || "Unknown error"));
    }
  } catch (e) {
    showPkiError("Request failed: " + e.message);
  } finally {
    btn.disabled = false;
    btn.innerHTML = '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/></svg> Revoke';
  }
});

/* Close revokeModal on backdrop click */
document.getElementById("revokeModal").addEventListener("click", function(e) {
  if (e.target === this) this.style.display = "none";
});

/* -- PKI: Load / Refresh CRL ----------------------------------- */
document.getElementById("btn-pki-crl").addEventListener("click", async () => {
  try {
    const res  = await fetch("/api/pki/crl");
    const data = await res.json();
    const list = document.getElementById("pki-crl-list");

    if (!data.revoked || data.revoked.length === 0) {
      list.innerHTML = '<p style="color:var(--text-3);font-size:.8125rem;padding:8px 0;">No certificates have been revoked.</p>';
    } else {
      let html = '<table style="width:100%;border-collapse:collapse;">'
        + '<thead><tr style="background:var(--bg-subtle);">'
        + '<th style="padding:6px 8px;font-size:.6rem;font-weight:600;letter-spacing:.06em;text-transform:uppercase;color:var(--text-2);border-bottom:1.5px solid var(--border);text-align:left;">Certificate ID</th>'
        + '<th style="padding:6px 8px;font-size:.6rem;font-weight:600;letter-spacing:.06em;text-transform:uppercase;color:var(--text-2);border-bottom:1.5px solid var(--border);text-align:left;">Revoked At</th>'
        + '<th style="padding:6px 8px;border-bottom:1.5px solid var(--border);"></th>'
        + '</tr></thead><tbody>';

      data.revoked.forEach(entry => {
        const id = typeof entry === "string" ? entry : entry.cert_id;
        // BUG-05 FIX: legacy entries show descriptive label with tooltip
        const isLegacy = typeof entry === "object" && (!entry.revoked_at || entry.revoked_at === "unknown");
        const ts = isLegacy
          ? '<span title="Revoked before timestamp logging was enabled" style="cursor:help;color:var(--text-3);font-style:italic;font-size:.75rem;">Legacy Revocation</span>'
          : formatToIST(entry.revoked_at);
        html += '<tr style="border-bottom:1px solid var(--border);">'
          + `<td style="padding:6px 8px;font-family:'IBM Plex Mono',monospace;font-size:.6rem;color:var(--slate);" title="${id}">${id.slice(0, 20)}\u2026</td>`
          + `<td style="padding:6px 8px;font-size:.75rem;color:var(--text-2);white-space:nowrap;">${ts}</td>`
          + '<td style="padding:6px 8px;text-align:right;">'
          + `<button onclick="copyToClipboard('${id}')" title="Copy full cert_id" style="background:none;border:none;cursor:pointer;color:var(--slate);padding:0;display:inline-flex;align-items:center;gap:3px;font-size:.75rem;">`
          + '<svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>'
          + 'Copy</button></td></tr>';
      });
      html += "</tbody></table>";
      list.innerHTML = html;
    }
    document.getElementById("pki-crl-result").style.display = "";

    // UX-07: change button label after first load
    if (!_crlLoaded) {
      _crlLoaded = true;
      const crlBtn = document.getElementById("btn-pki-crl");
      crlBtn.innerHTML = '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/></svg> Refresh CRL';
    }
  } catch (e) {
    showPkiError("Failed to load CRL: " + e.message);
  }
});

/* -- TSA: Helper to populate the TSA panel --------------------- */
window.populateTsaPanel = function(tsaToken, tsaValid) {
  if (!tsaToken) return;
  document.getElementById("tsa-placeholder").style.display = "none";
  document.getElementById("tsa-info").style.display = "";
  document.getElementById("tsa-timestamp").textContent = tsaToken.timestamp
    ? formatToIST(tsaToken.timestamp) : "\u2014";
  document.getElementById("tsa-name").textContent  = tsaToken.tsa  || "\u2014";
  document.getElementById("tsa-hash").textContent  = (tsaToken.hash || "").slice(0, 32) +
    (tsaToken.hash && tsaToken.hash.length > 32 ? "\u2026" : "");
  document.getElementById("tsa-valid").innerHTML   = tsaValid === true
    ? '<span class="t-badge ok">Valid</span>'
    : tsaValid === false
      ? '<span class="t-badge err">Invalid</span>'
      : '<span class="t-badge pending">\u2014</span>';
};

/* BUG-04 FIX: restore TSA token from localStorage on analysis page load */
(function restoreTsaFromStorage() {
  try {
    const raw = localStorage.getItem("lastTsaToken");
    if (!raw) return;
    const token = JSON.parse(raw);
    const valid = JSON.parse(localStorage.getItem("lastTsaValid") || "null");
    if (token && typeof window.populateTsaPanel === "function") {
      window.populateTsaPanel(token, valid);
    }
  } catch (_) {}
})();

/* -- Merkle: Compare two files --------------------------------- */
document.getElementById("btn-merkle-compare").addEventListener("click", async () => {
  const f1 = document.getElementById("merkle-file1").files[0];
  const f2 = document.getElementById("merkle-file2").files[0];
  // Phase 4 FIX: inline error instead of alert
  if (!f1 || !f2) {
    showMerkleError("Please select both files before comparing.");
    return;
  }

  const fd = new FormData();
  fd.append("file1", f1);
  fd.append("file2", f2);

  try {
    const res  = await fetch("/api/compare", { method: "POST", body: fd });
    const data = await res.json();
    if (data.error) {
      showMerkleError(data.error);
      return;
    }

    const m = data.merkle;
    document.getElementById("merkle-orig-root").textContent   = (m.original_root || "").slice(0, 32) + "\u2026";
    document.getElementById("merkle-mod-root").textContent    = (m.modified_root  || "").slice(0, 32) + "\u2026";
    document.getElementById("merkle-match").innerHTML         = m.roots_match
      ? '<span class="t-badge ok">Roots Match</span>'
      : '<span class="t-badge err">Roots Differ</span>';
    document.getElementById("merkle-orig-chunks").textContent  = m.original_chunks;
    document.getElementById("merkle-mod-chunks").textContent   = m.modified_chunks;

    const mismatchEl = document.getElementById("merkle-mismatch-count");
    if (m.mismatch_count === 0) {
      mismatchEl.innerHTML = '<span class="t-badge ok">0 \u2014 identical</span>';
    } else {
      const indices = (m.mismatched_chunks || []).slice(0, 20).join(", ");
      const more    = (m.mismatched_chunks || []).length > 20 ? " \u2026" : "";
      mismatchEl.innerHTML = `<span class="t-badge err">${m.mismatch_count} chunks differ</span>`
        + `<div style="font-size:.75rem;color:var(--text-2);margin-top:4px;">Changed indices: [${indices}${more}]</div>`;
    }

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

    document.getElementById("merkle-result").style.display = "";
  } catch (e) {
    showMerkleError("Merkle compare error: " + e.message);
  }
});


/* =======================================================================
   Side-Channel Timing Attack Simulator
   ======================================================================= */

(function initTimingSimulator() {
  const btn      = document.getElementById("btn-run-timing");
  const btnLabel = document.getElementById("timing-btn-label");
  const btnIcon  = document.getElementById("timing-btn-icon");
  const panel    = document.getElementById("timing-panel");
  const terminal = document.getElementById("timingTerminal");
  const errBox   = document.getElementById("timing-error");
  const errMsg   = document.getElementById("timing-error-msg");
  const summary  = document.getElementById("timing-summary");

  /* Helpers ─────────────────────────────────────────────────────────── */
  function showTimingError(msg) {
    errMsg.textContent = msg;
    errBox.style.display = "flex";
  }
  function hideTimingError() {
    errBox.style.display = "none";
  }

  function setButtonLoading(loading) {
    btn.disabled = loading;
    if (loading) {
      btnIcon.innerHTML = `<circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/>`;
      btnLabel.textContent = "Simulating\u2026";
    } else {
      btnIcon.innerHTML = `<polygon points="5 3 19 12 5 21 5 3"/>`;
      btnLabel.textContent = "Run Timing Attack Simulation";
    }
  }

  function termAppend(html) {
    terminal.insertAdjacentHTML("beforeend", html + "\n");
    terminal.scrollTop = terminal.scrollHeight;
  }

  /* Chart initialisation ─────────────────────────────────────────────── */
  let timingChart = null;

  function buildTimingChart(totalSteps) {
    const canvas = document.getElementById("timingChart");
    if (timingChart) { timingChart.destroy(); timingChart = null; }

    const labels = Array.from({ length: totalSteps }, (_, i) => i);
    timingChart = new Chart(canvas, {
      type: "line",
      data: {
        labels,
        datasets: [
          {
            label: "Vulnerable \u2014 naive compare",
            data:  new Array(totalSteps).fill(null),
            borderColor: "rgba(220, 80, 80, 0.9)",
            backgroundColor: "rgba(220, 80, 80, 0.08)",
            pointBackgroundColor: "rgba(220, 80, 80, 0.9)",
            pointRadius: 3,
            borderWidth: 2,
            tension: 0.3,
            fill: true,
          },
          {
            label: "Secure \u2014 constant time",
            data:  new Array(totalSteps).fill(null),
            borderColor: "rgba(60, 130, 220, 0.9)",
            backgroundColor: "rgba(60, 130, 220, 0.08)",
            pointBackgroundColor: "rgba(60, 130, 220, 0.9)",
            pointRadius: 3,
            borderWidth: 2,
            tension: 0.3,
            fill: true,
          },
        ],
      },
      options: {
        responsive: true,
        animation: { duration: 0 },
        plugins: {
          legend: {
            display: true,
            labels: { font: { family: "Inter, sans-serif", size: 11 }, boxWidth: 12 },
          },
          tooltip: {
            callbacks: {
              label: ctx => ` ${ctx.dataset.label}: ${ctx.parsed.y !== null ? ctx.parsed.y.toFixed(2) + " ms" : "—"}`,
            },
          },
        },
        scales: {
          x: {
            title: { display: true, text: "Probe Step (0–31)", font: { size: 11 } },
            grid:  { color: "rgba(0,0,0,0.05)" },
          },
          y: {
            title: { display: true, text: "Latency (ms)", font: { size: 11 } },
            beginAtZero: true,
            grid:  { color: "rgba(0,0,0,0.05)" },
          },
        },
      },
    });
    return timingChart;
  }

  /* Streaming renderer ────────────────────────────────────────────────── */
  function streamResults(vulnData, secData) {
    const total = vulnData.length;          // should be 32 (16 bytes × 2 probes)
    const chart = buildTimingChart(total);

    // Pre-compute per-byte deltas for Lock log lines
    const byteDeltas = {};                  // byteIndex -> { failMs, lockMs }
    vulnData.forEach(d => {
      const m = d.state.match(/^Byte (\d+) (Fail|Lock)$/);
      if (!m) return;
      const idx  = parseInt(m[1], 10);
      const kind = m[2];
      if (!byteDeltas[idx]) byteDeltas[idx] = {};
      byteDeltas[idx][kind === "Fail" ? "failMs" : "lockMs"] = d.ms;
    });

    let pointer = 0;

    termAppend(`<span class="t-header">─── Simulation start ─── target: VERITAS_SIG_2026 ───</span>`);

    const timer = setInterval(() => {
      if (pointer >= total) {
        clearInterval(timer);
        onStreamComplete(vulnData, secData, byteDeltas);
        return;
      }

      const vp = vulnData[pointer];
      const sp = secData[pointer];

      // Paint into chart
      chart.data.datasets[0].data[pointer] = vp.ms;
      chart.data.datasets[1].data[pointer] = sp.ms;
      chart.update();

      // Telemetry line
      const m = vp.state.match(/^Byte (\d+) (Fail|Lock)$/);
      if (m) {
        const i    = parseInt(m[1], 10);
        const kind = m[2];

        if (kind === "Fail") {
          termAppend(`<span class="t-probe">[PROBE]: Byte ${i} mismatch \u2014 ${vp.ms.toFixed(2)}ms</span>`);
        } else {
          const delta = byteDeltas[i]
            ? (byteDeltas[i].lockMs - (byteDeltas[i].failMs || 0)).toFixed(2)
            : "?";
          termAppend(`<span class="t-lock">[LOCK DETECTED]: Byte ${i} matched \u2014 delta +${delta}ms</span>`);
        }
        // Secure path log
        termAppend(`<span class="t-secure">[SECURE]: Byte ${i} \u2014 ${sp.ms.toFixed(2)}ms (no delta leak)</span>`);
      }

      pointer++;
    }, 120);   // 120 ms per point
  }

  /* Post-stream summary ─────────────────────────────────────────────── */
  function onStreamComplete(vulnData, _secData, byteDeltas) {
    termAppend(`<span class="t-header">─── Simulation complete ───</span>`);

    // Total timing leaked = sum of (lock - fail) deltas
    let totalLeaked = 0;
    Object.values(byteDeltas).forEach(d => {
      if (d.failMs !== undefined && d.lockMs !== undefined) {
        totalLeaked += Math.max(0, d.lockMs - d.failMs);
      }
    });

    document.getElementById("ts-leaked-val").textContent  = totalLeaked.toFixed(1) + " ms";
    document.getElementById("ts-bytes-val").textContent   = "16 / 16";
    document.getElementById("ts-secure-val").textContent  = "0 bits";
    summary.style.display = "";
    setButtonLoading(false);
  }

  /* Button click handler ──────────────────────────────────────────────── */
  btn.addEventListener("click", async () => {
    hideTimingError();
    summary.style.display = "none";
    terminal.innerHTML = "";
    panel.style.display = "";

    setButtonLoading(true);

    try {
      const res  = await fetch("/api/analysis/simulate-timing-attack", { method: "POST" });
      const data = await res.json();

      if (data.error) {
        showTimingError("Simulation error: " + data.error);
        setButtonLoading(false);
        return;
      }

      streamResults(data.vulnerable, data.secure);
    } catch (e) {
      showTimingError("Request failed: " + e.message);
      setButtonLoading(false);
    }
  });

})();  // end initTimingSimulator IIFE


/* =======================================================================
   Zero-Knowledge Proof Attestation Suite
   Schnorr Interactive Identification Protocol
   ======================================================================= */

(function initZKPSuite() {
  /* ── DOM refs ─────────────────────────────────────────────────────────── */
  const runBtn   = document.getElementById("zkpRunBtn");
  const btnLabel = document.getElementById("zkpBtnLabel");
  const btnIcon  = document.getElementById("zkpBtnIcon");
  const errBox   = document.getElementById("zkpError");
  const errMsg   = document.getElementById("zkpErrorMsg");
  const terminal = document.getElementById("zkpTerminal");
  const summary  = document.getElementById("zkpSummary");
  const hashInput = document.getElementById("zkpHashInput");

  const nodes   = [1, 2, 3, 4].map(i => document.getElementById("zkpNode" + i));
  const statuses = [1, 2, 3, 4].map(i => document.getElementById("zkpStatus" + i));

  /* ── Utilities ────────────────────────────────────────────────────────── */
  const sleep = ms => new Promise(res => setTimeout(res, ms));

  function ts() {
    const d = new Date();
    return d.toTimeString().slice(0, 8);
  }

  function zkLog(cls, text) {
    terminal.insertAdjacentHTML("beforeend",
      `<span class="${cls}">[${ts()}] ${text}</span>\n`);
    terminal.scrollTop = terminal.scrollHeight;
  }

  function setNode(idx, state, statusText) {
    // Remove all modifier classes then apply new one
    nodes[idx].classList.remove("zkp-node--active", "zkp-node--success", "zkp-node--error");
    if (state) nodes[idx].classList.add("zkp-node--" + state);
    if (statusText !== undefined) statuses[idx].textContent = statusText;
  }

  function resetAll() {
    nodes.forEach((n, i) => setNode(i, null, "Pending"));
    terminal.innerHTML = "";
    summary.style.display = "none";
    errBox.style.display = "none";
  }

  function setBtnRunning(running) {
    runBtn.disabled = running;
    if (running) {
      btnIcon.innerHTML = `<circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/>`;
      btnLabel.textContent = "Running\u2026";
    } else {
      btnIcon.innerHTML = `<polygon points="5 3 19 12 5 21 5 3"/>`;
      btnLabel.textContent = "Run Interactive Pipeline";
    }
  }

  function showError(msg) {
    errMsg.textContent = msg;
    errBox.style.display = "flex";
    zkLog("zl-err", "[ERROR]: " + msg);
  }

  /* ── Main pipeline ────────────────────────────────────────────────────── */
  runBtn.addEventListener("click", async () => {
    resetAll();
    setBtnRunning(true);

    const fileHash = (hashInput.value || "").trim();

    /* ── STEP 1: Initiate ─────────────────────────────────────────────── */
    setNode(0, "active", "Connecting\u2026");
    zkLog("zl-system", "[SYSTEM]: RFC 3526 / 2048-bit MODP Group initializing. G = 2.");

    let initData;
    try {
      const res = await fetch("/api/zkp/initiate", {
        method:  "POST",
        headers: { "Content-Type": "application/json" },
        body:    JSON.stringify({ file_hash: fileHash || undefined }),
      });
      initData = await res.json();
      if (initData.error) { setNode(0, "error", "Failed"); showError(initData.error); setBtnRunning(false); return; }
    } catch (e) {
      setNode(0, "error", "Failed");
      showError("Network error on /initiate: " + e.message);
      setBtnRunning(false);
      return;
    }

    setNode(0, "success", "Done");
    zkLog("zl-system", "[SYSTEM]: " + initData.group_params + " initialized. " + initData.generator + ".");
    zkLog("zl-prover", "[PROVER]: Transient commitment parameter r generated (kept secret).");
    zkLog("zl-tx",    "[TX]:     Public commitment Y dispatched \u2192 " + initData.commitment_Y);
    zkLog("zl-info",  "[INFO]:   Public identity node y \u2192 " + initData.public_identity_y);
    zkLog("zl-info",  "[INFO]:   0 bytes of raw document data transmitted.");

    await sleep(600);

    /* ── STEP 2: Challenge ────────────────────────────────────────────── */
    setNode(1, "active", "Waiting\u2026");

    let challData;
    try {
      const res = await fetch("/api/zkp/challenge", { method: "POST" });
      challData = await res.json();
      if (challData.error) { setNode(1, "error", "Failed"); showError(challData.error); setBtnRunning(false); return; }
    } catch (e) {
      setNode(1, "error", "Failed");
      showError("Network error on /challenge: " + e.message);
      setBtnRunning(false);
      return;
    }

    setNode(1, "success", "Issued");
    zkLog("zl-verif", "[VERIFIER]: Deterministic challenge bit derived from file hash binding.");
    zkLog("zl-verif", `[VERIFIER]: c = ${challData.challenge_bit} (SHA-256 of hash \u2225 Y, mod 2)`);
    zkLog("zl-info",  "[INFO]:     Challenge is now cryptographically bound to the submitted document.");

    await sleep(600);

    /* ── STEP 3: Verify (compute scalar response) ─────────────────────── */
    setNode(2, "active", "Computing\u2026");

    let verifyData;
    try {
      const liveHash = (hashInput.value || "").trim();
      const res = await fetch("/api/zkp/verify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ file_hash: liveHash })
      });
      verifyData = await res.json();
      if (verifyData.error) { setNode(2, "error", "Failed"); showError(verifyData.error); setBtnRunning(false); return; }
    } catch (e) {
      setNode(2, "error", "Failed");
      showError("Network error on /verify: " + e.message);
      setBtnRunning(false);
      return;
    }

    setNode(2, "success", "Sent");
    zkLog("zl-prover", "[PROVER]: Scalar proof response computed \u2192 s = " + verifyData.response_s);
    zkLog("zl-prover", "[PROVER]: s = (r + c\u00b7x) mod (P\u22121). Private x never transmitted.");

    await sleep(600);

    /* ── STEP 4: Validation result ─────────────────────────────────────── */
    setNode(3, "active", "Asserting\u2026");
    await sleep(300);

    if (verifyData.verified === true) {
      setNode(3, "success", "Verified \u2714");
      zkLog("zl-assert",  "[ASSERTION]: g^s \u2261 Y\u00b7y^c (mod P) \u2192 TRUE");
      zkLog("zl-success", "[SUCCESS]:   Zero-disclosure attestation cleared. Proof confirmed.");
    } else {
      setNode(3, "error", "Failed \u2718");
      zkLog("zl-failure", "[FAILURE]:   Proof assertion failed. Mathematical relationship invalid.");
    }

    /* ── Summary ──────────────────────────────────────────────────────── */
    document.getElementById("zkpBytesVal").textContent   = "0";
    document.getElementById("zkpLeakageVal").textContent = verifyData.disclosure_rate || "0.00%";

    const proofEl   = document.getElementById("zkpProofVal");
    const validCard = document.getElementById("zkpValidCard");
    validCard.classList.remove("ts-card-ok", "ts-card-err");
    if (verifyData.verified === true) {
      proofEl.textContent = "YES";
      validCard.classList.add("ts-card-ok");
    } else {
      proofEl.textContent = "NO";
      validCard.classList.add("ts-card-err");
    }

    summary.style.display = "";
    setBtnRunning(false);
  });

})();  // end initZKPSuite IIFE
