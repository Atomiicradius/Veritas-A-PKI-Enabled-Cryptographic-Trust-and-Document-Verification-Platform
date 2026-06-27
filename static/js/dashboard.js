/* ── State ───────────────────────────────────────────────────────── */
let uploadedFile = null;
let currentSigId = null;
let currentHash = null;
let hashIsHex = true;
let perfBenchMode = "file_size";
let perfChart = null;

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

/* ── Shared inline error helper (Phase 4 — replaces all alert()) ── */
function showInlineError(elementId, message) {
  const el = document.getElementById(elementId);
  if (!el) return;
  // If element has a child span for the message, set that; else set textContent
  const msgSpan = el.querySelector("span[id$='-msg']") || el.querySelector("span");
  if (msgSpan) msgSpan.textContent = message;
  else el.childNodes[el.childNodes.length - 1].textContent = " " + message;
  el.style.display = "flex";
  // Auto-hide after 6 seconds
  clearTimeout(el._hideTimer);
  el._hideTimer = setTimeout(() => el.style.display = "none", 6000);
}
function hideInlineError(elementId) {
  const el = document.getElementById(elementId);
  if (el) el.style.display = "none";
}

/* ── File Upload ─────────────────────────────────────────────────── */
const dropZone    = document.getElementById("drop-zone");
const fileInput   = document.getElementById("file-input");
const fileNameDiv = document.getElementById("file-name");

dropZone.addEventListener("dragover", e => { e.preventDefault(); dropZone.classList.add("dragover"); });
dropZone.addEventListener("dragleave", () => dropZone.classList.remove("dragover"));
dropZone.addEventListener("drop", e => {
  e.preventDefault();
  dropZone.classList.remove("dragover");
  if (e.dataTransfer.files[0]) setFile(e.dataTransfer.files[0]);
});
fileInput.addEventListener("change", () => { if (fileInput.files[0]) setFile(fileInput.files[0]); });

function setFile(f) {
  uploadedFile = f;
  fileNameDiv.textContent = f.name + " (" + (f.size / 1024).toFixed(1) + " KB)";
  fileNameDiv.style.color = "var(--ok)";
  hideInlineError("file-error");
}

/* ─────────────────────────────────────────────────────────────────
   BUG-02/03 FIX: btn-verify ONLY shows the verifier block.
   The actual API call is fired by btn-run-verify (inside the block).
   ──────────────────────────────────────────────────────────────── */
document.getElementById("btn-verify").addEventListener("click", () => {
  document.getElementById("verifier-block").style.display = "";
  document.getElementById("sig-upload-block").style.display = "";
  hideInlineError("verify-error");
});

/* ── Sign ────────────────────────────────────────────────────────── */
document.getElementById("btn-sign").addEventListener("click", async () => {
  // BUG-01 FIX: inline error instead of alert()
  if (!uploadedFile) {
    showInlineError("file-error", "Please upload a file first.");
    return;
  }
  hideInlineError("file-error");

  const user     = document.getElementById("user-select").value;
  const keySize  = document.querySelector("input[name='key-size']:checked").value;
  const hashAlgo = document.querySelector("input[name='hash-algo']:checked").value;

  setStatus("Hashing document…", "info");
  const fd = new FormData();
  fd.append("file", uploadedFile);
  fd.append("user", user);
  fd.append("key_size", keySize);
  fd.append("hash_algo", hashAlgo);

  try {
    setStatus("Signing with RSA-PSS…", "info");
    const res = await fetch("/api/sign", { method: "POST", body: fd });

    // ── PDF signing returns the stamped PDF directly, not JSON ──────────
    const ct = res.headers.get("Content-Type") || "";
    if (ct.includes("application/pdf")) {
      const sigId = res.headers.get("X-Sig-Id");
      const fileHash = res.headers.get("X-File-Hash");

      // Trigger a file download in the browser
      const blob = await res.blob();
      const url  = URL.createObjectURL(blob);
      const a    = document.createElement("a");
      // Try to get filename from Content-Disposition header
      const cd   = res.headers.get("Content-Disposition") || "";
      const fnMatch = cd.match(/filename[^;=\n]*=([^;\n]*)/);
      const filename = fnMatch ? fnMatch[1].trim().replace(/['"]/g, "") : "signed_document.pdf";
      a.download = filename;
      a.href = url;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);

      if (sigId) {
        currentSigId = sigId;
        currentHash  = fileHash;

        try {
          // Fetch signature details from the server to populate UI
          const sigRes = await fetch("/api/download_sig/" + sigId);
          const sigData = await sigRes.json();
          showResult("signed", "Signed");
          showHashDisplay(fileHash);
          showSigInfo(sigData);
          showDownloadLink(sigId);
          showSigIdDisplay(sigId);

          // Reconstruct the pipeline data for the UI
          const pipeline = [
            { id: "upload", label: "Document Upload", value: filename, status: "done" },
            { id: "hash", label: "SHA-256 Hash", value: fileHash.slice(0, 32) + "...", status: "done" },
            { id: "sign", label: "RSA-PSS Sign", value: sigData.key_size + "-bit key", status: "done" },
            { id: "output", label: "Signature Output", value: sigData.algorithm || "RSA-PSS-SHA256", status: "success" }
          ];
          renderPipeline(pipeline);

          // Populate TSA info if present
          if (sigData.tsa_token) {
            try {
              localStorage.setItem("lastTsaToken", JSON.stringify(sigData.tsa_token));
              localStorage.setItem("lastTsaValid", "null");
            } catch (_) {}
            if (typeof window.populateTsaPanel === "function") {
              window.populateTsaPanel(sigData.tsa_token, null);
            }
          }
        } catch (e) {
          console.error("Failed to populate UI details:", e);
        }
      }
      setStatus("PDF signed, stamped with QR, and downloaded successfully.", "success");
      return;
    }

    // ── All other file types return JSON ────────────────────────────────
    const data = await res.json();
    if (data.error) return setStatus("Error: " + data.error, "danger");

    currentSigId = data.sig_id;
    currentHash  = data.file_hash;
    showResult("signed", "Signed");
    showHashDisplay(data.file_hash);
    showSigInfo(data.sig_info);
    renderPipeline(data.pipeline);
    showDownloadLink(data.sig_id);
    // UX-03 FIX: show copyable sig_id
    showSigIdDisplay(data.sig_id);
    showV2Info(data);

    // BUG-04 FIX: persist TSA token in localStorage for Analysis page
    if (data.tsa_token) {
      try {
        localStorage.setItem("lastTsaToken", JSON.stringify(data.tsa_token));
        localStorage.setItem("lastTsaValid", "null"); // sign doesn't validate yet
      } catch (_) {}
    }
    // Populate TSA panel on Analysis page if loaded in the same session
    if (typeof window.populateTsaPanel === "function") {
      window.populateTsaPanel(data.tsa_token, null);
    }
    setStatus("Document signed successfully.", "success");
  } catch (e) {
    setStatus("Request failed: " + e.message, "danger");
  }
});

/* ── Run Verification (dedicated button inside verifier-block) ─── */
/* BUG-02/03 FIX: this is the ONLY handler that calls /api/verify   */
document.getElementById("btn-run-verify").addEventListener("click", async () => {
  // Validate file first
  if (!uploadedFile) {
    showInlineError("verify-error", "Please upload a file first.");
    return;
  }
  const sigFileInput = document.getElementById("sig-file-input");
  if (!sigFileInput.files[0] && !currentSigId) {
    showInlineError("verify-error", "Upload a .sig file or sign a document first.");
    return;
  }
  hideInlineError("verify-error");

  const verifierUser = document.getElementById("verifier-user-select").value;
  const hashAlgo     = document.querySelector("input[name='hash-algo']:checked").value;

  const fd = new FormData();
  fd.append("file", uploadedFile);
  fd.append("verifier_user", verifierUser);
  fd.append("hash_algo", hashAlgo);

  if (sigFileInput.files[0]) {
    fd.append("sig_file", sigFileInput.files[0]);
  } else {
    fd.append("sig_id", currentSigId);
  }

  setStatus("Verifying signature…", "info");
  try {
    const res  = await fetch("/api/verify", { method: "POST", body: fd });
    const data = await res.json();
    if (data.error) return setStatus("Error: " + data.error, "danger");

    currentHash = data.file_hash;
    const isValid = data.valid;
    showResult(isValid ? "valid" : "invalid", isValid ? "Valid" : "Invalid");
    showHashDisplay(data.file_hash);
    showSigInfo(data.sig_info);
    renderPipeline(data.pipeline);
    showV2Info(data);

    // BUG-04: persist TSA from verify result too
    const verifyTsa = data.sig_info && data.sig_info.tsa_token;
    if (verifyTsa) {
      try {
        localStorage.setItem("lastTsaToken", JSON.stringify(verifyTsa));
        localStorage.setItem("lastTsaValid", JSON.stringify(data.timestamp_valid));
      } catch (_) {}
    }
    if (typeof window.populateTsaPanel === "function") {
      window.populateTsaPanel(verifyTsa, data.timestamp_valid);
    }
    setStatus(isValid ? "Signature is valid." : "Signature is INVALID — document may have been tampered.", isValid ? "success" : "danger");
  } catch (e) {
    setStatus("Request failed: " + e.message, "danger");
  }
});

/* ── Tamper ──────────────────────────────────────────────────────── */
document.getElementById("btn-tamper").addEventListener("click", async () => {
  if (!uploadedFile) {
    showInlineError("file-error", "Please upload a file first.");
    return;
  }
  hideInlineError("file-error");

  const fd = new FormData();
  fd.append("file", uploadedFile);
  if (currentSigId) fd.append("sig_id", currentSigId);
  fd.append("verifier_user", document.getElementById("user-select").value);

  setStatus("Tampering file and re-verifying…", "warning");
  try {
    const res  = await fetch("/api/tamper", { method: "POST", body: fd });
    const data = await res.json();
    if (data.error) return setStatus("Error: " + data.error, "danger");

    showTamperDetails(data.tamper_info);

    if (data.avalanche) {
      showAvalancheTab(data.avalanche);
      document.querySelector('[data-target="#tab-avalanche"]').click();
    }

    if (data.verify_result) {
      showResult("invalid", "❌ INVALID (tampered)");
      showHashDisplay(data.file_hash);
      renderPipeline(data.pipeline);
      setStatus("File tampered — verification failed as expected.", "warning");
    } else {
      setStatus("File tampered. Upload the .sig to verify the change.", "warning");
    }
  } catch (e) {
    setStatus("Request failed: " + e.message, "danger");
  }
});

/* ── Compare Modal ───────────────────────────────────────────────── */
document.getElementById("btn-run-compare").addEventListener("click", async () => {
  const f1 = document.getElementById("cmp-file1").files[0];
  const f2 = document.getElementById("cmp-file2").files[0];
  // Phase 4: inline error inside modal instead of alert()
  const cmpError = document.getElementById("cmp-error");
  if (!f1 || !f2) {
    if (cmpError) {
      cmpError.textContent = "Please select both files before comparing.";
      cmpError.style.display = "flex";
    }
    return;
  }
  if (cmpError) cmpError.style.display = "none";

  const fd = new FormData();
  fd.append("file1", f1);
  fd.append("file2", f2);

  try {
    const res  = await fetch("/api/compare", { method: "POST", body: fd });
    const data = await res.json();
    if (data.error) {
      if (cmpError) { cmpError.textContent = data.error; cmpError.style.display = "flex"; }
      return;
    }

    document.getElementById("cmp-hash1").textContent = data.hash1;
    document.getElementById("cmp-hash2").textContent = data.hash2;
    document.getElementById("cmp-diff-bytes").textContent = data.diff_byte_count;
    document.getElementById("cmp-hamming").textContent = data.hamming_distance;
    document.getElementById("cmp-flip-pct").textContent = data.avalanche.flip_percent;
    renderAvalancheGrid("cmp-avalanche-grid", data.avalanche.cells);
    document.getElementById("cmp-result").style.display = "";
  } catch (e) {
    if (cmpError) { cmpError.textContent = "Error: " + e.message; cmpError.style.display = "flex"; }
  }
});

/* ── Performance Benchmark ───────────────────────────────────────── */
document.getElementById("bench-filesize").addEventListener("click", () => {
  perfBenchMode = "file_size";
  document.getElementById("bench-filesize").classList.add("active");
  document.getElementById("bench-keysize").classList.remove("active");
});
document.getElementById("bench-keysize").addEventListener("click", () => {
  perfBenchMode = "key_size";
  document.getElementById("bench-keysize").classList.add("active");
  document.getElementById("bench-filesize").classList.remove("active");
});

document.getElementById("btn-run-bench").addEventListener("click", async () => {
  setStatus("Running benchmark (this may take a few seconds)…", "info");
  try {
    const res  = await fetch("/api/performance", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ mode: perfBenchMode }),
    });
    const data = await res.json();
    if (data.error) return setStatus("Benchmark error: " + data.error, "danger");
    renderPerfChart(data.results, perfBenchMode);
    setStatus("Benchmark complete.", "success");
  } catch (e) {
    setStatus("Benchmark failed: " + e.message, "danger");
  }
});

/* ── Attack Sim ──────────────────────────────────────────────────── */
document.getElementById("btn-load-attack").addEventListener("click", async () => {
  try {
    const res  = await fetch("/api/attack_sim");
    const data = await res.json();
    renderAttackTable("attack-table", data.levels);
  } catch (e) {
    document.getElementById("attack-table").innerHTML = "<p class='text-danger'>Failed to load.</p>";
  }
});

/* ── Hash toggle ─────────────────────────────────────────────────── */
document.getElementById("btn-toggle-hash").addEventListener("click", () => {
  if (!currentHash) return;
  hashIsHex = !hashIsHex;
  if (hashIsHex) {
    document.getElementById("hash-display").textContent = currentHash;
  } else {
    const bin = currentHash.split("").map(c => parseInt(c, 16).toString(2).padStart(4, "0")).join(" ");
    document.getElementById("hash-display").textContent = bin;
  }
});

/* ── Helpers ─────────────────────────────────────────────────────── */
function setStatus(msg, type) {
  const bar = document.getElementById("status-bar");
  bar.className = "status-bar " + (type === "warning" ? "info" : type);
  const span = bar.querySelector("span") || bar;
  span.textContent = msg;
  bar.style.display = "flex";
}

function showResult(cls, label) {
  const badge = document.getElementById("result-badge");
  badge.className = "result-badge " + cls;
  badge.innerHTML = `<span class="rb-label">Status</span><span class="rb-value">${label}</span>`;
}

function showHashDisplay(hex) {
  currentHash = hex;
  hashIsHex = true;
  document.getElementById("hash-display").textContent = hex;
}

function showSigInfo(info) {
  document.getElementById("sig-info-block").style.display = "";
  document.getElementById("si-algo").textContent    = info.algorithm || "—";
  document.getElementById("si-keysize").textContent = (info.key_size || "—") + (info.key_size ? "-bit" : "");
  document.getElementById("si-signer").textContent  = info.signer || "—";
}

function showTamperDetails(info) {
  document.getElementById("tamper-details-block").style.display = "";
  document.getElementById("td-pos").textContent  = info.position;
  document.getElementById("td-orig").textContent = "0x" + info.original_hex;
  document.getElementById("td-new").textContent  = "0x" + info.new_hex;
}

/* UX-03 FIX: show copyable signature ID */
function showSigIdDisplay(sigId) {
  document.getElementById("sig-id-display").style.display = "";
  document.getElementById("sig-id-value").textContent = sigId;
}

function showDownloadLink(sigId) {
  const block = document.getElementById("download-sig-block");
  block.style.display = "";
  const link = document.getElementById("download-sig-link");
  link.href = "/api/download_sig/" + sigId;
  link.setAttribute("download", sigId + ".sig");
}

function showAvalancheTab(av) {
  document.getElementById("avalanche-placeholder").style.display = "none";
  const res = document.getElementById("avalanche-result");
  res.style.display = "";
  document.getElementById("av-hash1").textContent      = av.original_hash;
  document.getElementById("av-hash2").textContent      = av.modified_hash;
  document.getElementById("av-flip-count").textContent = av.flip_count;
  document.getElementById("av-flip-pct").textContent   = av.flip_percent;
  renderAvalancheGrid("avalanche-grid", av.cells);
}

function renderPipeline(steps) {
  const container = document.getElementById("pipeline-container");
  if (!steps || !steps.length) return;

  let html = '<div class="pipeline">';
  steps.forEach((step, i) => {
    const icons = { upload: "bi-file-earmark", hash: "bi-hash", sign: "bi-pen", output: "bi-check2-circle",
                    sig_hash: "bi-key", compare: "bi-arrows-collapse", result: "bi-shield-check" };
    const icon = icons[step.id] || "bi-circle";
    html += `
      <div class="pipeline-step ${step.status}">
        <div class="step-icon"><i class="bi ${icon}"></i></div>
        <div class="step-label">${step.label}</div>
        <div class="step-value">${step.value}</div>
      </div>`;
    if (i < steps.length - 1) {
      const arrowCls = step.status === "failure" ? "failure" : "";
      html += `<div class="pipeline-arrow ${arrowCls}"><i class="bi bi-arrow-right"></i></div>`;
    }
  });
  html += "</div>";
  container.innerHTML = html;
}

function renderPerfChart(results, mode) {
  const ctx = document.getElementById("perfChart");
  if (!ctx) return;
  if (ctx._chart) ctx._chart.destroy();

  let labels, hashData, signData, verifyData;
  if (mode === "file_size") {
    labels     = results.map(r => r.file_size_kb + " KB");
    hashData   = results.map(r => r.hash_avg);
    signData   = results.map(r => r.sign_avg);
    verifyData = results.map(r => r.verify_avg);
  } else {
    labels     = results.map(r => r.key_size + "-bit");
    hashData   = null;
    signData   = results.map(r => r.sign_avg);
    verifyData = results.map(r => r.verify_avg);
  }

  const datasets = [];
  if (hashData) datasets.push({ label: "Hashing", data: hashData, borderColor: "#6c757d", tension: 0.3 });
  datasets.push({ label: "Signing",      data: signData,   borderColor: "#0d6efd", tension: 0.3 });
  datasets.push({ label: "Verification", data: verifyData, borderColor: "#198754", tension: 0.3 });

  ctx._chart = new Chart(ctx, {
    type: "line",
    data: { labels, datasets },
    options: {
      responsive: true,
      plugins: { legend: { position: "top" } },
      scales: {
        x: { title: { display: true, text: mode === "file_size" ? "File Size" : "Key Size" } },
        y: { title: { display: true, text: "Time (ms)" }, beginAtZero: true },
      },
    },
  });
}

function renderAttackTable(containerId, levels) {
  const container = document.getElementById(containerId);
  let html = `<table class="table table-bordered table-sm security-table">
    <thead class="table-dark"><tr>
      <th>Key Size</th><th>Security Bits</th><th>Status</th><th>Factoring Estimate</th><th>NIST Status</th>
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
  container.innerHTML = html;
}

/* ── v2: Trust Chain summary in Right Panel ────────────────────── */
function showV2Info(data) {
  let v2Block = document.getElementById("v2-info-block");
  if (!v2Block) {
    v2Block = document.createElement("div");
    v2Block.id = "v2-info-block";
    const parent = document.getElementById("sig-info-block").parentNode;
    parent.appendChild(v2Block);
  }

  const certValid  = data.certificate_valid;
  const tsaValid   = data.timestamp_valid;
  const merkle     = data.merkle_verify || {};
  const cert       = data.certificate || (data.sig_info && data.sig_info.cert_id ? { cert_id: data.sig_info.cert_id } : null);
  const tsa        = data.tsa_token   || (data.sig_info && data.sig_info.tsa_token);
  const merkleRoot = data.merkle_root || (data.sig_info && data.sig_info.merkle_root);
  const certId     = cert && cert.cert_id ? cert.cert_id : null;

  function row(icon, label, status, sub) {
    const badgeCls = status === "ok" ? "ok" : status === "err" ? "err" : "pending";
    const iconSvg  = status === "ok"
      ? `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="var(--ok)" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>`
      : status === "err"
        ? `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="var(--err)" stroke-width="2.5"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>`
        : `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="var(--text-3)" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>`;
    return `<div class="trust-row">
      <span class="tr-label">${iconSvg} ${label}</span>
      <span class="t-badge ${badgeCls}">${sub || (status === "ok" ? "Verified" : status === "err" ? "Failed" : "N/A")}</span>
    </div>`;
  }

  const certStatus    = certValid === true  ? "ok" : certValid === false ? "err" : "pending";
  const tsaStatus     = tsaValid  === true  ? "ok" : tsaValid  === false ? "err" : (tsa ? "pending" : "pending");
  const merkleStatus  = merkle.merkle_matches === true  ? "ok" :
                        merkle.merkle_matches === false ? "err" :
                        merkleRoot ? "pending" : "pending";
  const rsaStatus     = data.valid === true ? "ok" : data.valid === false ? "err" : (data.status === "signed" ? "ok" : "pending");

  const certIdHtml = certId
    ? `<div style="font-size:.6875rem;color:var(--text-2);margin-top:6px;">
        Cert ID: <code class="mono" style="font-size:.625rem;">${certId.slice(0, 16)}…</code>
        <button onclick="copyToClipboard('${certId}')" title="Copy full cert_id" style="background:none;border:none;cursor:pointer;color:var(--slate);padding:0 2px;vertical-align:middle;">
          <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
        </button>
       </div>`
    : "";

  const tsaTimeHtml = tsa && tsa.timestamp
    ? `<div style="font-size:.6875rem;color:var(--text-2);margin-top:2px;">Signed: ${formatToIST(tsa.timestamp)}</div>`
    : "";

  const chunkCount = data.chunk_count || (data.sig_info && data.sig_info.chunk_count);
  const merkleHtml = chunkCount
    ? `<div style="font-size:.6875rem;color:var(--text-2);margin-top:2px;">${chunkCount} chunk${chunkCount !== 1 ? "s" : ""} verified</div>`
    : "";

  v2Block.innerHTML = `
    <div style="border-top:1px solid var(--border); margin-top:4px; padding-top:12px;">
      <p style="font-size:.6875rem;font-weight:600;letter-spacing:.07em;text-transform:uppercase;color:var(--text-2);margin:0 0 8px;">Trust Chain</p>
      ${row("", "Certificate",  certStatus)}
      ${certIdHtml}
      ${row("", "Timestamp Authority", tsaStatus)}
      ${tsaTimeHtml}
      ${row("", "Merkle Integrity", merkleStatus)}
      ${merkleHtml}
      ${row("", "RSA-PSS Signature",  rsaStatus)}
    </div>
  `;
}

/* ── Global clipboard helper ─────────────────────────── */
function copyToClipboard(text) {
  navigator.clipboard.writeText(text).then(() => {
    const tip = document.createElement("span");
    tip.textContent = " Copied!";
    tip.style.cssText = "font-size:.7rem;color:var(--ok);margin-left:4px;";
    document.activeElement.parentNode.appendChild(tip);
    setTimeout(() => tip.remove(), 1800);
  }).catch(() => {
    const el = document.createElement("textarea");
    el.value = text;
    document.body.appendChild(el);
    el.select();
    document.execCommand("copy");
    document.body.removeChild(el);
  });
}
// expose globally so analysis.js CRL buttons can also use it
window.copyToClipboard = copyToClipboard;
