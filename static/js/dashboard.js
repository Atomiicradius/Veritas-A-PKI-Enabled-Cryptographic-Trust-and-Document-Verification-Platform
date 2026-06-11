/* ── State ───────────────────────────────────────────────────────── */
let uploadedFile = null;
let currentSigId = null;
let currentHash = null;
let hashIsHex = true;
let perfBenchMode = "file_size";
let perfChart = null;

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
}

/* ── Show/hide verifier block ────────────────────────────────────── */
document.getElementById("btn-verify").addEventListener("click", () => {
  document.getElementById("verifier-block").style.display = "";
  document.getElementById("sig-upload-block").style.display = "";
});

/* ── Sign ────────────────────────────────────────────────────────── */
document.getElementById("btn-sign").addEventListener("click", async () => {
  if (!uploadedFile) return alert("Please upload a file first.");
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
    const res  = await fetch("/api/sign", { method: "POST", body: fd });
    const data = await res.json();
    if (data.error) return setStatus("Error: " + data.error, "danger");

    currentSigId = data.sig_id;
    currentHash  = data.file_hash;
    showResult("signed", "✍️ Signed");
    showHashDisplay(data.file_hash);
    showSigInfo(data.sig_info);
    renderPipeline(data.pipeline);
    showDownloadLink(data.sig_id);
    showV2Info(data);           // v2: PKI / TSA / Merkle badges
    setStatus("Document signed successfully.", "success");
  } catch (e) {
    setStatus("Request failed: " + e.message, "danger");
  }
});

/* ── Verify ──────────────────────────────────────────────────────── */
document.getElementById("btn-verify").addEventListener("click", async () => {
  if (!uploadedFile) return alert("Please upload a file first.");
  const verifierUser = document.getElementById("verifier-user-select").value;
  const hashAlgo     = document.querySelector("input[name='hash-algo']:checked").value;
  const sigFileInput = document.getElementById("sig-file-input");

  const fd = new FormData();
  fd.append("file", uploadedFile);
  fd.append("verifier_user", verifierUser);
  fd.append("hash_algo", hashAlgo);

  if (sigFileInput.files[0]) {
    fd.append("sig_file", sigFileInput.files[0]);
  } else if (currentSigId) {
    fd.append("sig_id", currentSigId);
  } else {
    return alert("Please upload a .sig file or sign first.");
  }

  setStatus("Verifying signature…", "info");
  try {
    const res  = await fetch("/api/verify", { method: "POST", body: fd });
    const data = await res.json();
    if (data.error) return setStatus("Error: " + data.error, "danger");

    currentHash = data.file_hash;
    const isValid = data.valid;
    showResult(isValid ? "valid" : "invalid", isValid ? "✅ VALID" : "❌ INVALID");
    showHashDisplay(data.file_hash);
    showSigInfo(data.sig_info);
    renderPipeline(data.pipeline);
    showV2Info(data);           // v2: PKI / TSA / Merkle badges
    setStatus(isValid ? "Signature is valid." : "Signature is INVALID — document may have been tampered.", isValid ? "success" : "danger");
  } catch (e) {
    setStatus("Request failed: " + e.message, "danger");
  }
});

/* ── Tamper ──────────────────────────────────────────────────────── */
document.getElementById("btn-tamper").addEventListener("click", async () => {
  if (!uploadedFile) return alert("Please upload a file first.");

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
      // Switch to avalanche tab
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
  if (!f1 || !f2) return alert("Select two files.");

  const fd = new FormData();
  fd.append("file1", f1);
  fd.append("file2", f2);

  try {
    const res  = await fetch("/api/compare", { method: "POST", body: fd });
    const data = await res.json();
    if (data.error) return alert(data.error);

    document.getElementById("cmp-hash1").textContent = data.hash1;
    document.getElementById("cmp-hash2").textContent = data.hash2;
    document.getElementById("cmp-diff-bytes").textContent = data.diff_byte_count;
    document.getElementById("cmp-hamming").textContent = data.hamming_distance;
    document.getElementById("cmp-flip-pct").textContent = data.avalanche.flip_percent;
    renderAvalancheGrid("cmp-avalanche-grid", data.avalanche.cells);
    document.getElementById("cmp-result").style.display = "";
  } catch (e) {
    alert("Error: " + e.message);
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
  // update the text node inside the <span>
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

function showDownloadLink(sigId) {
  const block = document.getElementById("download-sig-block");
  block.style.display = "";
  document.getElementById("download-sig-link").href = "/api/download_sig/" + sigId;
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

/* ── v2: Show PKI / TSA / Merkle summary badges in Right Panel ───── */
function showV2Info(data) {
  // Reuse or create the v2 summary block inside the right panel card-body
  let v2Block = document.getElementById("v2-info-block");
  if (!v2Block) {
    // Append once after sig-info-block
    v2Block = document.createElement("div");
    v2Block.id = "v2-info-block";
    const parent = document.getElementById("sig-info-block").parentNode;
    parent.appendChild(v2Block);
  }

  const certValid  = data.certificate_valid;
  const tsaValid   = data.timestamp_valid;
  const merkle     = data.merkle_verify || {};
  const cert       = data.certificate   || (data.sig_info && data.sig_info.cert_id ? {cert_id: data.sig_info.cert_id} : null);
  const tsa        = data.tsa_token     || (data.sig_info && data.sig_info.tsa_token);
  const merkleRoot = data.merkle_root   || (data.sig_info && data.sig_info.merkle_root);

  const certBadge = certValid === true
    ? '<span class="badge bg-success">✓ Cert Valid</span>'
    : certValid === false
      ? '<span class="badge bg-danger">✗ Cert Invalid</span>'
      : '<span class="badge bg-secondary">Cert: N/A</span>';

  const tsaBadge = tsaValid === true
    ? '<span class="badge bg-success">✓ TSA Valid</span>'
    : tsaValid === false
      ? '<span class="badge bg-danger">✗ TSA Invalid</span>'
      : (tsa ? '<span class="badge bg-secondary">TSA: N/A</span>' : '');

  const merkleBadge = merkle.merkle_matches === true
    ? '<span class="badge bg-success">✓ Merkle OK</span>'
    : merkle.merkle_matches === false
      ? '<span class="badge bg-danger">✗ Merkle Mismatch</span>'
      : (merkleRoot ? '<span class="badge bg-secondary">Merkle: signed</span>' : '');

  const certIdDisplay = cert && cert.cert_id
    ? `<div class="small text-muted mt-1">Cert ID: <code style="font-size:0.6rem">${cert.cert_id.slice(0,16)}…</code></div>`
    : '';

  const tsaTimeDisplay = tsa && tsa.timestamp
    ? `<div class="small text-muted">Signed at: ${tsa.timestamp.replace('T',' ').slice(0,19)} UTC</div>`
    : '';

  const merkleChunks = data.chunk_count || (data.sig_info && data.sig_info.chunk_count);
  const merkleChunkDisplay = merkleChunks
    ? `<div class="small text-muted">Chunks: ${merkleChunks}</div>`
    : '';

  v2Block.innerHTML = `
    <label class="form-label fw-semibold small mb-1">PKI / TSA / Merkle</label>
    <div class="d-flex flex-wrap gap-1 mb-1">${certBadge}${tsaBadge ? ' ' + tsaBadge : ''}${merkleBadge ? ' ' + merkleBadge : ''}</div>
    ${certIdDisplay}${tsaTimeDisplay}${merkleChunkDisplay}
  `;
}
