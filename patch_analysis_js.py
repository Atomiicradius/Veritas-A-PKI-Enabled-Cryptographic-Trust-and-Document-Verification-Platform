"""
patch_analysis_js.py
Replace the PKI section of analysis.js (btn-pki-check + btn-pki-crl) with
the full revocation-aware version that includes:
  - _currentCertId tracking
  - btn-pki-revoke / pki-revoked-badge state management
  - btn-confirm-revoke AJAX handler calling POST /api/pki/revoke
  - backdrop click to close modal
  - Enhanced CRL table renderer (cert_id | revoked_at | copy button)

Run once then delete.
"""
import re

PATH = "static/js/analysis.js"
content = open(PATH, encoding="utf-8").read()

OLD = content[content.find('/* \u2500\u2500 PKI: Certificate status lookup'):
               content.find("/* \u2500\u2500 TSA: Helper to populate the TSA panel")]

NEW = r"""/* \u2500\u2500 PKI: Certificate status lookup + Revoke state \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500 */
let _currentCertId = null;   // cert_id currently displayed in the panel

document.getElementById("btn-pki-check").addEventListener("click", async () => {
  const certId = document.getElementById("pki-cert-id-input").value.trim();
  if (!certId) return alert("Paste a cert_id first.");
  try {
    const res  = await fetch(`/api/pki/status?cert_id=${encodeURIComponent(certId)}`);
    const data = await res.json();
    if (data.error) return alert(data.error);

    const cert = data.certificate;
    const ver  = data.verification;
    _currentCertId = cert.cert_id;

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

    // \u2500\u2500 Show / hide the revocation action area \u2500\u2500
    const area        = document.getElementById("pki-revoke-area");
    const revokeBtn   = document.getElementById("btn-pki-revoke");
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
    alert("Error: " + e.message);
  }
});

/* \u2500\u2500 PKI: Confirm revoke \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500 */
document.getElementById("btn-confirm-revoke").addEventListener("click", async () => {
  if (!_currentCertId) return;
  const btn = document.getElementById("btn-confirm-revoke");
  btn.disabled    = true;
  btn.textContent = "Revoking\u2026";

  try {
    const res  = await fetch("/api/pki/revoke", {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body:    JSON.stringify({ cert_id: _currentCertId }),
    });
    const data = await res.json();
    document.getElementById("revokeModal").style.display = "none";

    if (data.status === "revoked") {
      // Update status rows in-place
      document.getElementById("pki-revoked").innerHTML = '<span class="t-badge err">Revoked</span>';
      document.getElementById("pki-valid").innerHTML   = '<span class="t-badge err">Invalid</span>';
      document.getElementById("pki-reason-badge").innerHTML =
        '<span class="t-badge warn">certificate_revoked</span>';

      // Swap button \u2192 badge
      document.getElementById("btn-pki-revoke").style.display    = "none";
      document.getElementById("pki-revoked-badge").style.display = "";

      // Auto-refresh CRL list
      document.getElementById("btn-pki-crl").click();

      // Toast notification
      const toast = document.createElement("div");
      toast.textContent = "Certificate revoked successfully.";
      toast.style.cssText =
        "position:fixed;bottom:24px;right:24px;z-index:9999;" +
        "background:var(--navy);color:#fff;padding:10px 18px;" +
        "border-radius:var(--radius-sm);font-size:.8125rem;font-weight:500;" +
        "box-shadow:var(--shadow);";
      document.body.appendChild(toast);
      setTimeout(() => toast.remove(), 2500);
    } else {
      alert("Revocation failed: " + (data.error || "Unknown error"));
    }
  } catch (e) {
    alert("Request failed: " + e.message);
  } finally {
    btn.disabled    = false;
    btn.textContent = "Revoke";
    // Re-add SVG icon (simpler: just set innerHTML)
    btn.innerHTML = `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/></svg> Revoke`;
  }
});

/* Close revokeModal on backdrop click */
document.getElementById("revokeModal").addEventListener("click", function(e) {
  if (e.target === this) this.style.display = "none";
});

/* \u2500\u2500 PKI: Load / Refresh CRL \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500 */
document.getElementById("btn-pki-crl").addEventListener("click", async () => {
  try {
    const res  = await fetch("/api/pki/crl");
    const data = await res.json();
    const list = document.getElementById("pki-crl-list");

    if (!data.revoked || data.revoked.length === 0) {
      list.innerHTML = `<p style="color:var(--text-3);font-size:.8125rem;padding:8px 0;">
        No certificates have been revoked.</p>`;
    } else {
      // Enhanced table: cert_id | revoked_at | copy
      let html = `<table style="width:100%;border-collapse:collapse;">
        <thead><tr style="background:var(--bg-subtle);">
          <th style="padding:6px 8px;font-size:.6rem;font-weight:600;letter-spacing:.06em;
            text-transform:uppercase;color:var(--text-2);border-bottom:1.5px solid var(--border);
            text-align:left;">Certificate ID</th>
          <th style="padding:6px 8px;font-size:.6rem;font-weight:600;letter-spacing:.06em;
            text-transform:uppercase;color:var(--text-2);border-bottom:1.5px solid var(--border);
            text-align:left;">Revoked At</th>
          <th style="padding:6px 8px;border-bottom:1.5px solid var(--border);"></th>
        </tr></thead><tbody>`;

      data.revoked.forEach(entry => {
        // Support old plain-string format + new dict format
        const id = typeof entry === "string" ? entry : entry.cert_id;
        const ts = (typeof entry === "object" && entry.revoked_at && entry.revoked_at !== "unknown")
          ? entry.revoked_at.replace("T", " ").slice(0, 19) + " UTC"
          : "\u2014";
        html += `<tr style="border-bottom:1px solid var(--border);">
          <td style="padding:6px 8px;font-family:'IBM Plex Mono',monospace;font-size:.6rem;
            color:var(--slate);" title="${id}">${id.slice(0, 20)}\u2026</td>
          <td style="padding:6px 8px;font-size:.75rem;color:var(--text-2);white-space:nowrap;">${ts}</td>
          <td style="padding:6px 8px;text-align:right;">
            <button onclick="copyToClipboard('${id}')" title="Copy full cert_id"
              style="background:none;border:none;cursor:pointer;color:var(--slate);
                     padding:0;display:inline-flex;align-items:center;gap:3px;font-size:.75rem;">
              <svg width="11" height="11" viewBox="0 0 24 24" fill="none"
                stroke="currentColor" stroke-width="2">
                <rect x="9" y="9" width="13" height="13" rx="2"/>
                <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>
              </svg>
              Copy
            </button>
          </td>
        </tr>`;
      });
      html += "</tbody></table>";
      list.innerHTML = html;
    }
    document.getElementById("pki-crl-result").style.display = "";
  } catch (e) {
    alert("Failed to load CRL: " + e.message);
  }
});

"""

if OLD not in content:
    print("ERROR: Could not find the PKI section to replace.")
    print("Searching for marker...")
    idx = content.find("btn-pki-check")
    print(f"  btn-pki-check found at char {idx}")
    exit(1)

new_content = content.replace(OLD, NEW)
open(PATH, "w", encoding="utf-8").write(new_content)
print(f"Done. Replaced {len(OLD)} chars with {len(NEW)} chars.")
print(f"New file: {len(new_content)} chars ({len(new_content.splitlines())} lines)")
