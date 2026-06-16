# Veritas: PKI-Enabled Cryptographic Trust & Document Verification Platform

Veritas is an interactive, web-based cryptographic analysis platform designed to simulate, visualize, and benchmark digital signatures (RSA-PSS) and document integrity structures. It provides an educational and functional playground for understanding Certificate Authorities, Timestamp Authorities, and Merkle Tree verification pipelines.

---

## 🚀 Features

### 1. RSA-PSS Digital Signatures
* Supports key sizes of **1024-bit** and **2048-bit**.
* Supports hashing algorithms: **SHA-256** and **SHA-512**.
* Incorporates deterministic **RSA-PSS** padding for maximum signature security.

### 2. Simulated PKI (Certificate Authority)
* Automatically generates simulated root **CA keys** on startup.
* Issues public-key **certificates** in JSON format containing Issuer, Subject, Validity dates, and RSA-PSS signatures.
* Exposes **Certificate Revocation Lists (CRL)** to verify and invalidate compromised credentials.

### 3. Timestamp Authority (TSA)
* Creates signed timestamp tokens for every document signed.
* Verifies signing time integrity by validating TSA signatures to prevent backdating.

### 4. Merkle Tree Chunk Verification
* Splits large files into fixed-size **4 KB chunks** and builds a Merkle Tree.
* Saves the **Merkle Root** hash into the signature metadata.
* Compares Merkle trees of original vs. modified documents to pinpoint exact mismatched chunk offsets.

### 5. Avalanche Effect & Attack Simulation
* Visualizes SHA-256 avalanche patterns on a 16x16 grid (256-bit representation) showing bit flips caused by minor changes.
* Evaluates RSA key security levels based on estimated factorization times against various hardware clusters.

### 6. Persistent Audit Logging
* Records all signature creations, verifications, and tampering events into a local SQLite database (`audit.db`).

---

## 🛠️ Technology Stack
* **Backend**: Python 3.10+, Flask
* **Cryptography**: `cryptography` library (PyCA)
* **Frontend**: HTML5, Vanilla CSS, Bootstrap 5, Chart.js
* **Database**: SQLite3

---

## 📦 Directory Structure

```
project/
├── app.py                  # Main Flask application entry point
├── requirements.txt        # Python dependencies
├── audit.db                # Persistent SQLite audit database (local only)
├── keys/                   # Local user cryptographic keys (userA, userB)
├── certificates/           # CA, TSA keys, issued certificates, and revoked.json
├── uploads/                # Directory for handling temporary file uploads
├── signatures/             # Generated signature JSON files (.sig)
├── crypto/                 # Core cryptographic operations
│   ├── keygen.py           # RSA Keypair generator
│   ├── hasher.py           # Hash utility helpers
│   ├── signer.py           # Document signing using RSA-PSS
│   ├── verifier.py         # Signature validation
│   ├── certificate.py      # Certificate Authority and CRL engine
│   └── timestamp.py        # Timestamp Authority engine
├── analysis/               # Cryptographic benchmarking and simulation
│   ├── avalanche.py        # Bit-level avalanche effect logic
│   ├── attack_sim.py       # Key factoring simulator
│   ├── merkle.py           # Merkle tree building and comparison
│   └── performance.py      # Execution runtime benchmarks
├── static/                 # Static files
│   ├── css/style.css       # Custom design styles
│   └── js/                 # Client-side scripts (dashboard.js, analysis.js, charts.js)
└── templates/              # HTML layout templates (dashboard.html, analysis.html, audit.html)
```

---

## 🔧 Installation & Setup

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/Atomiicradius/Veritas-A-PKI-Enabled-Cryptographic-Trust-and-Document-Verification-Platform.git
   cd Veritas-A-PKI-Enabled-Cryptographic-Trust-and-Document-Verification-Platform/project
   ```

2. **Install Dependencies**:
   Ensure you have Python installed, then run:
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the Application**:
   ```bash
   python app.py
   ```
   The application will start in debug mode, accessible at `http://127.0.0.1:5000/`.

---

## 📖 API Reference

### Document Operations
* **`POST /api/sign`**: Upload a file to sign it. Returns the file hash, signature payload, PKI certificate, TSA token, and Merkle root.
* **`POST /api/verify`**: Upload a file and its signature metadata to verify the CA certificate, TSA timestamp, and RSA signature integrity.
* **`POST /api/tamper`**: Artificially inject error bits into an uploaded document to simulate a tampering attack.
* **`POST /api/compare`**: Compare two files to compute bit-level avalanche percentages and Merkle tree chunk mismatches.
* **`POST /api/performance`**: Run timing benchmarks for different key sizes and file sizes.

### PKI / CA Operations
* **`GET /api/pki/crl`**: Fetch the list of revoked certificate IDs.
* **`POST /api/pki/issue`**: Manually request certificate issuance for a user.
* **`POST /api/pki/revoke`**: Revoke a specific certificate ID.
* **`GET /api/pki/status?cert_id=<id>`**: Query verification details and status for a specific certificate ID.

---

## 🔒 Release & Stabilization Updates

The platform recently underwent a comprehensive stability, UX, and security polish phase. Key improvements include:

* **Zero Browser Alerts**: Replaced legacy browser alerts (`alert()`) with elegant inline validation elements (`.v-error` panels) across all panels, ensuring professional visual hierarchy and preventing screen-blocking events.
* **Two-Step Verification Flow**: Resolved event race conditions by separating the action to show the verifier settings panel (`Verify Document`) from the actual verification trigger (`Run Verification`).
* **Cross-Page State Persistence**: Integrated local storage tracking for the Timestamp Authority (TSA) tokens. Signing a document on the dashboard now automatically populates the TSA details panel on the Analysis page.
* **PKI Status and Revocation Enhancements**:
  * Exposed full, copyable certificate IDs within the Certificate Status check response.
  * Added auto-scroll to the Revocation List view upon successfully revoking a certificate.
  * Dynamically updated the CRL loader action label to **Refresh CRL** on subsequent updates.
  * Implemented specific *Legacy Revocation* status markers for certificates revoked prior to timestamp logging.
* **Destructive Action Safety Guards**: Protected the audit ledger from accidental deletion by adding a confirmation modal popup ("Clear Audit Log?") before invoking the database reset.
* **Visual Theme Alignment**: Resolved styling issues with danger elements (e.g. `.v-btn-danger`) to match the clean, premium corporate dark-theme color palette.
