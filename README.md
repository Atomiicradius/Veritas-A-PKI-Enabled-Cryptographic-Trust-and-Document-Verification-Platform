# Veritas: PKI-Enabled Cryptographic Trust and Document Verification Platform

Veritas is a professional cryptographic analysis, simulation, and verification platform. Designed as a self-contained environment, the application demonstrates public key infrastructure (PKI) management, digital signature verification (RSA-PSS), Timestamp Authority (TSA) integration, and hierarchical file integrity verification via Merkle Trees. The platform features persistent database auditing, avalanche effect simulation, and system-wide execution profiling.

---

## Table of Contents
1. [Core Features](#core-features)
2. [System Architecture & Core Components](#system-architecture--core-components)
3. [Directory Structure](#directory-structure)
4. [Installation & Prerequisites](#installation--prerequisites)
5. [Quick Start Guide](#quick-start-guide)
6. [Detailed API Reference](#detailed-api-reference)
7. [Database & Storage Formats](#database--storage-formats)
8. [Stabilization & Security Enhancements](#stabilization--security-enhancements)

---

## Core Features

### RSA-PSS Digital Signatures
* Supports standard key sizes of 1024-bit and 2048-bit RSA.
* Leverages secure hashing algorithms: SHA-256 and SHA-512.
* Utilizes RSA-PSS (Probabilistic Signature Scheme) padding for robust signature generation and verification.

### Simulated Public Key Infrastructure (PKI)
* Bootstraps a local Certificate Authority (CA) on startup, creating self-signed root credentials.
* Manages user identity verification via cryptographically signed X.509-like certificates in structured JSON formats.
* Implements a Certificate Revocation List (CRL) engine to programmatically invalidate credentials.

### Timestamp Authority (TSA)
* Implements a simulated RFC 3161 compliant TSA.
* Generates signed cryptographic time tokens for all signed documents.
* Verifies signer validity times and token signatures to prevent backdating or modifications.

### Merkle Tree Integrity Verification
* Chunks files into uniform 4 KB segments to compute cryptographic leaf nodes.
* Builds a hierarchical Merkle Tree to establish a single verifiable Merkle Root.
* Cross-compares document structures block-by-block, mapping and reporting exact segment mismatches.

### Avalanche Effect & Cryptanalysis Simulation
* Computes bit-level avalanche effects across a 16x16 visual grid representing a 256-bit hash structure.
* Evaluates key strength by estimating factorization timelines across varied compute clusters (e.g., local machines, distributed setups, quantum hardware).

### Persistent Audit Ledger
* Collects and records all security operations, performance metrics, and validation logs to a local database.

---

## System Architecture & Core Components

```
                +-----------------------------------------+
                |             Client Browser              |
                |   (Dashboard, Analysis, Audit Views)    |
                +--------------------+--------------------+
                                     | JSON / Multipart
                                     v
                +--------------------+--------------------+
                |          Flask Application Server       |
                |                  (app.py)               |
                +----+----------------+---------------+----+
                     |                |               |
                     v                v               v
            +--------+-------+ +------+-------+ +-----+--------+
            |  Crypto Engine | |  Analysis    | | Audit Ledger |
            |  (RSA, CA,     | |  (Avalanche, | | (SQLite Database)
            |  TSA, Signers) | |  Merkle,     | |              |
            |                | |  Benchmarks) | |              |
            +----------------+ +--------------+ +--------------+
```

1. **Routing and Logic Controller (`app.py`)**: Coordinates REST calls, validates files, handles JSON transactions, and updates the SQLite audit logger.
2. **Cryptographic Suite (`project/crypto/`)**: Hosts the underlying RSA operations, CA validation loops, timestamping mechanisms, and signature packaging.
3. **Cryptanalysis Suite (`project/analysis/`)**: Handles computational processes, including Merkle Tree creation, avalanche mapping, and runtime execution profiling.

---

## Directory Structure

```
project/
├── app.py                  # Web router and application logic controller
├── requirements.txt        # Package dependencies
├── audit.db                # SQLite persistent database (auto-generated)
├── keys/                   # User keys directory (userA, userB)
├── certificates/           # CA/TSA credentials and revocation list storage
├── uploads/                # Directory for temporary file processing
├── signatures/             # Output directory for generated signature files (.sig)
├── crypto/                 # Core cryptographic operations library
│   ├── keygen.py           # RSA public/private keypair generator
│   ├── hasher.py           # File hashing utility wrapper
│   ├── signer.py           # RSA-PSS signature generator
│   ├── verifier.py         # RSA-PSS signature verifier
│   ├── certificate.py      # Certificate Authority and CRL engine
│   └── timestamp.py        # Timestamp Authority engine
├── analysis/               # Cryptographic benchmarking and simulation scripts
│   ├── avalanche.py        # Bit-level avalanche effect logic
│   ├── attack_sim.py       # Key factoring simulator
│   ├── merkle.py           # Merkle tree construction and comparison utility
│   └── performance.py      # Execution profiling benchmarks
├── static/                 # Static asset resources
│   ├── css/style.css       # Layout styles and custom theme parameters
│   └── js/                 # Client scripts (dashboard.js, analysis.js, charts.js)
└── templates/              # Jinja2 HTML layout templates
```

---

## Installation & Prerequisites

### Prerequisites
* Python 3.10 or higher.
* Platform compatibility: Windows, macOS, or Linux.

### Set Up Steps
1. Navigate to the project directory:
   ```bash
   cd project
   ```

2. Install python dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Initialize local cryptographic keys and local CA (Optional - will auto-generate if missing):
   ```bash
   python generate_keys.py
   ```

4. Launch the web application:
   ```bash
   python app.py
   ```
   The local development server runs on `http://127.0.0.1:5000/`.

---

## Quick Start Guide

### Signing a Document
1. Access the web dashboard at `http://127.0.0.1:5000/`.
2. Upload a file using the **Document Operations** drag-and-drop area.
3. Choose the signing identity, key size, and hash algorithm.
4. Click **Sign Document**. The platform displays the signature metadata, verification pipeline status, and download links.

### Verifying a Document
1. Select the document you wish to verify.
2. Click **Verify Document** in the side operations list.
3. Upload the corresponding signature file (`.sig`), or let the dashboard reuse the signature payload from the current session.
4. Click **Run Verification** to process CA validity, TSA signatures, and signature padding.

---

## Detailed API Reference

### Document Operations

#### `POST /api/sign`
Signs an uploaded file.
* **Payload**: Multipart Form Data
  * `file`: File binary (required)
  * `user`: Identity string (e.g., `userA`)
  * `key_size`: RSA key size (`1024` or `2048`)
  * `hash_algo`: Hash function selection (`SHA-256` or `SHA-512`)
* **Response (JSON)**:
  ```json
  {
    "success": true,
    "sig_id": "string",
    "file_hash": "hex_string",
    "tsa_token": {
      "timestamp": "ISO-8601",
      "tsa": "String",
      "hash": "hex_string",
      "signature": "hex_string"
    },
    "merkle_root": "hex_string"
  }
  ```

#### `POST /api/verify`
Validates a document against a signature.
* **Payload**: Multipart Form Data
  * `file`: File binary (required)
  * `verifier_user`: Identity string
  * `hash_algo`: Hash function
  * `sig_file`: Optional `.sig` metadata file
  * `sig_id`: Optional identifier string (reused from local session)
* **Response (JSON)**:
  ```json
  {
    "valid": true,
    "file_hash": "hex_string",
    "certificate_valid": true,
    "timestamp_valid": true,
    "merkle_verify": {
      "merkle_matches": true
    }
  }
  ```

#### `POST /api/compare`
Compares files to trace bit modifications and structural block diffs.
* **Payload**: Multipart Form Data
  * `file1`: Base file binary
  * `file2`: Modified file binary
* **Response (JSON)**:
  ```json
  {
    "hash1": "hex_string",
    "hash2": "hex_string",
    "diff_byte_count": 0,
    "hamming_distance": 0,
    "avalanche": {
      "flip_percent": 0.0
    },
    "merkle": {
      "roots_match": true,
      "original_chunks": 1,
      "modified_chunks": 1,
      "mismatch_count": 0,
      "mismatched_chunks": []
    }
  }
  ```

### PKI / CA Operations

#### `GET /api/pki/crl`
Queries the Certificate Revocation List.
* **Response (JSON)**:
  ```json
  {
    "revoked": [
      {
        "cert_id": "string",
        "revoked_at": "ISO-8601"
      }
    ]
  }
  ```

#### `POST /api/pki/revoke`
Revokes a cryptographic certificate.
* **Payload**: JSON
  * `cert_id`: Certificate identifier string
* **Response (JSON)**:
  ```json
  {
    "status": "revoked",
    "cert_id": "string",
    "revoked_at": "ISO-8601"
  }
  ```

---

## Database & Storage Formats

### SQLite Audit Ledger
All transactions are logged to the local database file `audit.db`. The table schema contains:
* `timestamp`: ISO-8601 string of the transaction time.
* `operation`: The operation performed (e.g., `SIGN`, `VERIFY`, `REVOKE`).
* `filename`: Name of the file processed.
* `file_hash`: Cryptographic digest of the file.
* `signer`: Signer's name (e.g., `userA`).
* `key_size`: RSA key size utilized.
* `result`: Status flag (`SUCCESS`, `FAILED`, `REVOKED`, `INVALID`).
* `certificate_id`: Associated public-key certificate ID.
* `certificate_status`: Verification status of the certificate.
* `timestamp_status`: TSA signature status.
* `merkle_root`: Root of the document's Merkle Tree.
* `notes`: Additional execution contexts.

### Signature Metadata Payload (`.sig` / `.json`)
When signing, a JSON structure is exported to bundle metadata:
* `sig_id`: Base64 or Hex identifier.
* `file_hash`: File's hash value.
* `hash_algo`: Selected hash algorithm.
* `signature`: RSA-PSS signature hex string.
* `cert_id`: Issuer certificate ID.
* `tsa_token`: Signed Timestamp Authority proof.
* `merkle_root`: Document Merkle Tree root.
* `chunk_count`: Number of 4 KB blocks in the document.

---

## Stabilization & Security Enhancements

The platform has been updated to improve user experience, system safety, and overall reliability:

1. **Inline DOM Validation**: Browser alert boxes (`alert()`) have been removed. Errors are rendered in red inline containers (`.v-error`) with context-specific descriptions.
2. **Two-Step Verification Flow**: Decoupled UI controls to prevent race conditions. Users click `Verify Document` to display settings, select the validator key or signature file, and then trigger `Run Verification`.
3. **Cross-Page State Persistence**: The platform utilizes browser local storage to synchronize TSA tokens. Signing a document on the main dashboard automatically populates the TSA status panel on the Analysis page.
4. **Certificate Lookup Details**:
   * The PKI lookup table shows the complete Certificate ID along with copy options.
   * Revoking a certificate automatically triggers smooth scrolling to the updated Certificate Revocation List.
   * The revocation view includes "Legacy Revocation" indicators for certificates modified before timestamping was introduced.
5. **Confirmation Guards**: High-risk operations (such as resetting the SQLite audit log) require confirmation via an overlay modal before running.
6. **Unified Styling Rules**: Removed bootstrap dependencies and defined consistent button styles, including `.v-btn-danger`, for a uniform dark-theme look.
