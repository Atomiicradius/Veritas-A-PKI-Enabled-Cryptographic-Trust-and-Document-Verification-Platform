import os
import json
import uuid
import shutil
import io
from functools import wraps

from flask import Flask, request, jsonify, render_template, send_from_directory, session, redirect, url_for, send_file

from crypto.keygen import generate_keys, save_keys, load_private_key, load_public_key
from crypto.hasher import compute_hash
from crypto.signer import sign_document
from crypto.verifier import verify_document
from analysis.avalanche import compute_avalanche_from_bytes
from analysis.attack_sim import (
    get_security_levels, tamper_file,
    naive_signature_verify, secure_signature_verify,
)
from audit.logger import (
    init_db, log_operation, get_all_logs, clear_logs,
    create_user, get_user_by_username, check_user_password
)
from qr_stamper import stamp_pdf_with_qr

import firebase_admin
from firebase_admin import credentials, auth

# Initialize Firebase Admin SDK
candidates = [
    os.path.join(os.path.dirname(__file__), "firebase-adminsdk.json"),
    os.path.join(os.path.dirname(__file__), "firebaseadminsdk.json")
]
cred_path = None
for p in candidates:
    if os.path.exists(p):
        cred_path = p
        break

try:
    if cred_path:
        cred = credentials.Certificate(cred_path)
        firebase_admin.initialize_app(cred)
    else:
        # Try default environment initialization
        firebase_admin.initialize_app()
except Exception as e:
    print(f"WARNING: Firebase Admin SDK could not be initialized: {e}")
    print("Please place your Firebase service account JSON file at 'firebaseadminsdk.json' in the project root.")

# ── New v2 modules (additive – do not remove existing imports) ────────────────
from crypto.certificate import (
    generate_ca_keys, issue_certificate, verify_certificate,
    load_certificate, revoke_certificate, is_revoked, CERTS_DIR,
)
from crypto.timestamp import generate_tsa_keys, create_timestamp, verify_timestamp
from analysis.merkle import generate_root_hash, verify_merkle_tree
from crypto.zkp import ZKPEngine, P as ZKP_P

BASE_DIR = os.path.dirname(__file__)
KEYS_DIR = os.path.join(BASE_DIR, "keys")
UPLOADS_DIR = os.path.join(BASE_DIR, "uploads")
SIGS_DIR = os.path.join(BASE_DIR, "signatures")
# CERTS_DIR is imported from crypto.certificate

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024  # 50 MB

# Session secret key loading/generating logic
SECRET_KEY_PATH = os.path.join(BASE_DIR, ".secret_key")
if os.path.exists(SECRET_KEY_PATH):
    with open(SECRET_KEY_PATH, "rb") as f:
        app.secret_key = f.read()
else:
    import secrets
    key = secrets.token_bytes(32)
    with open(SECRET_KEY_PATH, "wb") as f:
        f.write(key)
    app.secret_key = key


# ── Timezone formatting: convert UTC/ISO to Indian Standard Time (IST) ──────
@app.template_filter('to_ist')
def to_ist_filter(utc_str):
    if not utc_str:
        return ""
    try:
        from datetime import datetime, timezone, timedelta
        clean_str = utc_str.replace("Z", "")
        if "T" in clean_str:
            dt = datetime.fromisoformat(clean_str)
        else:
            dt = datetime.fromisoformat(clean_str.replace(" ", "T"))
        dt = dt.replace(tzinfo=timezone.utc)
        ist_tz = timezone(timedelta(hours=5, minutes=30))
        ist_dt = dt.astimezone(ist_tz)
        return ist_dt.strftime("%Y-%m-%d %H:%M:%S IST")
    except Exception:
        return utc_str


# Auth Decorators
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "username" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function


def api_login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "username" not in session:
            return jsonify({"error": "Unauthorized. Please log in."}), 401
        return f(*args, **kwargs)
    return decorated_function


def _ensure_dirs():
    for d in [KEYS_DIR, UPLOADS_DIR, SIGS_DIR, CERTS_DIR]:
        os.makedirs(d, exist_ok=True)


def _ensure_keys():
    for user, size in [("userA", 2048), ("userB", 2048)]:
        if not os.path.exists(os.path.join(KEYS_DIR, f"{user}_private.pem")):
            priv, pub = generate_keys(size)
            save_keys(priv, pub, user, KEYS_DIR)


def _ensure_ca_and_tsa():
    """Pre-generate CA and TSA key-pairs on startup (idempotent)."""
    generate_ca_keys()
    generate_tsa_keys()


def _save_upload(file_obj) -> str:
    filename = f"{uuid.uuid4().hex}_{file_obj.filename}"
    path = os.path.join(UPLOADS_DIR, filename)
    file_obj.save(path)
    return path


# ── Routes ──────────────────────────────────────────────────────────────────

@app.route("/")
@login_required
def dashboard():
    return render_template("dashboard.html")


@app.route("/analysis")
@login_required
def analysis_page():
    return render_template("analysis.html")


@app.route("/audit")
@login_required
def audit_page():
    logs = get_all_logs()
    return render_template("audit.html", logs=logs)


# ── Auth Routes ─────────────────────────────────────────────────────────────

@app.route("/signup", methods=["GET", "POST"])
def signup():
    if "username" in session:
        return redirect(url_for("dashboard"))
    
    if request.method == "POST":
        data = request.get_json(force=True) or {}
        id_token = data.get("idToken")
        email = data.get("email")
        username = data.get("username")
        
        if not id_token:
            return jsonify({"error": "Missing ID token"}), 400
            
        try:
            decoded_token = auth.verify_id_token(id_token)
            uid = decoded_token['uid']
            
            display_name = decoded_token.get("name") or username or email or "User"
            session["username"] = display_name
            session["firebase_uid"] = uid
            
            log_operation("USER_SIGNUP", display_name, "", display_name, 0, "SUCCESS", f"Firebase UID: {uid}")
            return jsonify({"success": True, "redirect": url_for("dashboard")})
        except Exception as e:
            log_operation("USER_SIGNUP", username or email or "?", "", "", 0, "FAILED", str(e))
            return jsonify({"error": f"Invalid ID token: {str(e)}"}), 401
            
    return render_template("signup.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if "username" in session:
        return redirect(url_for("dashboard"))
        
    if request.method == "POST":
        data = request.get_json(force=True) or {}
        id_token = data.get("idToken")
        
        if not id_token:
            return jsonify({"error": "Missing ID token"}), 400
            
        try:
            decoded_token = auth.verify_id_token(id_token)
            uid = decoded_token['uid']
            display_name = decoded_token.get("name") or decoded_token.get("email") or "User"
            session["username"] = display_name
            session["firebase_uid"] = uid
            
            log_operation("USER_LOGIN", display_name, "", display_name, 0, "SUCCESS", f"Firebase UID: {uid}")
            return jsonify({"success": True, "redirect": url_for("dashboard")})
        except Exception as e:
            log_operation("USER_LOGIN", "?", "", "?", 0, "FAILED", str(e))
            return jsonify({"error": f"Invalid ID token: {str(e)}"}), 401
            
    return render_template("login.html")


@app.route("/logout", methods=["GET", "POST"])
def logout():
    username = session.pop("username", None)
    session.pop("firebase_uid", None)
    if username:
        log_operation("USER_LOGOUT", username, "", username, 0, "SUCCESS", "User logged out")
    return redirect(url_for("login"))


@app.route("/api/sign", methods=["POST"])
@api_login_required
def api_sign():
    file = request.files.get("file")
    user = request.form.get("user", "userA")
    key_size = int(request.form.get("key_size", 2048))
    hash_algo = request.form.get("hash_algo", "SHA-256")

    if not file:
        return jsonify({"error": "No file provided"}), 400

    path = _save_upload(file)
    try:
        if key_size not in (1024, 2048):
            return jsonify({"error": "Only 1024 or 2048-bit keys for signing"}), 400

        stored_size = _get_stored_key_size(user)
        if stored_size != key_size:
            priv, pub = generate_keys(key_size)
            save_keys(priv, pub, user, KEYS_DIR)
        else:
            priv = load_private_key(user, KEYS_DIR)
            pub  = load_public_key(user, KEYS_DIR)

        file_hash = compute_hash(path, hash_algo.lower().replace("-", ""))
        sig_dict  = sign_document(path, priv, user, hash_algo)
        sig_dict["original_filename"] = file.filename

        # ── v2: PKI certificate ──────────────────────────────────────────
        cert     = issue_certificate(user, pub)
        cert_id  = cert["cert_id"]
        sig_dict["cert_id"] = cert_id

        # ── v2: TSA timestamp ────────────────────────────────────────────
        tsa_token = create_timestamp(file_hash)
        sig_dict["tsa_token"] = tsa_token

        # ── v2: Merkle root ──────────────────────────────────────────────
        with open(path, "rb") as fh:
            file_data = fh.read()
        merkle_info = generate_root_hash(file_data)
        sig_dict["merkle_root"]  = merkle_info["merkle_root"]
        sig_dict["chunk_count"]  = merkle_info["chunk_count"]

        sig_id   = uuid.uuid4().hex
        sig_path = os.path.join(SIGS_DIR, f"{sig_id}.sig")
        with open(sig_path, "w", encoding="utf-8") as fh:
            json.dump(sig_dict, fh, indent=2)

        log_operation(
            "SIGN", file.filename, file_hash, user, key_size, "SUCCESS",
            certificate_id=cert_id,
            certificate_status="ISSUED",
            timestamp_status="OK",
            merkle_root=merkle_info["merkle_root"],
        )

        # Check if the file is a PDF. If so, stamp it and return it directly.
        if file.filename.lower().endswith(".pdf"):
            qr_metadata = {
                "sig_id":      sig_id,
                "file_hash":   file_hash,
                "signer":      user,
                "timestamp":   tsa_token.get("timestamp") if isinstance(tsa_token, dict) else "",
                "merkle_root":  merkle_info["merkle_root"]
            }
            stamped_pdf = stamp_pdf_with_qr(file_data, qr_metadata)
            response = send_file(
                io.BytesIO(stamped_pdf),
                mimetype="application/pdf",
                as_attachment=True,
                download_name=f"signed_{file.filename}"
            )
            response.headers["X-Sig-Id"] = sig_id
            response.headers["X-File-Hash"] = file_hash
            response.headers["Access-Control-Expose-Headers"] = "X-Sig-Id, X-File-Hash"
            return response

        return jsonify({
            "status":      "signed",
            "sig_id":      sig_id,
            "file_hash":   file_hash,
            "sig_info":    sig_dict,
            "pipeline":    _build_pipeline("sign", file_hash, sig_dict, None),
            # v2 extras
            "certificate":       cert,
            "tsa_token":         tsa_token,
            "merkle_root":       merkle_info["merkle_root"],
            "chunk_count":       merkle_info["chunk_count"],
        })
    except Exception as e:
        log_operation("SIGN", file.filename, "", user, key_size, "ERROR", str(e))
        return jsonify({"error": str(e)}), 500
    finally:
        if os.path.exists(path):
            os.unlink(path)


@app.route("/api/verify", methods=["POST"])
@api_login_required
def api_verify():
    file = request.files.get("file")
    sig_file = request.files.get("sig_file")
    sig_id = request.form.get("sig_id")
    verifier_user = request.form.get("verifier_user", "userA")
    hash_algo = request.form.get("hash_algo", "SHA-256")

    if not file:
        return jsonify({"error": "No file provided"}), 400

    path = _save_upload(file)
    sig_path = None
    try:
        if sig_file:
            sig_path = _save_upload(sig_file)
            try:
                with open(sig_path, encoding="utf-8") as fh:
                    sig_dict = json.load(fh)
            except (UnicodeDecodeError, json.JSONDecodeError):
                return jsonify({"error": "Invalid signature file format. Please upload a valid .sig JSON file."}), 400
        elif sig_id:
            stored = os.path.join(SIGS_DIR, f"{sig_id}.sig")
            if not os.path.exists(stored):
                return jsonify({"error": "Signature not found"}), 404
            try:
                with open(stored, encoding="utf-8") as fh:
                    sig_dict = json.load(fh)
            except (UnicodeDecodeError, json.JSONDecodeError):
                return jsonify({"error": "Signature data corrupt or invalid."}), 400
        else:
            return jsonify({"error": "No signature provided"}), 400

        pub = load_public_key(verifier_user, KEYS_DIR)
        file_hash = compute_hash(path, hash_algo.lower().replace("-", ""))
        valid = verify_document(path, sig_dict, pub)
        result = "VALID" if valid else "INVALID"

        # ── v2: certificate check ────────────────────────────────────────
        cert_result   = {"certificate_valid": None}
        cert_meta     = None
        cert_id       = sig_dict.get("cert_id", "")
        if cert_id:
            cert_meta = load_certificate(cert_id)
            if cert_meta:
                cert_result = verify_certificate(cert_meta)
                if not cert_result["certificate_valid"]:
                    valid  = False
                    result = "INVALID"

        # ── v2: TSA check ──────────────────────────────────────────────
        tsa_result = {"timestamp_valid": None, "timestamp": None, "reason": None}
        tsa_token  = sig_dict.get("tsa_token")
        if tsa_token:
            tsa_result = verify_timestamp(tsa_token)

        # ── v2: Merkle check ─────────────────────────────────────────────
        merkle_verify = {}
        stored_root   = sig_dict.get("merkle_root")
        if stored_root:
            with open(path, "rb") as fh:
                current_data = fh.read()
            current_merkle = generate_root_hash(current_data)
            merkle_verify  = {
                "stored_root":    stored_root,
                "current_root":   current_merkle["merkle_root"],
                "merkle_matches": stored_root == current_merkle["merkle_root"],
                "chunk_count":    current_merkle["chunk_count"],
            }

        cert_status_str = "OK" if cert_result.get("certificate_valid") else (
            cert_result.get("reason") or "NOT_CHECKED"
        )
        tsa_status_str  = "OK" if tsa_result.get("timestamp_valid")  else (
            tsa_result.get("reason")  or "NOT_CHECKED"
        )

        log_operation(
            "VERIFY", file.filename, file_hash,
            sig_dict.get("signer", "?"), sig_dict.get("key_size", 0),
            result, f"verifier={verifier_user}",
            certificate_id=cert_id,
            certificate_status=cert_status_str,
            timestamp_status=tsa_status_str,
            merkle_root=sig_dict.get("merkle_root", ""),
        )

        return jsonify({
            # original fields (unchanged)
            "status":       result,
            "valid":        valid,
            "file_hash":    file_hash,
            "sig_info":     sig_dict,
            "pipeline":     _build_pipeline("verify", file_hash, sig_dict, valid),
            # v2 extras
            "certificate_valid": cert_result.get("certificate_valid"),
            "certificate":       cert_meta,
            "cert_result":       cert_result,
            "timestamp_valid":   tsa_result.get("timestamp_valid"),
            "tsa_result":        tsa_result,
            "merkle_verify":     merkle_verify,
        })
    except Exception as e:
        log_operation("VERIFY", file.filename, "", verifier_user, 0, "ERROR", str(e))
        return jsonify({"error": str(e)}), 500
    finally:
        if os.path.exists(path):
            os.unlink(path)
        if sig_path and os.path.exists(sig_path):
            os.unlink(sig_path)


@app.route("/api/tamper", methods=["POST"])
@api_login_required
def api_tamper():
    file = request.files.get("file")
    sig_id = request.form.get("sig_id")
    verifier_user = request.form.get("verifier_user", "userA")

    if not file:
        return jsonify({"error": "No file provided"}), 400

    path = _save_upload(file)
    try:
        with open(path, "rb") as f:
            orig_data = f.read()

        tamper_info = tamper_file(path)

        with open(path, "rb") as f:
            tampered_data = f.read()

        avalanche = compute_avalanche_from_bytes(orig_data, tampered_data)

        result = {"tamper_info": tamper_info, "avalanche": avalanche}

        if sig_id:
            stored = os.path.join(SIGS_DIR, f"{sig_id}.sig")
            if os.path.exists(stored):
                try:
                    with open(stored, encoding="utf-8") as f:
                        sig_dict = json.load(f)
                except (UnicodeDecodeError, json.JSONDecodeError):
                    sig_dict = None
                pub = load_public_key(verifier_user, KEYS_DIR)
                valid = verify_document(path, sig_dict, pub)
                file_hash = compute_hash(path, "sha256")
                result["verify_result"] = "INVALID" if not valid else "VALID"
                result["file_hash"] = file_hash
                result["pipeline"] = _build_pipeline("verify", file_hash, sig_dict, valid)

        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        if os.path.exists(path):
            os.unlink(path)


@app.route("/api/compare", methods=["POST"])
@api_login_required
def api_compare():
    file1 = request.files.get("file1")
    file2 = request.files.get("file2")

    if not file1 or not file2:
        return jsonify({"error": "Two files required"}), 400

    path1 = _save_upload(file1)
    path2 = _save_upload(file2)
    try:
        with open(path1, "rb") as fh:
            data1 = fh.read()
        with open(path2, "rb") as fh:
            data2 = fh.read()

        hash1 = compute_hash(path1, "sha256")
        hash2 = compute_hash(path2, "sha256")

        # Byte-level diff (original logic unchanged)
        diff_positions = [i for i in range(min(len(data1), len(data2))) if data1[i] != data2[i]]
        hamming = sum(bin(a ^ b).count("1") for a, b in zip(data1, data2))

        avalanche = compute_avalanche_from_bytes(data1, data2)

        # ── v2: Merkle comparison ──────────────────────────────────────────
        merkle_comparison = verify_merkle_tree(data1, data2)

        return jsonify({
            # original fields (unchanged)
            "hash1":               hash1,
            "hash2":               hash2,
            "match":              hash1 == hash2,
            "diff_byte_count":    len(diff_positions),
            "hamming_distance":   hamming,
            "first_diff_positions": diff_positions[:20],
            "avalanche":          avalanche,
            # v2 extras
            "merkle": merkle_comparison,
        })
    finally:
        for p in [path1, path2]:
            if os.path.exists(p):
                os.unlink(p)


@app.route("/api/performance", methods=["POST"])
@api_login_required
def api_performance():
    mode = request.json.get("mode", "file_size") if request.is_json else "file_size"
    key_size = int(request.json.get("key_size", 2048)) if request.is_json else 2048
    try:
        from analysis.performance import benchmark_by_file_size, benchmark_by_key_size
        if mode == "key_size":
            data = benchmark_by_key_size()
        else:
            data = benchmark_by_file_size(key_size)
        return jsonify({"results": data})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/attack_sim")
@api_login_required
def api_attack_sim():
    return jsonify({"levels": get_security_levels()})


@app.route("/api/analysis/simulate-timing-attack", methods=["POST"])
@api_login_required
def api_simulate_timing_attack():
    """Side-channel timing attack simulator.

    For each of the 16 target bytes we run two probes:
      - Fail probe  : set byte to 0xFF  → naive compare exits early
      - Lock probe  : set byte to correct value → naive compare matches one more byte
    Both probes are also run through the constant-time (secure) path for comparison.
    Returns two datasets (vulnerable / secure) for the frontend chart.
    """
    TARGET_SIG = b"VERITAS_SIG_2026"   # 16 bytes
    N = len(TARGET_SIG)

    vulnerable_dataset = []
    secure_dataset      = []

    current_guess = bytearray(N)        # starts as 16 × 0x00

    try:
        for i in range(N):
            # ── Fail probe: inject a wrong byte ──────────────────────────
            current_guess[i] = 0xFF
            _, v_fail_ms = naive_signature_verify(TARGET_SIG, bytes(current_guess))
            _, s_fail_ms = secure_signature_verify(TARGET_SIG, bytes(current_guess))

            vulnerable_dataset.append({
                "step":  i * 2,
                "state": f"Byte {i} Fail",
                "ms":    v_fail_ms,
            })
            secure_dataset.append({
                "step":  i * 2,
                "state": f"Byte {i} Fail",
                "ms":    s_fail_ms,
            })

            # ── Lock probe: inject the correct byte ───────────────────────
            current_guess[i] = TARGET_SIG[i]
            _, v_lock_ms = naive_signature_verify(TARGET_SIG, bytes(current_guess))
            _, s_lock_ms = secure_signature_verify(TARGET_SIG, bytes(current_guess))

            vulnerable_dataset.append({
                "step":  i * 2 + 1,
                "state": f"Byte {i} Lock",
                "ms":    v_lock_ms,
            })
            secure_dataset.append({
                "step":  i * 2 + 1,
                "state": f"Byte {i} Lock",
                "ms":    s_lock_ms,
            })

        return jsonify({
            "vulnerable": vulnerable_dataset,
            "secure":     secure_dataset,
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/audit")
@api_login_required
def api_audit():
    return jsonify({"logs": get_all_logs()})


@app.route("/api/zkp/initiate", methods=["POST"])
@api_login_required
def api_zkp_initiate():
    """Build Schnorr statement and commitment, persist both in session."""
    import secrets as _secrets
    data = request.get_json(force=True) or {}
    file_hash = data.get("file_hash") or "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    # Ensure it is a valid non-empty hex string
    if not file_hash or not all(c in '0123456789abcdefABCDEF' for c in file_hash):
        file_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    try:
        x, y = ZKPEngine.generate_statement(file_hash)
        r, Y = ZKPEngine.compute_commitment()

        # Persist both secret values in the server-side session
        session["zkp_x"] = str(x)
        session["zkp_r"] = str(r)
        session["zkp_y"] = str(y)
        session["zkp_Y"] = str(Y)
        session["zkp_file_hash"] = file_hash

        return jsonify({
            "public_identity_y": hex(y)[:24] + "...",
            "commitment_Y":      hex(Y)[:24] + "...",
            "group_params":      "RFC 3526 / 2048-bit MODP Group",
            "generator":         "G = 2",
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/zkp/challenge", methods=["POST"])
@api_login_required
def api_zkp_challenge():
    """Issue a deterministic challenge bit derived from the file hash and commitment Y."""
    import hashlib
    if 'zkp_file_hash' not in session or 'zkp_Y' not in session:
        return jsonify({"error": "No active ZKP session. Run /initiate first."}), 400

    try:
        user_input_hash = session.get('zkp_file_hash', '')
        public_commitment_Y = session.get('zkp_Y', '')

        binding_string = f"{user_input_hash}{public_commitment_Y}"
        hashed_val = hashlib.sha256(binding_string.encode('utf-8')).hexdigest()
        c = int(hashed_val, 16) % 2

        session['zkp_c'] = c
        return jsonify({ "challenge_bit": c })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/zkp/verify", methods=["POST"])
@api_login_required
def api_zkp_verify():
    """Compute scalar response s using stored challenge, and assert proof using re-calculated challenge."""
    import hashlib
    try:
        x = int(session["zkp_x"])
        r = int(session["zkp_r"])
        c_prover = int(session["zkp_c"])
        y = int(session["zkp_y"])
        Y = int(session["zkp_Y"])
    except KeyError:
        return jsonify({"error": "No active ZKP session. Run /initiate first."}), 400

    try:
        data = request.get_json(force=True) or {}
        file_hash = data.get("file_hash") or "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

        # Recompute challenge based on the verify-time file_hash and commitment Y
        binding_string = f"{file_hash}{Y}"
        hashed_val = hashlib.sha256(binding_string.encode('utf-8')).hexdigest()
        c_verifier = int(hashed_val, 16) % 2

        # Response s is calculated using the challenge c_prover generated during Step 2
        s = (r + c_prover * x) % (ZKP_P - 1)
        valid = ZKPEngine.assert_proof(Y, y, c_verifier, s)

        return jsonify({
            "response_s":    hex(s)[:24] + "...",
            "challenge_used": c_verifier,
            "verified":      valid,
            "disclosure_rate": "0.00%",
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500



@app.route("/api/audit/clear", methods=["POST"])
@api_login_required
def api_audit_clear():
    """Delete all rows from audit_log. Preserves schema; does NOT drop table."""
    try:
        deleted = clear_logs()
        return jsonify({"success": True, "deleted_records": deleted})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/download_sig/<sig_id>")
@api_login_required
def download_sig(sig_id):
    return send_from_directory(
        SIGS_DIR,
        f"{sig_id}.sig",
        as_attachment=True,
        download_name=f"{sig_id}.sig",
        mimetype="application/octet-stream"
    )


# ── PKI / Certificate routes (v2 additions) ──────────────────────────────

@app.route("/api/pki/issue", methods=["POST"])
@api_login_required
def api_pki_issue():
    """Manually issue a certificate for a user's public key."""
    data = request.get_json(force=True) or {}
    user = data.get("user", "userA")
    try:
        pub = load_public_key(user, KEYS_DIR)
        cert = issue_certificate(user, pub)
        return jsonify({"status": "issued", "certificate": cert})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/pki/revoke", methods=["POST"])
@api_login_required
def api_pki_revoke():
    """Add a cert_id to the Certificate Revocation List."""
    data    = request.get_json(force=True) or {}
    cert_id = data.get("cert_id", "").strip()
    if not cert_id:
        return jsonify({"error": "cert_id required"}), 400

    # Resolve subject for the audit log (non-fatal if cert not on disk)
    cert_meta = load_certificate(cert_id)
    subject   = cert_meta["subject"] if cert_meta else "unknown"

    # Check whether already revoked (is_revoked reads the CRL)
    already = is_revoked(cert_id)

    if not already:
        revoke_certificate(cert_id)

    # Write audit entry for every attempt
    log_operation(
        "CERTIFICATE_REVOKE",
        subject,
        "",
        "system",
        0,
        "SUCCESS" if not already else "ALREADY_REVOKED",
        f"cert_id={cert_id}",
        certificate_id=cert_id,
        certificate_status="REVOKED",
    )

    return jsonify({
        "status":          "revoked",
        "cert_id":         cert_id,
        "already_revoked": already,
    })


@app.route("/api/pki/status", methods=["GET"])
@api_login_required
def api_pki_status():
    """Check the status of a certificate by cert_id."""
    cert_id = request.args.get("cert_id", "")
    if not cert_id:
        return jsonify({"error": "cert_id query param required"}), 400
    cert = load_certificate(cert_id)
    if not cert:
        return jsonify({"error": "Certificate not found"}), 404
    result = verify_certificate(cert)
    return jsonify({"certificate": cert, "verification": result})


@app.route("/api/pki/crl", methods=["GET"])
@api_login_required
def api_pki_crl():
    """Return the current Certificate Revocation List."""
    from crypto.certificate import _load_crl
    return jsonify({"revoked": _load_crl()})


# ── Helpers ──────────────────────────────────────────────────────────────────

def _get_stored_key_size(user: str) -> int:
    try:
        priv = load_private_key(user, KEYS_DIR)
        return priv.key_size
    except Exception:
        return 2048


def _build_pipeline(operation: str, file_hash: str, sig_dict: dict, valid) -> list:
    steps = [
        {"id": "upload", "label": "Document Upload", "value": sig_dict.get("original_filename", "file"), "status": "done"},
        {"id": "hash", "label": "SHA-256 Hash", "value": file_hash[:32] + "...", "status": "done"},
    ]
    if operation == "sign":
        steps += [
            {"id": "sign", "label": "RSA-PSS Sign", "value": f"{sig_dict.get('key_size', '?')}-bit key", "status": "done"},
            {"id": "output", "label": "Signature Output", "value": sig_dict.get("algorithm", "RSA-PSS-SHA256"), "status": "success"},
        ]
    else:
        status = "success" if valid else "failure"
        steps += [
            {"id": "sig_hash", "label": "Signature Hash", "value": sig_dict.get("algorithm", "?"), "status": "done"},
            {"id": "compare", "label": "Hash Comparison", "value": "Match" if valid else "MISMATCH", "status": status},
            {"id": "result", "label": "Result", "value": "✅ VALID" if valid else "❌ INVALID", "status": status},
        ]
    return steps


if __name__ == "__main__":
    _ensure_dirs()
    _ensure_keys()
    _ensure_ca_and_tsa()   # v2: pre-generate CA + TSA key-pairs
    init_db()
    app.run(debug=True, port=5000)
