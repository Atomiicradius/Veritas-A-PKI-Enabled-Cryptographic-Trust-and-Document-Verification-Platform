"""
Certificate Authority (PKI) simulation for CryptoDAA.

Provides:
  - generate_ca_keys()      – create / load the CA RSA key-pair
  - issue_certificate()     – sign a user's public key with the CA key
  - verify_certificate()    – validate CA signature + expiry
  - load_certificate()      – read a stored certificate from disk
  - revoke_certificate()    – add a cert_id to the CRL
  - is_revoked()            – check whether a cert_id is in the CRL
"""

import os
import json
import uuid
import base64
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.exceptions import InvalidSignature

# ── Directory paths ────────────────────────────────────────────────────────────
_BASE_DIR   = os.path.dirname(os.path.dirname(__file__))          # project/
CERTS_DIR   = os.path.join(_BASE_DIR, "certificates")
CRL_PATH    = os.path.join(CERTS_DIR, "revoked.json")
CA_PRIV_PATH = os.path.join(CERTS_DIR, "ca_private.pem")
CA_PUB_PATH  = os.path.join(CERTS_DIR, "ca_public.pem")

ISSUER_NAME = "CryptoDAA_CA"
CERT_VALIDITY_DAYS = 365


# ── Internal helpers ──────────────────────────────────────────────────────────

def _ensure_certs_dir() -> None:
    """Create the certificates/ directory if it doesn't exist."""
    os.makedirs(CERTS_DIR, exist_ok=True)


def _load_crl() -> list:
    """Return CRL as list of dicts {cert_id, revoked_at}.

    Backward-compatible: plain string entries (old format) are normalised
    to dicts transparently.
    """
    if not os.path.exists(CRL_PATH):
        return []
    with open(CRL_PATH, "r", encoding="utf-8") as f:
        raw = json.load(f)
    result = []
    for entry in raw:
        if isinstance(entry, str):
            result.append({"cert_id": entry, "revoked_at": "unknown"})
        else:
            result.append(entry)
    return result


def _save_crl(crl: list) -> None:
    _ensure_certs_dir()
    with open(CRL_PATH, "w", encoding="utf-8") as f:
        json.dump(crl, f, indent=2)


def _sign_payload(payload_bytes: bytes, private_key) -> str:
    """Sign arbitrary bytes with RSA-PSS and return a Base64 string."""
    sig = private_key.sign(
        payload_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )
    return base64.b64encode(sig).decode("utf-8")


def _verify_sig(payload_bytes: bytes, signature_b64: str, public_key) -> bool:
    """Verify an RSA-PSS signature. Returns True/False."""
    try:
        sig = base64.b64decode(signature_b64)
        public_key.verify(
            sig,
            payload_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return True
    except InvalidSignature:
        return False


# ── Public API ────────────────────────────────────────────────────────────────

def generate_ca_keys():
    """
    Generate (or load) the CA RSA key-pair.

    Keys are persisted in certificates/ca_private.pem and ca_public.pem.
    Returns (private_key, public_key).
    """
    _ensure_certs_dir()

    if os.path.exists(CA_PRIV_PATH) and os.path.exists(CA_PUB_PATH):
        with open(CA_PRIV_PATH, "rb") as f:
            priv = serialization.load_pem_private_key(f.read(), password=None)
        with open(CA_PUB_PATH, "rb") as f:
            pub = serialization.load_pem_public_key(f.read())
        return priv, pub

    # Generate a fresh 2048-bit CA key
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub  = priv.public_key()

    with open(CA_PRIV_PATH, "wb") as f:
        f.write(priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))
    with open(CA_PUB_PATH, "wb") as f:
        f.write(pub.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ))

    return priv, pub


def issue_certificate(subject: str, user_public_key) -> dict:
    """
    Issue a signed certificate for *subject*'s public key.

    The certificate JSON is stored in certificates/<cert_id>.json and
    the dict is returned.
    """
    _ensure_certs_dir()
    ca_priv, _ = generate_ca_keys()

    now     = datetime.now(timezone.utc)
    expires = now + timedelta(days=CERT_VALIDITY_DAYS)
    cert_id = uuid.uuid4().hex

    pub_pem = user_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")

    # Build the payload that will be signed (deterministic JSON)
    payload = {
        "cert_id":    cert_id,
        "subject":    subject,
        "public_key": pub_pem,
        "issuer":     ISSUER_NAME,
        "issued_at":  now.isoformat(),
        "expires_at": expires.isoformat(),
    }
    payload_bytes = json.dumps(payload, sort_keys=True).encode("utf-8")
    signature     = _sign_payload(payload_bytes, ca_priv)

    cert = {**payload, "signature": signature}

    cert_path = os.path.join(CERTS_DIR, f"{cert_id}.json")
    with open(cert_path, "w", encoding="utf-8") as f:
        json.dump(cert, f, indent=2)

    return cert


def load_certificate(cert_id: str) -> dict | None:
    """Load a certificate by its cert_id. Returns None if not found."""
    cert_path = os.path.join(CERTS_DIR, f"{cert_id}.json")
    if not os.path.exists(cert_path):
        return None
    with open(cert_path, "r", encoding="utf-8") as f:
        return json.load(f)


def verify_certificate(cert: dict) -> dict:
    """
    Verify a certificate dict against the CA public key.

    Checks:
      1. CA signature is valid
      2. Certificate has not expired
      3. Certificate is not revoked

    Returns a result dict with keys:
      certificate_valid (bool)
      cert_id
      subject
      issued_at
      expires_at
      revoked (bool)
      reason (str | None)
    """
    cert_id = cert.get("cert_id", "")
    subject = cert.get("subject", "")

    # ── Revocation check ─────────────────────────────────────────────
    if is_revoked(cert_id):
        return {
            "certificate_valid": False,
            "cert_id":    cert_id,
            "subject":    subject,
            "issued_at":  cert.get("issued_at"),
            "expires_at": cert.get("expires_at"),
            "revoked":    True,
            "reason":     "certificate_revoked",
        }

    # ── Expiry check ─────────────────────────────────────────────────
    try:
        expires_at = datetime.fromisoformat(cert["expires_at"])
        if datetime.now(timezone.utc) > expires_at:
            return {
                "certificate_valid": False,
                "cert_id":    cert_id,
                "subject":    subject,
                "issued_at":  cert.get("issued_at"),
                "expires_at": cert.get("expires_at"),
                "revoked":    False,
                "reason":     "certificate_expired",
            }
    except Exception:
        pass

    # ── CA signature check ───────────────────────────────────────────
    _, ca_pub = generate_ca_keys()
    sig = cert.get("signature", "")

    # Reconstruct the exact payload that was signed
    payload = {k: cert[k] for k in
               ("cert_id", "subject", "public_key", "issuer", "issued_at", "expires_at")}
    payload_bytes = json.dumps(payload, sort_keys=True).encode("utf-8")

    sig_valid = _verify_sig(payload_bytes, sig, ca_pub)

    if not sig_valid:
        return {
            "certificate_valid": False,
            "cert_id":    cert_id,
            "subject":    subject,
            "issued_at":  cert.get("issued_at"),
            "expires_at": cert.get("expires_at"),
            "revoked":    False,
            "reason":     "invalid_ca_signature",
        }

    return {
        "certificate_valid": True,
        "cert_id":    cert_id,
        "subject":    subject,
        "issued_at":  cert.get("issued_at"),
        "expires_at": cert.get("expires_at"),
        "revoked":    False,
        "reason":     None,
    }


# ── CRL management ─────────────────────────────────────────────────────────────

def revoke_certificate(cert_id: str) -> None:
    """Add *cert_id* to the CRL with a revocation timestamp.

    Idempotent — a second call for the same cert_id is a no-op.
    """
    crl        = _load_crl()
    existing   = {e["cert_id"] for e in crl}
    if cert_id not in existing:
        crl.append({
            "cert_id":    cert_id,
            "revoked_at": datetime.now(timezone.utc).isoformat(),
        })
        _save_crl(crl)


def is_revoked(cert_id: str) -> bool:
    """Return True if *cert_id* appears in the CRL."""
    return cert_id in {e["cert_id"] for e in _load_crl()}
