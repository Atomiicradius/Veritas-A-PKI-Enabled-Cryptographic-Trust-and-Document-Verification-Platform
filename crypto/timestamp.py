"""
Timestamp Authority (TSA) simulation for CryptoDAA.

Provides:
  - generate_tsa_keys()   – create / load the TSA RSA key-pair
  - create_timestamp()    – produce a signed timestamp token for a file hash
  - verify_timestamp()    – validate the TSA signature on a token
"""

import os
import json
import base64
from datetime import datetime, timezone

from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature

# ── Directory paths ────────────────────────────────────────────────────────────
_BASE_DIR    = os.path.dirname(os.path.dirname(__file__))          # project/
_TSA_DIR     = os.path.join(_BASE_DIR, "certificates")             # share dir
TSA_PRIV_PATH = os.path.join(_TSA_DIR, "tsa_private.pem")
TSA_PUB_PATH  = os.path.join(_TSA_DIR, "tsa_public.pem")
TSA_NAME      = "CryptoDAA_TSA"


# ── Internal helpers ──────────────────────────────────────────────────────────

def _ensure_tsa_dir() -> None:
    os.makedirs(_TSA_DIR, exist_ok=True)


# ── Public API ────────────────────────────────────────────────────────────────

def generate_tsa_keys():
    """
    Generate (or load) the TSA RSA key-pair.

    Keys are stored in certificates/tsa_private.pem and tsa_public.pem.
    Returns (private_key, public_key).
    """
    _ensure_tsa_dir()

    if os.path.exists(TSA_PRIV_PATH) and os.path.exists(TSA_PUB_PATH):
        with open(TSA_PRIV_PATH, "rb") as f:
            priv = serialization.load_pem_private_key(f.read(), password=None)
        with open(TSA_PUB_PATH, "rb") as f:
            pub = serialization.load_pem_public_key(f.read())
        return priv, pub

    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub  = priv.public_key()

    with open(TSA_PRIV_PATH, "wb") as f:
        f.write(priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))
    with open(TSA_PUB_PATH, "wb") as f:
        f.write(pub.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ))

    return priv, pub


def create_timestamp(file_hash: str) -> dict:
    """
    Create a signed timestamp token for *file_hash*.

    Returns a dict:
    {
        "timestamp":     "<ISO-8601 UTC string>",
        "hash":          "<hex file hash>",
        "tsa":           "CryptoDAA_TSA",
        "tsa_signature": "<Base64 RSA-PSS signature>"
    }
    """
    tsa_priv, _ = generate_tsa_keys()
    now = datetime.now(timezone.utc).isoformat()

    payload = {"timestamp": now, "hash": file_hash, "tsa": TSA_NAME}
    payload_bytes = json.dumps(payload, sort_keys=True).encode("utf-8")

    sig = tsa_priv.sign(
        payload_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )

    return {**payload, "tsa_signature": base64.b64encode(sig).decode("utf-8")}


def verify_timestamp(token: dict) -> dict:
    """
    Verify a timestamp token produced by *create_timestamp*.

    Returns:
    {
        "timestamp_valid": bool,
        "timestamp":       str | None,
        "reason":          str | None
    }
    """
    if not token:
        return {"timestamp_valid": False, "timestamp": None, "reason": "no_token"}

    _, tsa_pub = generate_tsa_keys()

    payload = {k: token[k] for k in ("timestamp", "hash", "tsa") if k in token}
    payload_bytes = json.dumps(payload, sort_keys=True).encode("utf-8")

    try:
        sig = base64.b64decode(token.get("tsa_signature", ""))
        tsa_pub.verify(
            sig,
            payload_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return {
            "timestamp_valid": True,
            "timestamp": token.get("timestamp"),
            "reason": None,
        }
    except InvalidSignature:
        return {
            "timestamp_valid": False,
            "timestamp": token.get("timestamp"),
            "reason": "invalid_tsa_signature",
        }
    except Exception as exc:
        return {
            "timestamp_valid": False,
            "timestamp": token.get("timestamp"),
            "reason": str(exc),
        }
