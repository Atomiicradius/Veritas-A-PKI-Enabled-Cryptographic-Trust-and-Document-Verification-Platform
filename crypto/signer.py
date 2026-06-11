import base64
import json
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes


def _get_hash_algo(hash_algo: str):
    algo = hash_algo.upper().replace("-", "")
    if algo == "SHA512":
        return hashes.SHA512()
    return hashes.SHA256()


def sign_document(file_path: str, private_key, signer: str, hash_algo: str = "SHA-256") -> dict:
    with open(file_path, "rb") as f:
        data = f.read()

    h = _get_hash_algo(hash_algo)
    signature_bytes = private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(h),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        h,
    )

    key_size = private_key.key_size
    algo_label = f"RSA-PSS-{hash_algo.upper().replace('-', '')}"

    return {
        "algorithm": algo_label,
        "key_size": key_size,
        "signer": signer,
        "signature": base64.b64encode(signature_bytes).decode("utf-8"),
    }
