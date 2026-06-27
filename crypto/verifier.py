import base64
import fitz  # PyMuPDF to handle stamped PDF verification
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature


def _get_hash_algo(algorithm_label: str):
    label = algorithm_label.upper()
    if "SHA512" in label:
        return hashes.SHA512()
    return hashes.SHA256()


def verify_document(file_path: str, sig_dict: dict, public_key) -> bool:
    data = None
    if file_path.lower().endswith(".pdf"):
        try:
            doc = fitz.open(file_path)
            if len(doc) > 1:
                last_page = doc[-1]
                text = last_page.get_text()
                if "Veritas Mobile App" in text or "verify cryptographic authenticity" in text:
                    doc.delete_page(len(doc) - 1)
                    data = doc.tobytes()
            doc.close()
        except Exception:
            pass

    if data is None:
        with open(file_path, "rb") as f:
            data = f.read()

    signature_bytes = base64.b64decode(sig_dict["signature"])
    h = _get_hash_algo(sig_dict.get("algorithm", "RSA-PSS-SHA256"))

    try:
        public_key.verify(
            signature_bytes,
            data,
            padding.PSS(
                mgf=padding.MGF1(h),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            h,
        )
        return True
    except InvalidSignature:
        return False
