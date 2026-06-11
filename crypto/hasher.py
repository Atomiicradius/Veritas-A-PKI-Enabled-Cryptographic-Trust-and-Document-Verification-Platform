import hashlib


def compute_hash(file_path: str, algorithm: str = "sha256") -> str:
    algo = algorithm.lower().replace("-", "")
    h = hashlib.new(algo)
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def compute_hash_bytes(data: bytes, algorithm: str = "sha256") -> bytes:
    algo = algorithm.lower().replace("-", "")
    h = hashlib.new(algo)
    h.update(data)
    return h.digest()
