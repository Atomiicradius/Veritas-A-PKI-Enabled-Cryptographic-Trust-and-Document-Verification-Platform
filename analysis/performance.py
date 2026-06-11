import time
import os
import tempfile
import statistics

from crypto.keygen import generate_keys
from crypto.hasher import compute_hash
from crypto.signer import sign_document
from crypto.verifier import verify_document


def _make_temp_file(size_kb: int) -> str:
    f = tempfile.NamedTemporaryFile(delete=False, suffix=".bin")
    f.write(os.urandom(size_kb * 1024))
    f.close()
    return f.name


def benchmark_by_file_size(key_size: int = 2048, runs: int = 5) -> list:
    """Returns list of dicts with file_size_kb, hash_ms, sign_ms, verify_ms (avg + stdev)."""
    priv, pub = generate_keys(key_size)
    results = []

    for size_kb in [1, 10, 50, 100, 500, 1024]:
        hash_times, sign_times, verify_times = [], [], []

        for _ in range(runs):
            path = _make_temp_file(size_kb)
            try:
                t0 = time.perf_counter()
                compute_hash(path, "sha256")
                hash_times.append((time.perf_counter() - t0) * 1000)

                t0 = time.perf_counter()
                sig = sign_document(path, priv, "UserA", "SHA-256")
                sign_times.append((time.perf_counter() - t0) * 1000)

                t0 = time.perf_counter()
                verify_document(path, sig, pub)
                verify_times.append((time.perf_counter() - t0) * 1000)
            finally:
                os.unlink(path)

        results.append({
            "file_size_kb": size_kb,
            "hash_avg": round(statistics.mean(hash_times), 3),
            "hash_err": round(statistics.stdev(hash_times) if len(hash_times) > 1 else 0, 3),
            "sign_avg": round(statistics.mean(sign_times), 3),
            "sign_err": round(statistics.stdev(sign_times) if len(sign_times) > 1 else 0, 3),
            "verify_avg": round(statistics.mean(verify_times), 3),
            "verify_err": round(statistics.stdev(verify_times) if len(verify_times) > 1 else 0, 3),
        })

    return results


def benchmark_by_key_size(runs: int = 5) -> list:
    """Returns list of dicts with key_size, sign_ms, verify_ms (avg + stdev)."""
    results = []
    path = _make_temp_file(10)

    try:
        for key_size in [1024, 2048]:
            priv, pub = generate_keys(key_size)
            sign_times, verify_times = [], []

            for _ in range(runs):
                t0 = time.perf_counter()
                sig = sign_document(path, priv, "UserA", "SHA-256")
                sign_times.append((time.perf_counter() - t0) * 1000)

                t0 = time.perf_counter()
                verify_document(path, sig, pub)
                verify_times.append((time.perf_counter() - t0) * 1000)

            results.append({
                "key_size": key_size,
                "sign_avg": round(statistics.mean(sign_times), 3),
                "sign_err": round(statistics.stdev(sign_times) if len(sign_times) > 1 else 0, 3),
                "verify_avg": round(statistics.mean(verify_times), 3),
                "verify_err": round(statistics.stdev(verify_times) if len(verify_times) > 1 else 0, 3),
            })
    finally:
        os.unlink(path)

    return results
