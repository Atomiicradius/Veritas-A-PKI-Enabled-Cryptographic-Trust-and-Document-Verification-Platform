"""
Performance benchmarks for the Veritas cryptographic platform.

Methodology:
  - File data is loaded into memory BEFORE timing begins, so only pure
    cryptographic computation is measured (no disk-I/O noise).
  - A single warm-up iteration is executed before the timed loop so that
    library initialisation / JIT effects do not distort the first sample.
  - 50 iterations are averaged to minimise measurement noise.
  - statistics.mean / stdev are used; min/max are also returned so the
    frontend can show "fastest" / "slowest" summary cards.
"""

import io
import time
import os
import tempfile
import statistics

from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives import hashes, serialization

from crypto.keygen import generate_keys
from crypto.hasher import compute_hash
from crypto.signer import sign_document
from crypto.verifier import verify_document


# ── Low-level helpers that accept bytes (no disk I/O inside timing) ───────────

def _hash_bytes(data: bytes) -> str:
    """SHA-256 hash of raw bytes (no file I/O)."""
    import hashlib
    return hashlib.sha256(data).hexdigest()


def _sign_bytes(data: bytes, private_key) -> bytes:
    """RSA-PSS sign of raw bytes."""
    h = hashes.SHA256()
    return private_key.sign(
        data,
        asym_padding.PSS(
            mgf=asym_padding.MGF1(h),
            salt_length=asym_padding.PSS.MAX_LENGTH,
        ),
        h,
    )


def _verify_bytes(data: bytes, signature: bytes, public_key) -> bool:
    """RSA-PSS verify of raw bytes."""
    from cryptography.exceptions import InvalidSignature
    h = hashes.SHA256()
    try:
        public_key.verify(
            signature,
            data,
            asym_padding.PSS(
                mgf=asym_padding.MGF1(h),
                salt_length=asym_padding.PSS.MAX_LENGTH,
            ),
            h,
        )
        return True
    except InvalidSignature:
        return False


def _make_random_bytes(size_kb: int) -> bytes:
    return os.urandom(size_kb * 1024)


# ── Public benchmark functions ────────────────────────────────────────────────

def benchmark_by_file_size(key_size: int = 2048, runs: int = 50) -> list:
    """
    Returns list of dicts with per-file-size timing statistics.

    Keys per entry:
      file_size_kb, hash_avg, hash_err, hash_min, hash_max,
                    sign_avg, sign_err, sign_min, sign_max,
                    verify_avg, verify_err, verify_min, verify_max
    """
    priv, pub = generate_keys(key_size)
    results = []

    for size_kb in [1, 10, 50, 100, 500, 1024]:
        # Pre-generate data in memory — kept constant across all runs for
        # this file size so that variance reflects only crypto, not random().
        data = _make_random_bytes(size_kb)

        hash_times, sign_times, verify_times = [], [], []

        # ── Warm-up run (results discarded) ──────────────────────────────────
        _hash_bytes(data)
        sig_warmup = _sign_bytes(data, priv)
        _verify_bytes(data, sig_warmup, pub)

        # ── Timed runs ────────────────────────────────────────────────────────
        for _ in range(runs):
            t0 = time.perf_counter()
            _hash_bytes(data)
            hash_times.append((time.perf_counter() - t0) * 1000)

            t0 = time.perf_counter()
            sig = _sign_bytes(data, priv)
            sign_times.append((time.perf_counter() - t0) * 1000)

            t0 = time.perf_counter()
            _verify_bytes(data, sig, pub)
            verify_times.append((time.perf_counter() - t0) * 1000)

        def _stats(times):
            return {
                "avg": round(statistics.mean(times), 3),
                "err": round(statistics.stdev(times) if len(times) > 1 else 0, 3),
                "min": round(min(times), 3),
                "max": round(max(times), 3),
            }

        hs = _stats(hash_times)
        ss = _stats(sign_times)
        vs = _stats(verify_times)

        results.append({
            "file_size_kb": size_kb,
            "hash_avg":    hs["avg"], "hash_err":    hs["err"],
            "hash_min":    hs["min"], "hash_max":    hs["max"],
            "sign_avg":    ss["avg"], "sign_err":    ss["err"],
            "sign_min":    ss["min"], "sign_max":    ss["max"],
            "verify_avg":  vs["avg"], "verify_err":  vs["err"],
            "verify_min":  vs["min"], "verify_max":  vs["max"],
        })

    return results


def benchmark_by_key_size(runs: int = 50) -> list:
    """
    Returns list of dicts with per-key-size signing/verification timing.

    Keys per entry:
      key_size, sign_avg, sign_err, sign_min, sign_max,
                verify_avg, verify_err, verify_min, verify_max
    """
    # Fixed 10 KB payload in memory — same data for both key sizes.
    data = _make_random_bytes(10)
    results = []

    for key_size in [1024, 2048]:
        priv, pub = generate_keys(key_size)
        sign_times, verify_times = [], []

        # ── Warm-up run ───────────────────────────────────────────────────────
        sig_warmup = _sign_bytes(data, priv)
        _verify_bytes(data, sig_warmup, pub)

        # ── Timed runs ────────────────────────────────────────────────────────
        for _ in range(runs):
            t0 = time.perf_counter()
            sig = _sign_bytes(data, priv)
            sign_times.append((time.perf_counter() - t0) * 1000)

            t0 = time.perf_counter()
            _verify_bytes(data, sig, pub)
            verify_times.append((time.perf_counter() - t0) * 1000)

        def _stats(times):
            return {
                "avg": round(statistics.mean(times), 3),
                "err": round(statistics.stdev(times) if len(times) > 1 else 0, 3),
                "min": round(min(times), 3),
                "max": round(max(times), 3),
            }

        ss = _stats(sign_times)
        vs = _stats(verify_times)

        results.append({
            "key_size":   key_size,
            "sign_avg":   ss["avg"], "sign_err":   ss["err"],
            "sign_min":   ss["min"], "sign_max":   ss["max"],
            "verify_avg": vs["avg"], "verify_err": vs["err"],
            "verify_min": vs["min"], "verify_max": vs["max"],
        })

    return results
