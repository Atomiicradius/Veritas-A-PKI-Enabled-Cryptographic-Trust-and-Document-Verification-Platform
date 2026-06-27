"""Attack simulation data — illustrative estimates only."""

import hmac
import time

# NIST security levels and illustrative factoring estimates
SECURITY_LEVELS = [
    {
        "key_size": 512,
        "security_bits": 56,
        "status": "BROKEN",
        "factoring_time": "< 1 hour (modern hardware)",
        "nist_status": "Deprecated (factored in practice)",
        "color": "danger",
    },
    {
        "key_size": 1024,
        "security_bits": 80,
        "status": "WEAK",
        "factoring_time": "~10^9 MIPS-years (theoretically feasible)",
        "nist_status": "Deprecated since 2013",
        "color": "warning",
    },
    {
        "key_size": 2048,
        "security_bits": 112,
        "status": "SECURE",
        "factoring_time": "~10^22 MIPS-years (computationally infeasible)",
        "nist_status": "Recommended through 2030",
        "color": "success",
    },
    {
        "key_size": 4096,
        "security_bits": 140,
        "status": "VERY SECURE",
        "factoring_time": "~10^33 MIPS-years (far beyond feasible)",
        "nist_status": "Recommended beyond 2030",
        "color": "primary",
    },
]


def get_security_levels() -> list:
    return SECURITY_LEVELS


def tamper_file(file_path: str) -> dict:
    """Flip one byte at a random position. Returns tamper details."""
    import random
    import os

    with open(file_path, "rb") as f:
        data = bytearray(f.read())

    if not data:
        return {"error": "File is empty"}

    pos = random.randint(0, len(data) - 1)
    original_byte = data[pos]
    new_byte = (original_byte + 1) % 256
    data[pos] = new_byte

    with open(file_path, "wb") as f:
        f.write(data)

    return {
        "position": pos,
        "original_hex": format(original_byte, "02X"),
        "new_hex": format(new_byte, "02X"),
        "file_size": len(data),
    }


def naive_signature_verify(calculated_sig: bytes, provided_sig: bytes) -> tuple:
    """Byte-by-byte comparison — VULNERABLE to timing side-channels.

    Returns early on the first mismatched byte, leaking how many bytes
    matched via measurable latency differences.
    Each matched byte incurs an artificial 2 ms sleep to magnify the delta.
    """
    t0 = time.perf_counter()
    result = True
    for a, b in zip(calculated_sig, provided_sig):
        if a != b:
            result = False
            break
        time.sleep(0.002)          # 2 ms per matched byte — detectable timing leak

    if len(calculated_sig) != len(provided_sig):
        result = False

    elapsed_ms = (time.perf_counter() - t0) * 1000
    return result, round(elapsed_ms, 3)


def secure_signature_verify(calculated_sig: bytes, provided_sig: bytes) -> tuple:
    """Constant-time comparison — SECURE against timing side-channels.

    Uses hmac.compare_digest() which always inspects every byte so the
    execution time is independent of how many bytes match.
    A uniform 10 ms sleep is added as a consistent performance baseline.
    """
    t0 = time.perf_counter()
    time.sleep(0.010)              # 10 ms uniform baseline — no per-byte leak
    result = hmac.compare_digest(calculated_sig, provided_sig)
    elapsed_ms = (time.perf_counter() - t0) * 1000
    return result, round(elapsed_ms, 3)
