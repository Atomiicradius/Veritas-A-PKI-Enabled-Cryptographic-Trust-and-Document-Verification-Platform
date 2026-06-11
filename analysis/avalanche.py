import hashlib


def compute_avalanche(original_path: str, modified_path: str) -> dict:
    """Compare SHA-256 hashes of two files bit-by-bit and return heatmap data."""
    with open(original_path, "rb") as f:
        orig_data = f.read()
    with open(modified_path, "rb") as f:
        mod_data = f.read()

    orig_hash = hashlib.sha256(orig_data).digest()  # 32 bytes = 256 bits
    mod_hash = hashlib.sha256(mod_data).digest()

    orig_hex = orig_hash.hex()
    mod_hex = mod_hash.hex()

    xor_bytes = bytes(a ^ b for a, b in zip(orig_hash, mod_hash))

    cells = []
    flip_count = 0
    for byte_val in xor_bytes:
        for bit_pos in range(7, -1, -1):
            flipped = bool((byte_val >> bit_pos) & 1)
            cells.append(1 if flipped else 0)
            if flipped:
                flip_count += 1

    return {
        "original_hash": orig_hex,
        "modified_hash": mod_hex,
        "cells": cells,          # 256 values: 1=flipped, 0=unchanged
        "flip_count": flip_count,
        "flip_percent": round(flip_count / 256 * 100, 1),
    }


def compute_avalanche_from_bytes(orig_data: bytes, mod_data: bytes) -> dict:
    orig_hash = hashlib.sha256(orig_data).digest()
    mod_hash = hashlib.sha256(mod_data).digest()

    orig_hex = orig_hash.hex()
    mod_hex = mod_hash.hex()

    xor_bytes = bytes(a ^ b for a, b in zip(orig_hash, mod_hash))

    cells = []
    flip_count = 0
    for byte_val in xor_bytes:
        for bit_pos in range(7, -1, -1):
            flipped = bool((byte_val >> bit_pos) & 1)
            cells.append(1 if flipped else 0)
            if flipped:
                flip_count += 1

    return {
        "original_hash": orig_hex,
        "modified_hash": mod_hex,
        "cells": cells,
        "flip_count": flip_count,
        "flip_percent": round(flip_count / 256 * 100, 1),
    }
