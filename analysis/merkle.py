"""
Merkle Tree implementation for chunk-level document integrity verification.

Provides:
  - get_chunk_hashes()     – split a file into fixed-size chunks and hash each
  - build_merkle_tree()    – build the full tree from a list of leaf hashes
  - generate_root_hash()   – compute the Merkle root for a file
  - verify_merkle_tree()   – compare two files' Merkle trees for mismatch info
"""

import hashlib
import math
from typing import List, Optional

CHUNK_SIZE = 4096  # 4 KB chunks


# ── Internal helpers ──────────────────────────────────────────────────────────

def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _combine(left: str, right: str) -> str:
    """Hash two sibling nodes together to produce their parent."""
    return _sha256((left + right).encode("utf-8"))


# ── Public API ────────────────────────────────────────────────────────────────

def get_chunk_hashes(data: bytes, chunk_size: int = CHUNK_SIZE) -> List[str]:
    """
    Split *data* into fixed-size chunks and return the SHA-256 hex hash of each.

    If data is empty a single hash of b"" is returned so the tree is never
    degenerate.
    """
    if not data:
        return [_sha256(b"")]

    chunks = [data[i: i + chunk_size] for i in range(0, len(data), chunk_size)]
    return [_sha256(chunk) for chunk in chunks]


def build_merkle_tree(leaf_hashes: List[str]) -> List[List[str]]:
    """
    Build a Merkle tree from *leaf_hashes* and return the full tree as a
    list of levels (level 0 = leaves, last element = [root]).

    Odd-length levels are padded by duplicating the last leaf.
    """
    if not leaf_hashes:
        leaf_hashes = [_sha256(b"")]

    current_level = list(leaf_hashes)
    tree = [current_level]

    while len(current_level) > 1:
        # Pad odd-length level by duplicating last node
        if len(current_level) % 2 != 0:
            current_level = current_level + [current_level[-1]]

        next_level = [
            _combine(current_level[i], current_level[i + 1])
            for i in range(0, len(current_level), 2)
        ]
        tree.append(next_level)
        current_level = next_level

    return tree


def generate_root_hash(data: bytes, chunk_size: int = CHUNK_SIZE) -> dict:
    """
    Compute the Merkle root hash for *data*.

    Returns:
    {
        "merkle_root":  "<hex root hash>",
        "chunk_count":  <int>,
        "tree_depth":   <int>,
        "chunk_hashes": [<hex>, ...]   # leaf hashes
    }
    """
    leaves = get_chunk_hashes(data, chunk_size)
    tree   = build_merkle_tree(leaves)
    root   = tree[-1][0]
    depth  = len(tree) - 1  # 0 means single-leaf / already root

    return {
        "merkle_root":  root,
        "chunk_count":  len(leaves),
        "tree_depth":   depth,
        "chunk_hashes": leaves,
    }


def verify_merkle_tree(orig_data: bytes, mod_data: bytes,
                       chunk_size: int = CHUNK_SIZE) -> dict:
    """
    Compare the Merkle trees of two byte arrays.

    Returns:
    {
        "original_root":     str,
        "modified_root":     str,
        "roots_match":       bool,
        "original_chunks":   int,
        "modified_chunks":   int,
        "mismatched_chunks": [int, ...],  # 0-based indices
        "mismatch_count":    int,
    }
    """
    orig_info = generate_root_hash(orig_data, chunk_size)
    mod_info  = generate_root_hash(mod_data,  chunk_size)

    orig_leaves = orig_info["chunk_hashes"]
    mod_leaves  = mod_info["chunk_hashes"]

    max_len = max(len(orig_leaves), len(mod_leaves))
    mismatched = [
        i for i in range(max_len)
        if (orig_leaves[i] if i < len(orig_leaves) else None) !=
           (mod_leaves[i]  if i < len(mod_leaves)  else None)
    ]

    return {
        "original_root":     orig_info["merkle_root"],
        "modified_root":     mod_info["merkle_root"],
        "roots_match":       orig_info["merkle_root"] == mod_info["merkle_root"],
        "original_chunks":   orig_info["chunk_count"],
        "modified_chunks":   mod_info["chunk_count"],
        "mismatched_chunks": mismatched,
        "mismatch_count":    len(mismatched),
    }
