"""Merkle root computation for Bitcoin blocks."""

import hashlib


def _sha256d(data: bytes) -> bytes:
    """Double SHA-256 hash."""
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def compute_merkle_root(txid_list: list[str]) -> str:
    """Compute the Merkle root from a list of txids (hex strings in display order).

    Returns the merkle root in display (reversed) hex format.

    Bitcoin Merkle tree rules:
    - If odd number of hashes, duplicate the last one
    - Hashes are concatenated in internal byte order (reversed from display)
    - Each pair is double-SHA256 hashed
    """
    if not txid_list:
        return "0" * 64

    # Convert display txids to internal byte order
    hashes = [bytes.fromhex(txid)[::-1] for txid in txid_list]

    while len(hashes) > 1:
        if len(hashes) % 2 == 1:
            hashes.append(hashes[-1])  # duplicate last if odd

        new_hashes = []
        for i in range(0, len(hashes), 2):
            combined = hashes[i] + hashes[i + 1]
            new_hashes.append(_sha256d(combined))
        hashes = new_hashes

    # Return in display order (reversed)
    return hashes[0][::-1].hex()
