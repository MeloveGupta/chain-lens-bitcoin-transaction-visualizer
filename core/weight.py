"""BIP141 weight and vbytes calculation."""

import math


def compute_weight(non_witness_bytes: int, witness_bytes: int) -> int:
    """Compute transaction weight per BIP141.

    weight = non_witness_bytes * 4 + witness_bytes * 1
    """
    return non_witness_bytes * 4 + witness_bytes * 1


def compute_vbytes(weight: int) -> int:
    """Compute virtual bytes: ceil(weight / 4)."""
    return math.ceil(weight / 4)


def compute_segwit_savings(non_witness_bytes: int, witness_bytes: int, total_bytes: int) -> dict | None:
    """Compute segwit savings analysis.

    Returns None for non-segwit transactions (witness_bytes == 0).
    """
    if witness_bytes == 0:
        return None

    weight_actual = compute_weight(non_witness_bytes, witness_bytes)
    weight_if_legacy = total_bytes * 4
    savings_pct = round((1 - weight_actual / weight_if_legacy) * 100, 2)

    return {
        "witness_bytes": witness_bytes,
        "non_witness_bytes": non_witness_bytes,
        "total_bytes": total_bytes,
        "weight_actual": weight_actual,
        "weight_if_legacy": weight_if_legacy,
        "savings_pct": savings_pct,
    }
