"""Warning detection for Bitcoin transactions."""


def detect_warnings(fee_sats: int, fee_rate: float, outputs: list, rbf: bool) -> list:
    """Detect warning conditions and return list of warning dicts.

    Warning codes:
    - HIGH_FEE: fee_sats > 1,000,000 OR fee_rate > 200
    - DUST_OUTPUT: non-op_return output with value_sats < 546
    - UNKNOWN_OUTPUT_SCRIPT: any output has script_type == 'unknown'
    - RBF_SIGNALING: if rbf_signaling is true
    """
    warnings = []

    # HIGH_FEE
    if fee_sats > 1_000_000 or fee_rate > 200:
        warnings.append({"code": "HIGH_FEE"})

    # DUST_OUTPUT
    for out in outputs:
        if out.get("script_type") != "op_return" and out.get("value_sats", 0) < 546:
            warnings.append({"code": "DUST_OUTPUT"})
            break  # Only add once

    # UNKNOWN_OUTPUT_SCRIPT
    for out in outputs:
        if out.get("script_type") == "unknown":
            warnings.append({"code": "UNKNOWN_OUTPUT_SCRIPT"})
            break  # Only add once

    # RBF_SIGNALING
    if rbf:
        warnings.append({"code": "RBF_SIGNALING"})

    return warnings
