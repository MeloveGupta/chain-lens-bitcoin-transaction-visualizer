"""Main transaction analyzer — builds the full JSON report from a fixture."""

import json
import math

from core.tx_parser import parse_transaction
from core.script import disassemble
from core.script_classifier import classify_output, classify_input, get_op_return_info
from core.address import address_from_script
from core.weight import compute_vbytes, compute_segwit_savings
from core.warnings import detect_warnings
from core.errors import InvalidFixtureError, InvalidTxError


def analyze_transaction(fixture: dict) -> dict:
    """Analyze a transaction from fixture JSON and return the full report dict."""

    network = fixture.get("network", "mainnet")
    raw_tx = fixture.get("raw_tx")
    prevouts_list = fixture.get("prevouts", [])

    if not raw_tx:
        raise InvalidFixtureError("Missing 'raw_tx' field in fixture")
    if not isinstance(prevouts_list, list):
        raise InvalidFixtureError("'prevouts' must be an array")

    # Parse the raw transaction
    tx = parse_transaction(raw_tx)

    # Build prevout lookup: (txid, vout) -> prevout
    prevout_map = {}
    for p in prevouts_list:
        key = (p["txid"], p["vout"])
        if key in prevout_map:
            raise InvalidFixtureError(f"Duplicate prevout: {key}")
        prevout_map[key] = p

    # Match prevouts to inputs
    for inp in tx.inputs:
        key = (inp["txid"], inp["vout"])
        if key not in prevout_map:
            raise InvalidFixtureError(f"Missing prevout for input: txid={inp['txid']}, vout={inp['vout']}")

    if len(prevout_map) != len(tx.inputs):
        raise InvalidFixtureError(
            f"Prevout count ({len(prevout_map)}) does not match input count ({len(tx.inputs)})"
        )

    # Compute txid and wtxid
    txid = tx.compute_txid()
    wtxid = tx.compute_wtxid()

    # Compute size, weight, vbytes
    size_bytes = tx.get_size_bytes()
    non_witness_bytes = tx.get_non_witness_bytes()
    witness_bytes = tx.get_witness_bytes()
    weight = non_witness_bytes * 4 + witness_bytes
    vbytes = compute_vbytes(weight)

    # Compute fees
    total_input_sats = sum(prevout_map[(inp["txid"], inp["vout"])]["value_sats"] for inp in tx.inputs)
    total_output_sats = sum(out["value_sats"] for out in tx.outputs)
    fee_sats = total_input_sats - total_output_sats

    if fee_sats < 0:
        raise InvalidTxError(f"Negative fee: inputs={total_input_sats}, outputs={total_output_sats}")

    fee_rate = fee_sats / vbytes if vbytes > 0 else 0
    fee_rate_rounded = round(fee_rate, 2)

    # RBF detection (BIP125)
    rbf_signaling = any(inp["sequence"] < 0xFFFFFFFE for inp in tx.inputs)

    # Locktime analysis
    locktime_value = tx.locktime
    if locktime_value == 0:
        locktime_type = "none"
    elif locktime_value < 500_000_000:
        locktime_type = "block_height"
    else:
        locktime_type = "unix_timestamp"

    # SegWit savings
    segwit_savings = compute_segwit_savings(non_witness_bytes, witness_bytes, size_bytes)

    # Build vin array
    vin = []
    for inp in tx.inputs:
        prevout = prevout_map[(inp["txid"], inp["vout"])]
        script_sig_hex = inp["script_sig_hex"]

        # Classify input
        input_type = classify_input(script_sig_hex, inp["witness"], prevout["script_pubkey_hex"])

        # Address from prevout scriptPubKey
        prevout_script_type = classify_output(prevout["script_pubkey_hex"])
        address = address_from_script(prevout_script_type, prevout["script_pubkey_hex"])

        # Relative timelock (BIP68)
        relative_timelock = _parse_relative_timelock(inp["sequence"])

        vin_entry = {
            "txid": inp["txid"],
            "vout": inp["vout"],
            "sequence": inp["sequence"],
            "script_sig_hex": script_sig_hex,
            "script_asm": disassemble(script_sig_hex),
            "witness": inp["witness"],
            "script_type": input_type,
            "address": address,
            "prevout": {
                "value_sats": prevout["value_sats"],
                "script_pubkey_hex": prevout["script_pubkey_hex"],
            },
            "relative_timelock": relative_timelock,
        }

        # For p2wsh and p2sh-p2wsh: add witness_script_asm
        if input_type in ("p2wsh", "p2sh-p2wsh") and len(inp["witness"]) > 0:
            witness_script_hex = inp["witness"][-1]
            vin_entry["witness_script_asm"] = disassemble(witness_script_hex)

        vin.append(vin_entry)

    # Build vout array
    vout = []
    for out in tx.outputs:
        script_type = classify_output(out["script_pubkey_hex"])
        address = address_from_script(script_type, out["script_pubkey_hex"])

        vout_entry = {
            "n": out["n"],
            "value_sats": out["value_sats"],
            "script_pubkey_hex": out["script_pubkey_hex"],
            "script_asm": disassemble(out["script_pubkey_hex"]),
            "script_type": script_type,
            "address": address,
        }

        # OP_RETURN extra fields
        if script_type == "op_return":
            op_return_info = get_op_return_info(out["script_pubkey_hex"])
            vout_entry["op_return_data_hex"] = op_return_info["op_return_data_hex"]
            vout_entry["op_return_data_utf8"] = op_return_info["op_return_data_utf8"]
            vout_entry["op_return_protocol"] = op_return_info["op_return_protocol"]

        vout.append(vout_entry)

    # Detect warnings
    warnings = detect_warnings(fee_sats, fee_rate, vout, rbf_signaling)

    # Build result
    result = {
        "ok": True,
        "network": network,
        "segwit": tx.is_segwit,
        "txid": txid,
        "wtxid": wtxid,
        "version": tx.version,
        "locktime": locktime_value,
        "size_bytes": size_bytes,
        "weight": weight,
        "vbytes": vbytes,
        "total_input_sats": total_input_sats,
        "total_output_sats": total_output_sats,
        "fee_sats": fee_sats,
        "fee_rate_sat_vb": fee_rate_rounded,
        "rbf_signaling": rbf_signaling,
        "locktime_type": locktime_type,
        "locktime_value": locktime_value,
        "segwit_savings": segwit_savings,
        "vin": vin,
        "vout": vout,
        "warnings": warnings,
    }

    return result


def _parse_relative_timelock(sequence: int) -> dict:
    """Parse BIP68 relative timelock from input sequence number."""
    # Bit 31 (0x80000000): if set, relative locktime is disabled
    if sequence & 0x80000000:
        return {"enabled": False}

    # Bit 22 (0x00400000): if set, time-based; otherwise block-based
    if sequence & 0x00400000:
        # Time-based: lower 16 bits * 512 seconds
        value = (sequence & 0xFFFF) * 512
        return {"enabled": True, "type": "time", "value": value}
    else:
        # Block-based: lower 16 bits
        value = sequence & 0xFFFF
        return {"enabled": True, "type": "blocks", "value": value}


def analyze_transaction_from_fixture_file(filepath: str) -> dict:
    """Read a fixture JSON file and return the analysis result."""
    with open(filepath, "r") as f:
        fixture = json.load(f)
    return analyze_transaction(fixture)
