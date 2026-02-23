"""Script classifier for Bitcoin inputs and outputs."""


def classify_output(script_hex: str) -> str:
    """Classify an output scriptPubKey into a script type.

    Returns one of: p2pkh, p2sh, p2wpkh, p2wsh, p2tr, op_return, unknown
    """
    try:
        script = bytes.fromhex(script_hex)
    except ValueError:
        return "unknown"

    n = len(script)

    # P2PKH: OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
    # 76 a9 14 <20> 88 ac
    if n == 25 and script[0] == 0x76 and script[1] == 0xa9 and script[2] == 0x14 \
            and script[23] == 0x88 and script[24] == 0xac:
        return "p2pkh"

    # P2SH: OP_HASH160 <20 bytes> OP_EQUAL
    # a9 14 <20> 87
    if n == 23 and script[0] == 0xa9 and script[1] == 0x14 and script[22] == 0x87:
        return "p2sh"

    # P2WPKH: OP_0 <20 bytes>
    # 00 14 <20>
    if n == 22 and script[0] == 0x00 and script[1] == 0x14:
        return "p2wpkh"

    # P2WSH: OP_0 <32 bytes>
    # 00 20 <32>
    if n == 34 and script[0] == 0x00 and script[1] == 0x20:
        return "p2wsh"

    # P2TR: OP_1 <32 bytes>
    # 51 20 <32>
    if n == 34 and script[0] == 0x51 and script[1] == 0x20:
        return "p2tr"

    # OP_RETURN: starts with 0x6a
    if n >= 1 and script[0] == 0x6a:
        return "op_return"

    return "unknown"


def classify_input(script_sig_hex: str, witness: list, prevout_script_hex: str) -> str:
    """Classify an input's spend type.

    Uses the combination of scriptSig, witness stack, and prevout scriptPubKey.

    Returns one of: p2pkh, p2sh-p2wpkh, p2sh-p2wsh, p2wpkh, p2wsh,
                     p2tr_keypath, p2tr_scriptpath, unknown
    """
    prevout_type = classify_output(prevout_script_hex)
    has_witness = len(witness) > 0 and any(len(w) > 0 for w in witness)

    try:
        script_sig = bytes.fromhex(script_sig_hex)
    except ValueError:
        script_sig = b""

    # Native SegWit types (empty scriptSig, identified by prevout)
    if prevout_type == "p2wpkh" and len(script_sig) == 0 and has_witness:
        return "p2wpkh"

    if prevout_type == "p2wsh" and len(script_sig) == 0 and has_witness:
        return "p2wsh"

    if prevout_type == "p2tr" and len(script_sig) == 0:
        # Taproot: keypath = exactly 1 witness item (64 or 65 bytes schnorr sig)
        # scriptpath = witness has script + control block (control block starts with 0xc0 or 0xc1)
        if len(witness) == 1:
            # Key path spend: single signature
            return "p2tr_keypath"
        elif len(witness) >= 2:
            # Script path spend: last item is control block starting with 0xc0 or 0xc1
            try:
                last_item = bytes.fromhex(witness[-1])
                if len(last_item) >= 33 and (last_item[0] & 0xFE) == 0xC0:
                    return "p2tr_scriptpath"
            except ValueError:
                pass
            return "p2tr_keypath"
        return "p2tr_keypath"

    # P2PKH (legacy, no witness)
    if prevout_type == "p2pkh":
        return "p2pkh"

    # P2SH types
    if prevout_type == "p2sh":
        # Check if scriptSig wraps a witness program (nested SegWit)
        if len(script_sig) > 0 and has_witness:
            # P2SH-P2WPKH: scriptSig = push of 0x0014{20-byte-hash}
            # The redeem script is the witness program
            redeem_script = _extract_p2sh_redeem_script(script_sig)
            if redeem_script is not None:
                if len(redeem_script) == 22 and redeem_script[0] == 0x00 and redeem_script[1] == 0x14:
                    return "p2sh-p2wpkh"
                if len(redeem_script) == 34 and redeem_script[0] == 0x00 and redeem_script[1] == 0x20:
                    return "p2sh-p2wsh"
        return "unknown"

    return "unknown"


def _extract_p2sh_redeem_script(script_sig: bytes) -> bytes | None:
    """Extract the last push from a scriptSig (the redeemScript for P2SH).

    In P2SH, the redeemScript is the final push in the scriptSig.
    """
    i = 0
    n = len(script_sig)
    last_push = None

    while i < n:
        op = script_sig[i]
        i += 1

        if 0x01 <= op <= 0x4b:
            last_push = script_sig[i : i + op]
            i += op
        elif op == 0x4c:  # OP_PUSHDATA1
            if i >= n:
                break
            length = script_sig[i]
            i += 1
            last_push = script_sig[i : i + length]
            i += length
        elif op == 0x4d:  # OP_PUSHDATA2
            if i + 2 > n:
                break
            import struct
            length = struct.unpack_from("<H", script_sig, i)[0]
            i += 2
            last_push = script_sig[i : i + length]
            i += length
        elif op == 0x4e:  # OP_PUSHDATA4
            if i + 4 > n:
                break
            import struct
            length = struct.unpack_from("<I", script_sig, i)[0]
            i += 4
            last_push = script_sig[i : i + length]
            i += length
        elif op == 0x00:
            last_push = b""
        else:
            # Regular opcode — not a push, just skip
            last_push = None

    return last_push


def get_op_return_info(script_hex: str) -> dict:
    """Extract OP_RETURN data and detect protocol.

    Returns dict with:
        op_return_data_hex: str
        op_return_data_utf8: str | None
        op_return_protocol: str
    """
    from core.script import parse_op_return_data

    raw_data = parse_op_return_data(script_hex)
    data_hex = raw_data.hex()

    # UTF-8 decoding
    try:
        data_utf8 = raw_data.decode("utf-8")
    except (UnicodeDecodeError, ValueError):
        data_utf8 = None

    # Protocol detection
    if data_hex.startswith("6f6d6e69"):
        protocol = "omni"
    elif data_hex.startswith("0109f91102"):
        protocol = "opentimestamps"
    else:
        protocol = "unknown"

    return {
        "op_return_data_hex": data_hex,
        "op_return_data_utf8": data_utf8,
        "op_return_protocol": protocol,
    }
