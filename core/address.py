"""Bitcoin address encoding: Base58Check, Bech32, Bech32m.

Pure Python implementations — no external dependencies.
"""

import hashlib


# =============================================================================
# Base58Check encoding (P2PKH, P2SH)
# =============================================================================

BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _hash256(data: bytes) -> bytes:
    return _sha256(_sha256(data))


def _hash160(data: bytes) -> bytes:
    return hashlib.new("ripemd160", _sha256(data)).digest()


def base58_encode(payload: bytes) -> str:
    """Encode bytes to Base58."""
    n = int.from_bytes(payload, "big")
    result = []
    while n > 0:
        n, r = divmod(n, 58)
        result.append(BASE58_ALPHABET[r])

    # Leading zero bytes → leading '1's
    for byte in payload:
        if byte == 0:
            result.append("1")
        else:
            break

    return "".join(reversed(result))


def base58check_encode(version: int, payload: bytes) -> str:
    """Encode with version byte and 4-byte checksum."""
    data = bytes([version]) + payload
    checksum = _hash256(data)[:4]
    return base58_encode(data + checksum)


def p2pkh_address(pubkey_hash: bytes) -> str:
    """P2PKH address (version 0x00)."""
    return base58check_encode(0x00, pubkey_hash)


def p2sh_address(script_hash: bytes) -> str:
    """P2SH address (version 0x05)."""
    return base58check_encode(0x05, script_hash)


# =============================================================================
# Bech32 / Bech32m encoding (P2WPKH, P2WSH, P2TR)
# =============================================================================

BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

BECH32_CONST = 1   # Bech32
BECH32M_CONST = 0x2BC830A3  # Bech32m


def _bech32_polymod(values):
    """Internal function that computes the Bech32 checksum."""
    GEN = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for v in values:
        b = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ v
        for i in range(5):
            chk ^= GEN[i] if ((b >> i) & 1) else 0
    return chk


def _bech32_hrp_expand(hrp):
    """Expand the HRP into values for checksum computation."""
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def _bech32_create_checksum(hrp, data, spec):
    """Compute the checksum values given HRP and data."""
    values = _bech32_hrp_expand(hrp) + data
    polymod = _bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ spec
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]


def _convertbits(data, frombits, tobits, pad=True):
    """General power-of-2 base conversion."""
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    for value in data:
        if value < 0 or (value >> frombits):
            return None
        acc = (acc << frombits) | value
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        return None
    return ret


def bech32_encode(hrp, witver, witprog, spec=None):
    """Encode a SegWit address."""
    if spec is None:
        spec = BECH32M_CONST if witver > 0 else BECH32_CONST
    data = _convertbits(witprog, 8, 5)
    if data is None:
        return None
    combined = [witver] + data
    checksum = _bech32_create_checksum(hrp, combined, spec)
    return hrp + "1" + "".join(BECH32_CHARSET[d] for d in combined + checksum)


def p2wpkh_address(witness_program: bytes) -> str:
    """P2WPKH address (Bech32, witness version 0)."""
    return bech32_encode("bc", 0, list(witness_program), BECH32_CONST)


def p2wsh_address(witness_program: bytes) -> str:
    """P2WSH address (Bech32, witness version 0)."""
    return bech32_encode("bc", 0, list(witness_program), BECH32_CONST)


def p2tr_address(witness_program: bytes) -> str:
    """P2TR address (Bech32m, witness version 1)."""
    return bech32_encode("bc", 1, list(witness_program), BECH32M_CONST)


def address_from_script(script_type: str, script_hex: str) -> str | None:
    """Derive address from script type and scriptPubKey hex."""
    try:
        script = bytes.fromhex(script_hex)
    except ValueError:
        return None

    if script_type == "p2pkh" and len(script) == 25:
        # OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
        return p2pkh_address(script[3:23])

    elif script_type == "p2sh" and len(script) == 23:
        # OP_HASH160 <20 bytes> OP_EQUAL
        return p2sh_address(script[2:22])

    elif script_type == "p2wpkh" and len(script) == 22:
        # OP_0 <20 bytes>
        return p2wpkh_address(script[2:])

    elif script_type == "p2wsh" and len(script) == 34:
        # OP_0 <32 bytes>
        return p2wsh_address(script[2:])

    elif script_type == "p2tr" and len(script) == 34:
        # OP_1 <32 bytes>
        return p2tr_address(script[2:])

    return None
