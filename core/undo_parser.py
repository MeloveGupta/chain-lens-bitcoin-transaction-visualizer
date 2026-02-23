"""Bitcoin Core undo data (rev*.dat) parser.

Handles:
- Bitcoin Core's varint format for undo records
- Amount decompression
- Script decompression (nSize 0-5, >=6)
"""

import struct


def read_compact_size(data: bytes, pos: int) -> tuple[int, int]:
    """Read a Bitcoin CompactSize uint (standard transaction-style varint)."""
    if pos >= len(data):
        from core.errors import UndoDataError
        raise UndoDataError(f"Unexpected end of data at pos {pos}")
    first = data[pos]
    pos += 1
    if first < 0xFD:
        return first, pos
    elif first == 0xFD:
        val = struct.unpack_from("<H", data, pos)[0]
        return val, pos + 2
    elif first == 0xFE:
        val = struct.unpack_from("<I", data, pos)[0]
        return val, pos + 4
    else:
        val = struct.unpack_from("<Q", data, pos)[0]
        return val, pos + 8


def decompress_amount(x: int) -> int:
    """Decompress a Bitcoin Core compressed amount.

    Bitcoin Core uses a special compression for amounts in undo data.
    See: Bitcoin Core src/compressor.cpp DecompressAmount()
    """
    if x == 0:
        return 0
    x -= 1
    e = x % 10
    x //= 10
    if e < 9:
        d = x % 9 + 1
        x //= 9
        n = x * 10 + d
    else:
        n = x + 1
    while e > 0:
        n *= 10
        e -= 1
    return n


def read_varint_core(data: bytes, pos: int) -> tuple[int, int]:
    """Read a Bitcoin Core-style varint (not the same as transaction varint!).

    Bitcoin Core uses a variable-length encoding where:
    - Each byte contributes 7 bits
    - If highest bit is set, more bytes follow
    - Each continuation adds (value + 1) * 128
    """
    n = 0
    while True:
        if pos >= len(data):
            from core.errors import UndoDataError
            raise UndoDataError(f"Unexpected end of undo data at pos {pos}")
        ch = data[pos]
        pos += 1
        n = (n << 7) | (ch & 0x7F)
        if ch & 0x80:
            n += 1
        else:
            break
    return n, pos


def decompress_script(data: bytes, pos: int) -> tuple[str, int]:
    """Read and decompress a script from undo data.

    Returns (script_pubkey_hex, new_pos).

    nSize values:
    0 = P2PKH (20 bytes hash follows → build full P2PKH script)
    1 = P2SH (20 bytes hash follows → build full P2SH script)
    2,3 = compressed public key (even/odd) → build P2PK script
    4,5 = uncompressed-from-compressed pubkey (even/odd) → build P2PK script
    >=6 = raw script of length (nSize - 6)
    """
    nSize, pos = read_varint_core(data, pos)

    if nSize == 0:
        # P2PKH: next 20 bytes = pubkey hash
        if pos + 20 > len(data):
            from core.errors import UndoDataError
            raise UndoDataError(f"Truncated P2PKH script data at pos {pos}")
        pubkey_hash = data[pos:pos + 20]
        pos += 20
        # Build: OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG
        script = b"\x76\xa9\x14" + pubkey_hash + b"\x88\xac"
        return script.hex(), pos

    elif nSize == 1:
        # P2SH: next 20 bytes = script hash
        if pos + 20 > len(data):
            from core.errors import UndoDataError
            raise UndoDataError(f"Truncated P2SH script data at pos {pos}")
        script_hash = data[pos:pos + 20]
        pos += 20
        # Build: OP_HASH160 <20> OP_EQUAL
        script = b"\xa9\x14" + script_hash + b"\x87"
        return script.hex(), pos

    elif nSize in (2, 3):
        # Compressed public key: next 32 bytes = x-coordinate
        # nSize 2 = even (02), nSize 3 = odd (03)
        if pos + 32 > len(data):
            from core.errors import UndoDataError
            raise UndoDataError(f"Truncated compressed pubkey data at pos {pos}")
        x_coord = data[pos:pos + 32]
        pos += 32
        prefix = bytes([nSize])
        pubkey = prefix + x_coord  # 33-byte compressed pubkey
        # Build P2PK: <33 pubkey> OP_CHECKSIG
        script = bytes([33]) + pubkey + b"\xac"
        return script.hex(), pos

    elif nSize in (4, 5):
        # Uncompressed pubkey stored as compressed: next 32 bytes = x-coordinate
        # nSize 4 = even (04→02), nSize 5 = odd (04→03)
        if pos + 32 > len(data):
            from core.errors import UndoDataError
            raise UndoDataError(f"Truncated uncompressed pubkey data at pos {pos}")
        x_coord = data[pos:pos + 32]
        pos += 32
        # Decompress to 65-byte uncompressed pubkey
        pubkey = _decompress_pubkey(nSize - 2, x_coord)
        # Build P2PK: <65 pubkey> OP_CHECKSIG
        script = bytes([65]) + pubkey + b"\xac"
        return script.hex(), pos

    else:
        # Raw script: length = nSize - 6
        script_len = nSize - 6
        if pos + script_len > len(data):
            from core.errors import UndoDataError
            raise UndoDataError(f"Truncated raw script data at pos {pos}, need {script_len} bytes, have {len(data) - pos}")
        script = data[pos:pos + script_len]
        pos += script_len
        return script.hex(), pos


def _decompress_pubkey(parity: int, x_bytes: bytes) -> bytes:
    """Decompress a public key from x-coordinate on secp256k1.

    parity: 2 = even y, 3 = odd y
    Returns 65-byte uncompressed pubkey (04 + x + y).
    """
    # secp256k1 parameters
    P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F

    x = int.from_bytes(x_bytes, 'big')

    # y^2 = x^3 + 7 (mod P)
    y_sq = (pow(x, 3, P) + 7) % P
    y = pow(y_sq, (P + 1) // 4, P)

    # Check parity
    if parity == 2:  # even
        if y % 2 != 0:
            y = P - y
    else:  # odd (parity == 3)
        if y % 2 == 0:
            y = P - y

    x_out = x.to_bytes(32, 'big')
    y_out = y.to_bytes(32, 'big')
    return b"\x04" + x_out + y_out


def parse_undo_data(data: bytes, block_txs: list) -> tuple[list, int]:
    """Parse undo data for a single block.

    The format follows Bitcoin Core's CBlockUndo serialization:
    - CompactSize: number of CTxUndo entries (= number of non-coinbase txs)
    - For each CTxUndo:
      - CompactSize: number of Coin entries (= number of inputs)
      - For each Coin (TxInUndoFormatter):
        - VARINT(nCode): nHeight * 2 + fCoinBase
        - if nHeight > 0: VARINT(nVersionDummy) (compatibility)
        - TxOutCompression: VARINT(compressed_amount) + ScriptCompression(script)

    block_txs: list of parsed transactions from the block (for verification).
    Returns (list_of_prevout_lists, bytes_consumed).
    """
    pos = 0

    # Read number of CTxUndo entries
    num_tx_undos, pos = read_compact_size(data, pos)

    all_prevouts = []

    for tx_idx in range(num_tx_undos):
        # Read number of Coin entries for this CTxUndo
        num_coins, pos = read_compact_size(data, pos)

        tx_prevouts = []
        for _ in range(num_coins):
            # Read nCode: encodes height and coinbase flag
            nCode, pos = read_varint_core(data, pos)
            height = nCode >> 1
            is_coinbase = nCode & 1

            # If height > 0, read dummy version varint (compatibility)
            if height > 0:
                _, pos = read_varint_core(data, pos)

            # Read compressed amount
            compressed_amount, pos = read_varint_core(data, pos)
            value_sats = decompress_amount(compressed_amount)

            # Read compressed script
            script_hex, pos = decompress_script(data, pos)

            tx_prevouts.append({
                "value_sats": value_sats,
                "script_pubkey_hex": script_hex,
            })

        all_prevouts.append(tx_prevouts)

    return all_prevouts, pos
