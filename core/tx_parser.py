"""Raw Bitcoin transaction parser.

Handles both legacy and SegWit (BIP141) serialization.
Computes txid and wtxid using double SHA-256.
"""

import hashlib
import struct


def _sha256d(data: bytes) -> bytes:
    """Double SHA-256 hash."""
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


class TxParser:
    """Parse a raw Bitcoin transaction from hex or raw bytes."""

    def __init__(self, raw_hex: str = None, *, raw_bytes: bytes = None):
        if raw_bytes is not None:
            self.raw = raw_bytes
        elif raw_hex is not None:
            self.raw = bytes.fromhex(raw_hex)
        else:
            from core.errors import InvalidTxError
            raise InvalidTxError("Must provide raw_hex or raw_bytes")
        self.pos = 0
        self.is_segwit = False

        # For weight calculation: track witness vs non-witness bytes
        self._witness_start = None
        self._witness_end = None

        self.version = 0
        self.inputs = []
        self.outputs = []
        self.locktime = 0

        self._parse()

    def _read(self, n: int) -> bytes:
        if self.pos + n > len(self.raw):
            from core.errors import InvalidTxError
            raise InvalidTxError(f"Unexpected end of transaction data at offset {self.pos}, need {n} bytes")
        result = self.raw[self.pos : self.pos + n]
        self.pos += n
        return result

    def _read_uint8(self) -> int:
        return self._read(1)[0]

    def _read_uint16_le(self) -> int:
        return struct.unpack("<H", self._read(2))[0]

    def _read_uint32_le(self) -> int:
        return struct.unpack("<I", self._read(4))[0]

    def _read_int32_le(self) -> int:
        return struct.unpack("<i", self._read(4))[0]

    def _read_uint64_le(self) -> int:
        return struct.unpack("<Q", self._read(8))[0]

    def _read_varint(self) -> int:
        first = self._read_uint8()
        if first < 0xFD:
            return first
        elif first == 0xFD:
            return self._read_uint16_le()
        elif first == 0xFE:
            return self._read_uint32_le()
        else:
            return self._read_uint64_le()

    def _parse(self):
        start = self.pos

        # Version (4 bytes)
        self.version = self._read_int32_le()

        # Check for SegWit marker and flag
        marker_pos = self.pos
        marker = self._read_uint8()

        if marker == 0x00:
            flag = self._read_uint8()
            if flag != 0x01:
                from core.errors import InvalidTxError
                raise InvalidTxError(f"Invalid SegWit flag: {flag}")
            self.is_segwit = True
        else:
            # Not segwit, rewind
            self.pos = marker_pos
            self.is_segwit = False

        # Inputs
        input_count = self._read_varint()
        for _ in range(input_count):
            txid = self._read(32)[::-1].hex()  # reversed to display convention
            vout = self._read_uint32_le()
            script_sig_len = self._read_varint()
            script_sig = self._read(script_sig_len).hex()
            sequence = self._read_uint32_le()
            self.inputs.append({
                "txid": txid,
                "vout": vout,
                "script_sig_hex": script_sig,
                "sequence": sequence,
                "witness": [],  # filled later if segwit
            })

        # Outputs
        output_count = self._read_varint()
        for i in range(output_count):
            value = self._read_uint64_le()
            script_len = self._read_varint()
            script_pubkey = self._read(script_len).hex()
            self.outputs.append({
                "n": i,
                "value_sats": value,
                "script_pubkey_hex": script_pubkey,
            })

        # Witness data (if segwit)
        if self.is_segwit:
            self._witness_start = self.pos
            for inp in self.inputs:
                item_count = self._read_varint()
                witness_items = []
                for _ in range(item_count):
                    item_len = self._read_varint()
                    item = self._read(item_len).hex()
                    witness_items.append(item)
                inp["witness"] = witness_items
            self._witness_end = self.pos

        # Locktime (4 bytes)
        self.locktime = self._read_uint32_le()

        if self.pos != len(self.raw):
            from core.errors import InvalidTxError
            raise InvalidTxError(f"Extra bytes after transaction: {len(self.raw) - self.pos} remaining")

    def compute_txid(self) -> str:
        """Compute txid (non-witness serialization, double SHA-256, reversed)."""
        # For legacy: just hash the entire raw tx
        # For segwit: hash version + inputs + outputs + locktime (no marker/flag/witness)
        if not self.is_segwit:
            h = _sha256d(self.raw)
            return h[::-1].hex()
        else:
            # Build non-witness serialization
            parts = []
            # Version (4 bytes)
            parts.append(self.raw[:4])
            # Skip marker (1 byte) + flag (1 byte) = start from offset 6
            # Input count + inputs + output count + outputs
            # We need to find where witness starts and where locktime is
            # Easier: rebuild from parsed data
            buf = bytearray()
            buf += struct.pack("<i", self.version)
            buf += self._encode_varint(len(self.inputs))
            for inp in self.inputs:
                buf += bytes.fromhex(inp["txid"])[::-1]  # internal byte order
                buf += struct.pack("<I", inp["vout"])
                script_sig = bytes.fromhex(inp["script_sig_hex"])
                buf += self._encode_varint(len(script_sig))
                buf += script_sig
                buf += struct.pack("<I", inp["sequence"])
            buf += self._encode_varint(len(self.outputs))
            for out in self.outputs:
                buf += struct.pack("<Q", out["value_sats"])
                script = bytes.fromhex(out["script_pubkey_hex"])
                buf += self._encode_varint(len(script))
                buf += script
            buf += struct.pack("<I", self.locktime)

            h = _sha256d(bytes(buf))
            return h[::-1].hex()

    def compute_wtxid(self) -> str | None:
        """Compute wtxid (full serialization including witness). None for legacy."""
        if not self.is_segwit:
            return None
        h = _sha256d(self.raw)
        return h[::-1].hex()

    def get_size_bytes(self) -> int:
        """Total serialized size."""
        return len(self.raw)

    def get_weight(self) -> int:
        """BIP141 weight: non_witness * 4 + witness * 1."""
        if not self.is_segwit:
            return len(self.raw) * 4

        # Non-witness bytes = total - witness_bytes - marker(1) - flag(1)
        witness_bytes = self._witness_end - self._witness_start
        # marker + flag = 2 bytes
        non_witness_bytes = len(self.raw) - witness_bytes - 2
        return non_witness_bytes * 4 + (witness_bytes + 2) * 1

    def get_non_witness_bytes(self) -> int:
        """Non-witness byte count."""
        if not self.is_segwit:
            return len(self.raw)
        witness_bytes = self._witness_end - self._witness_start
        return len(self.raw) - witness_bytes - 2

    def get_witness_bytes(self) -> int:
        """Witness byte count (including marker + flag)."""
        if not self.is_segwit:
            return 0
        witness_bytes = self._witness_end - self._witness_start
        return witness_bytes + 2  # +2 for marker and flag

    @staticmethod
    def _encode_varint(n: int) -> bytes:
        if n < 0xFD:
            return bytes([n])
        elif n <= 0xFFFF:
            return b"\xfd" + struct.pack("<H", n)
        elif n <= 0xFFFFFFFF:
            return b"\xfe" + struct.pack("<I", n)
        else:
            return b"\xff" + struct.pack("<Q", n)


def parse_transaction(raw_hex: str) -> TxParser:
    """Parse a raw transaction hex string and return a TxParser instance."""
    return TxParser(raw_hex)
