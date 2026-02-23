"""Structured error handling for the Bitcoin analyzer."""

import json
import sys


class AnalyzerError(Exception):
    """Base exception with structured JSON error output."""

    def __init__(self, code: str, message: str):
        self.code = code
        self.message = message
        super().__init__(message)

    def to_dict(self):
        return {
            "ok": False,
            "error": {
                "code": self.code,
                "message": self.message,
            },
        }

    def to_json(self):
        return json.dumps(self.to_dict())


class InvalidTxError(AnalyzerError):
    def __init__(self, message: str):
        super().__init__("INVALID_TX", message)


class InvalidBlockError(AnalyzerError):
    def __init__(self, message: str):
        super().__init__("INVALID_BLOCK", message)


class InvalidFixtureError(AnalyzerError):
    def __init__(self, message: str):
        super().__init__("INVALID_FIXTURE", message)


class MerkleRootMismatchError(AnalyzerError):
    def __init__(self, expected: str, computed: str):
        super().__init__(
            "MERKLE_ROOT_MISMATCH",
            f"Merkle root mismatch: header={expected}, computed={computed}",
        )


class UndoDataError(AnalyzerError):
    def __init__(self, message: str):
        super().__init__("UNDO_DATA_ERROR", message)


def error_exit(error: AnalyzerError):
    """Print error JSON to stdout and exit with code 1."""
    print(error.to_json())
    sys.exit(1)
