"""Bitcoin transaction/block analyzer CLI entry point."""

import json
import os
import sys

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.errors import AnalyzerError, InvalidFixtureError, InvalidBlockError
from core.analyzer import analyze_transaction
from core.block_parser import parse_blocks


def run_transaction_mode(fixture_path: str):
    """Run in single-transaction mode."""
    try:
        with open(fixture_path, "r") as f:
            fixture = json.load(f)
    except json.JSONDecodeError as e:
        error = InvalidFixtureError(f"Invalid JSON in fixture file: {e}")
        print(error.to_json())
        sys.exit(1)
    except FileNotFoundError:
        error = InvalidFixtureError(f"Fixture file not found: {fixture_path}")
        print(error.to_json())
        sys.exit(1)

    try:
        result = analyze_transaction(fixture)
    except AnalyzerError as e:
        print(e.to_json())
        sys.exit(1)
    except Exception as e:
        error = InvalidFixtureError(f"Unexpected error: {str(e)}")
        print(error.to_json())
        sys.exit(1)

    # Create output directory
    os.makedirs("out", exist_ok=True)

    # Write to file
    txid = result["txid"]
    output_path = os.path.join("out", f"{txid}.json")
    with open(output_path, "w") as f:
        json.dump(result, f, indent=2)

    # Print to stdout (single-transaction mode only)
    print(json.dumps(result, indent=2))


def run_block_mode(blk_path: str, rev_path: str, xor_path: str):
    """Run in block parsing mode."""
    try:
        with open(blk_path, "rb") as f:
            blk_data = f.read()
        with open(rev_path, "rb") as f:
            rev_data = f.read()
        with open(xor_path, "rb") as f:
            xor_key = f.read()
    except FileNotFoundError as e:
        error = InvalidBlockError(f"File not found: {e}")
        print(error.to_json())
        sys.exit(1)

    try:
        blocks = parse_blocks(blk_data, rev_data, xor_key)
    except AnalyzerError as e:
        print(e.to_json())
        sys.exit(1)
    except Exception as e:
        error = InvalidBlockError(f"Unexpected error: {str(e)}")
        print(error.to_json())
        sys.exit(1)

    if not blocks:
        error = InvalidBlockError("No blocks found in file")
        print(error.to_json())
        sys.exit(1)

    # Create output directory
    os.makedirs("out", exist_ok=True)

    # Write each block to file
    for block in blocks:
        block_hash = block["block_header"]["block_hash"]
        output_path = os.path.join("out", f"{block_hash}.json")
        with open(output_path, "w") as f:
            json.dump(block, f, indent=2)


def main():
    args = sys.argv[1:]

    if not args:
        error = InvalidFixtureError("Usage: cli/main.py <fixture.json> or cli/main.py --block <blk> <rev> <xor>")
        print(error.to_json())
        sys.exit(1)

    if args[0] == "--block":
        if len(args) < 4:
            error = InvalidBlockError("Block mode requires: --block <blk.dat> <rev.dat> <xor.dat>")
            print(error.to_json())
            sys.exit(1)
        run_block_mode(args[1], args[2], args[3])
    else:
        run_transaction_mode(args[0])


if __name__ == "__main__":
    main()
