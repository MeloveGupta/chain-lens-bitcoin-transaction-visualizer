#!/usr/bin/env bash
set -euo pipefail

###############################################################################
# cli.sh — Bitcoin transaction / block analyzer CLI
###############################################################################

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

exec python3 "$SCRIPT_DIR/cli/main.py" "$@"
