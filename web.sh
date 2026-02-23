#!/usr/bin/env bash
set -euo pipefail

###############################################################################
# web.sh — Bitcoin transaction web visualizer
###############################################################################

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
export PORT="${PORT:-3000}"

exec python3 "$SCRIPT_DIR/api/server.py"
