#!/usr/bin/env bash
# Multi-agent dashboard — reads agent output paths from tools/agent-dashboard/.dashboard
# The orchestrator writes that file when launching parallel background agents.
#
# Usage: bash tools/agent-dashboard/dashboard.sh
#        bash tools/agent-dashboard/dashboard.sh extra-label:/tmp/.../extra.output

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
AGENTS_FILE="$SCRIPT_DIR/.dashboard"

exec python3 "$SCRIPT_DIR/tail-agent.py" --dashboard --from "$AGENTS_FILE" "$@"
