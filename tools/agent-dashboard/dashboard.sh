#!/usr/bin/env bash
# Multi-agent dashboard — reads agent output paths from tools/agent-dashboard/.dashboard
# The orchestrator writes that file when launching parallel background agents.
#
# Usage: bash tools/agent-dashboard/dashboard.sh
#        bash tools/agent-dashboard/dashboard.sh extra-label:/tmp/.../extra.output

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
AGENTS_FILE="$SCRIPT_DIR/.dashboard"

# Derive tasks directory for agent browser
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
ENCODED="$(echo "$PROJECT_DIR" | sed 's|/|-|g')"
TASKS_DIR="/tmp/claude-$(id -u)/${ENCODED}/tasks"

exec python3 "$SCRIPT_DIR/tail-agent.py" --dashboard --from "$AGENTS_FILE" --tasks-dir "$TASKS_DIR" "$@"
