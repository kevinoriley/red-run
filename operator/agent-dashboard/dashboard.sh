#!/usr/bin/env bash
# Multi-agent dashboard — auto-discovers Claude Code agent output files.
#
# Usage: bash dashboard.sh
#        bash dashboard.sh extra-label:/tmp/.../extra.output
#        bash dashboard.sh --purge

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Derive tasks directory from cwd (matches Claude Code's convention)
ENCODED="${PWD//\//-}"
TASKS_DIR="/tmp/claude-$(id -u)/${ENCODED}/tasks"

# --purge is a standalone mode, not a dashboard flag
if [[ "${1:-}" == "--purge" ]]; then
    exec python3 "$SCRIPT_DIR/tail-agent.py" --purge --project-dir "$PWD"
fi

exec python3 "$SCRIPT_DIR/tail-agent.py" --dashboard --tasks-dir "$TASKS_DIR" --project-dir "$PWD" "$@"
