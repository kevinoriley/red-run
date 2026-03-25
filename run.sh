#!/usr/bin/env bash
# Launch red-run: starts shell-server, then Claude Code.
set -euo pipefail
cd "$(dirname "$0")"
bash tools/shell-server/start.sh
exec claude "$@"
