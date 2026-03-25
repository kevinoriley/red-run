#!/usr/bin/env bash
# Start shell-server as a persistent SSE service.
# Run this before launching Claude Code (e.g., in a tmux pane).
set -euo pipefail
REPO_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
PORT="${SHELL_SSE_PORT:-8022}"
echo "[shell-server] Starting on 127.0.0.1:${PORT} ..."
exec uv run --directory "$REPO_DIR/tools/shell-server" python server.py
