#!/usr/bin/env bash
# Start sliver-server MCP as a persistent SSE service.
# Idempotent — exits once the server is listening.
set -euo pipefail
REPO_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
PORT="${SLIVER_SSE_PORT:-8023}"

# Already listening — nothing to do
if ss -tln 2>/dev/null | grep -q ":${PORT} "; then
    exit 0
fi

# Start server in background
uv run --directory "$REPO_DIR/tools/sliver-server" python server.py &>/dev/null &

# Wait until it's actually listening (up to 15s)
for i in $(seq 1 30); do
    if ss -tln 2>/dev/null | grep -q ":${PORT} "; then
        exit 0
    fi
    sleep 0.5
done

echo "sliver-server MCP failed to start on port ${PORT}" >&2
exit 1
