#!/usr/bin/env bash
# Launch red-run: starts shell-server, then Claude Code.
set -euo pipefail
cd "$(dirname "$0")"

PORT="${SHELL_SSE_PORT:-8022}"

# Parse run.sh-specific flags, pass the rest to claude
lead="ctf"
claude_args=()
for arg in "$@"; do
    case "$arg" in
        --yolo)       claude_args+=("--dangerously-skip-permissions") ;;
        --lead=*)     lead="${arg#--lead=}" ;;
        *)            claude_args+=("$arg") ;;
    esac
done

# Map lead to slash command
case "$lead" in
    ctf)    skill="/red-run-ctf" ;;
    legacy) skill="/red-run-legacy" ;;
    *)      echo "Unknown lead: $lead (options: ctf, legacy)" >&2; exit 1 ;;
esac

# Check for existing shell-server with active sessions
if ss -tln 2>/dev/null | grep -q ":${PORT} "; then
    status=$(curl -s "http://127.0.0.1:${PORT}/status" 2>/dev/null || echo '{}')
    count=$(echo "$status" | python3 -c "import sys,json; print(json.load(sys.stdin).get('count',0))" 2>/dev/null || echo 0)

    if [[ "$count" -gt 0 ]]; then
        echo "[shell-server] ${count} active session(s) from previous run:"
        echo "$status" | python3 -c "
import sys, json
from datetime import datetime, timezone
data = json.load(sys.stdin)
for s in data.get('sessions', []):
    t = datetime.fromisoformat(s['connected_at'].replace('Z','+00:00'))
    age = datetime.now(timezone.utc) - t
    hrs, rem = divmod(int(age.total_seconds()), 3600)
    mins = rem // 60
    if hrs > 0:
        elapsed = f'{hrs}h{mins}m ago'
    else:
        elapsed = f'{mins}m ago'
    print(f\"  - {s['id']} ({s['label']}, {s['addr']}, {elapsed})\")
" 2>/dev/null
        echo ""
        read -rp "  [k]eep sessions / [c]lear all / [r]estart server? [k/c/r] " choice
        case "${choice,,}" in
            c)
                curl -s -X POST "http://127.0.0.1:${PORT}/clear" >/dev/null 2>&1
                echo "  Sessions cleared."
                ;;
            r)
                pkill -f "shell-server.*server.py" 2>/dev/null || true
                sleep 1
                bash tools/shell-server/start.sh
                echo "  Server restarted."
                ;;
            *)
                echo "  Keeping sessions."
                ;;
        esac
    fi
else
    bash tools/shell-server/start.sh
fi

# Detect and start C2 frameworks
if command -v sliver-server &>/dev/null || command -v sliver &>/dev/null; then
    export RED_RUN_SLIVER_AVAILABLE=1
    echo "[c2] Sliver detected"
    # Start Sliver daemon if not running
    if command -v sliver-server &>/dev/null && ! pgrep -f "sliver-server daemon" &>/dev/null; then
        sliver-server daemon &>/dev/null &
        echo "[c2] Sliver daemon started"
        sleep 1  # brief wait for gRPC to bind
    fi
    # Start sliver-server MCP
    bash tools/sliver-server/start.sh 2>/dev/null && echo "[c2] Sliver MCP ready" \
        || echo "[c2] Sliver MCP failed to start (sliver-server may need operator config)"
fi
# Add future C2 detection here (e.g., Mythic, Havoc)
if [[ -z "${RED_RUN_SLIVER_AVAILABLE:-}" ]]; then
    echo "[c2] No C2 framework detected — shell-server only"
fi

exec claude --model "sonnet[1m]" "${claude_args[@]}" \
    --append-system-prompt "On activation, immediately invoke the skill: ${skill}"
