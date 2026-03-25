#!/usr/bin/env bash
# Launch red-run: starts shell-server, then Claude Code.
set -euo pipefail
cd "$(dirname "$0")"
bash tools/shell-server/start.sh

args=("$@")
for i in "${!args[@]}"; do
    if [[ "${args[$i]}" == "--yolo" ]]; then
        args[$i]="--dangerously-skip-permissions"
    fi
done

exec claude "${args[@]}"
