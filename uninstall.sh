#!/usr/bin/env bash
set -euo pipefail

# uninstall.sh — Remove all red-run skills from ~/.claude/skills/

SKILLS_DST="${HOME}/.claude/skills"
PREFIX="red-run"

count=0
for dir in "${SKILLS_DST}/${PREFIX}-"*/; do
    if [[ -d "$dir" ]]; then
        rm -rf "$dir"
        echo "  Removed: $(basename "$dir")"
        ((count++))
    fi
done

echo ""
echo "Removed ${count} red-run skills."
