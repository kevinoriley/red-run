#!/usr/bin/env bash
set -euo pipefail

# uninstall.sh — Remove red-run skills and MCP server data
#
# Removes:
# - All red-run native skills from ~/.claude/skills/
# - ChromaDB index (tools/skill-router/.chromadb/)
# - Python venv (tools/skill-router/.venv/)
#
# Does NOT remove .mcp.json or .claude/settings.json (project config).

REPO_DIR="$(cd "$(dirname "$0")" && pwd)"
SKILLS_DST="${HOME}/.claude/skills"
PREFIX="red-run"
MCP_DIR="${REPO_DIR}/tools/skill-router"

# --- Step 1: Remove native skills ---
echo "Removing native skills..."
count=0
for dir in "${SKILLS_DST}/${PREFIX}-"*/; do
    if [[ -d "$dir" ]]; then
        rm -rf "$dir"
        echo "  Removed: $(basename "$dir")"
        count=$((count + 1))
    fi
done
echo "  ${count} skill(s) removed"

# --- Step 2: Clean up MCP skill-router ---
echo ""
echo "Cleaning up MCP skill-router..."
mcp_cleaned=0
if [[ -d "${MCP_DIR}/.chromadb" ]]; then
    rm -rf "${MCP_DIR}/.chromadb"
    echo "  Removed ChromaDB index"
    mcp_cleaned=$((mcp_cleaned + 1))
fi
if [[ -d "${MCP_DIR}/.venv" ]]; then
    rm -rf "${MCP_DIR}/.venv"
    echo "  Removed Python venv"
    mcp_cleaned=$((mcp_cleaned + 1))
fi
if [[ "$mcp_cleaned" -eq 0 ]]; then
    echo "  Nothing to clean up"
fi

echo ""
echo "Uninstall complete."
