#!/usr/bin/env bash
set -euo pipefail

# uninstall.sh — Remove red-run skills, agents, and MCP server data
#
# Removes:
# - All red-run native skills from ~/.claude/skills/
# - Custom subagents from ~/.claude/agents/
# - ChromaDB index (tools/skill-router/.chromadb/)
# - Python venvs (tools/skill-router/.venv/, tools/nmap-server/.venv/, tools/shell-server/.venv/, tools/state-server/.venv/)
#
# Does NOT remove .mcp.json or .claude/settings.json (project config).

REPO_DIR="$(cd "$(dirname "$0")" && pwd)"
SKILLS_DST="${HOME}/.claude/skills"
AGENTS_DST="${HOME}/.claude/agents"
AGENTS_SRC="${REPO_DIR}/agents"
PREFIX="red-run"
MCP_SKILL_ROUTER="${REPO_DIR}/tools/skill-router"
MCP_NMAP_SERVER="${REPO_DIR}/tools/nmap-server"
MCP_SHELL_SERVER="${REPO_DIR}/tools/shell-server"
MCP_STATE_SERVER="${REPO_DIR}/tools/state-server"

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

# --- Step 2: Remove custom subagents ---
echo ""
echo "Removing custom subagents..."
agent_count=0
for agent_file in "${AGENTS_SRC}"/*.md; do
    [[ -f "$agent_file" ]] || continue
    agent_basename="$(basename "$agent_file")"
    dest_file="${AGENTS_DST}/${agent_basename}"
    if [[ -f "$dest_file" || -L "$dest_file" ]]; then
        rm -f "$dest_file"
        echo "  Removed: ${agent_basename}"
        agent_count=$((agent_count + 1))
    fi
done

# Also clean up old agents from before the discovery/exploit split
OLD_AGENTS=("web-agent.md" "ad-agent.md" "privesc-agent.md")
for old_agent in "${OLD_AGENTS[@]}"; do
    old_dest="${AGENTS_DST}/${old_agent}"
    if [[ -f "$old_dest" || -L "$old_dest" ]]; then
        rm -f "$old_dest"
        echo "  Removed old agent: ${old_agent}"
        agent_count=$((agent_count + 1))
    fi
done
echo "  ${agent_count} agent(s) removed"

# --- Step 3: Clean up MCP servers ---
echo ""
echo "Cleaning up MCP servers..."
mcp_cleaned=0

# Skill-router
if [[ -d "${MCP_SKILL_ROUTER}/.chromadb" ]]; then
    rm -rf "${MCP_SKILL_ROUTER}/.chromadb"
    echo "  Removed ChromaDB index"
    mcp_cleaned=$((mcp_cleaned + 1))
fi
if [[ -d "${MCP_SKILL_ROUTER}/.venv" ]]; then
    rm -rf "${MCP_SKILL_ROUTER}/.venv"
    echo "  Removed skill-router venv"
    mcp_cleaned=$((mcp_cleaned + 1))
fi

# nmap-server
if [[ -d "${MCP_NMAP_SERVER}/.venv" ]]; then
    rm -rf "${MCP_NMAP_SERVER}/.venv"
    echo "  Removed nmap-server venv"
    mcp_cleaned=$((mcp_cleaned + 1))
fi

# nmap Docker image
if command -v docker &>/dev/null && docker image inspect red-run-nmap:latest &>/dev/null 2>&1; then
    docker rmi red-run-nmap:latest &>/dev/null
    echo "  Removed Docker image: red-run-nmap:latest"
    mcp_cleaned=$((mcp_cleaned + 1))
fi

# shell-server
if [[ -d "${MCP_SHELL_SERVER}/.venv" ]]; then
    rm -rf "${MCP_SHELL_SERVER}/.venv"
    echo "  Removed shell-server venv"
    mcp_cleaned=$((mcp_cleaned + 1))
fi

# state-server
if [[ -d "${MCP_STATE_SERVER}/.venv" ]]; then
    rm -rf "${MCP_STATE_SERVER}/.venv"
    echo "  Removed state-server venv"
    mcp_cleaned=$((mcp_cleaned + 1))
fi

if [[ "$mcp_cleaned" -eq 0 ]]; then
    echo "  Nothing to clean up"
fi

echo ""
echo "Uninstall complete."
