#!/usr/bin/env bash
set -euo pipefail

# install.sh — Install red-run skill library
#
# Installs the orchestrator as a native Claude Code skill, custom subagents,
# and sets up MCP servers (skill-router, nmap-server, shell-server,
# state-server) for on-demand skill loading, privileged scanning, reverse
# shell management, and SQLite engagement state.
#
# Default: creates symlinks (edits in repo reflect immediately)
# --copy:  copies files (for machines without persistent repo access)
#
# MCP servers always read from the repo, so the repo must stay in place.
#
# Requires: uv (https://docs.astral.sh/uv/)

REPO_DIR="$(cd "$(dirname "$0")" && pwd)"
SKILLS_SRC="${REPO_DIR}/skills"
SKILLS_DST="${HOME}/.claude/skills"
AGENTS_SRC="${REPO_DIR}/agents"
AGENTS_DST="${HOME}/.claude/agents"
PREFIX="red-run"
MCP_SKILL_ROUTER="${REPO_DIR}/tools/skill-router"
MCP_NMAP_SERVER="${REPO_DIR}/tools/nmap-server"
MCP_SHELL_SERVER="${REPO_DIR}/tools/shell-server"
MCP_STATE_SERVER="${REPO_DIR}/tools/state-server"

# Only the orchestrator is installed as a native Claude Code skill.
# Everything else is served on-demand via the MCP skill-router.
NATIVE_SKILLS=("orchestrator")

MODE="symlink"
if [[ "${1:-}" == "--copy" ]]; then
    MODE="copy"
fi

mkdir -p "${SKILLS_DST}" "${AGENTS_DST}"

# --- Step 1: Clean up old native installs ---
# Previous versions installed all 62+ skills natively. The MCP architecture
# only needs the orchestrator natively — remove the rest.
old_count=0
for dir in "${SKILLS_DST}/${PREFIX}-"*/; do
    [[ -d "$dir" ]] || continue
    skill_basename="$(basename "$dir")"
    skill_name="${skill_basename#"${PREFIX}"-}"

    is_native=0
    for ns in "${NATIVE_SKILLS[@]}"; do
        [[ "$skill_name" == "$ns" ]] && is_native=1 && break
    done

    if [[ "$is_native" -eq 0 ]]; then
        rm -rf "$dir"
        echo "  Removed old native: ${skill_basename}"
        old_count=$((old_count + 1))
    fi
done
if [[ "$old_count" -gt 0 ]]; then
    echo "Cleaned up ${old_count} old native skill(s)"
    echo ""
fi

# --- Step 2: Install native skills ---
echo "Installing native skills..."
native_count=0
for skill_name in "${NATIVE_SKILLS[@]}"; do
    skill_file="$(find "${SKILLS_SRC}" -path "*/${skill_name}/SKILL.md" -print -quit)"
    if [[ -z "$skill_file" ]]; then
        echo "ERROR: Cannot find SKILL.md for native skill '${skill_name}'" >&2
        exit 1
    fi

    installed_name="${PREFIX}-${skill_name}"
    dest_dir="${SKILLS_DST}/${installed_name}"
    skill_src_dir="$(dirname "$skill_file")"

    mkdir -p "${dest_dir}"

    rm -f "${dest_dir}/SKILL.md"
    if [[ "$MODE" == "symlink" ]]; then
        ln -s "$skill_file" "${dest_dir}/SKILL.md"
    else
        cp "$skill_file" "${dest_dir}/SKILL.md"
    fi

    # Install subdirectories (scripts/, references/, assets/) if they exist
    for subdir in scripts references assets; do
        if [[ -d "${skill_src_dir}/${subdir}" ]]; then
            rm -rf "${dest_dir:?}/${subdir}"
            if [[ "$MODE" == "symlink" ]]; then
                ln -s "${skill_src_dir}/${subdir}" "${dest_dir}/${subdir}"
            else
                cp -r "${skill_src_dir}/${subdir}" "${dest_dir}/${subdir}"
            fi
        fi
    done

    echo "  ${installed_name} -> ${skill_file}"
    native_count=$((native_count + 1))
done

# --- Step 3: Validate native installs ---
for skill_name in "${NATIVE_SKILLS[@]}"; do
    installed="${SKILLS_DST}/${PREFIX}-${skill_name}/SKILL.md"
    if [[ ! -r "$installed" ]]; then
        target="$(readlink -f "$installed" 2>/dev/null || echo "unknown")"
        echo "ERROR: Broken skill: ${installed} -> ${target}" >&2
        exit 1
    fi
done

# --- Step 4: Install custom subagents ---
echo ""
echo "Installing custom subagents..."
agent_count=0
for agent_file in "${AGENTS_SRC}"/*.md; do
    [[ -f "$agent_file" ]] || continue
    agent_basename="$(basename "$agent_file")"
    dest_file="${AGENTS_DST}/${agent_basename}"

    rm -f "$dest_file"
    if [[ "$MODE" == "symlink" ]]; then
        ln -s "$agent_file" "$dest_file"
    else
        cp "$agent_file" "$dest_file"
    fi

    echo "  ${agent_basename} -> ${agent_file}"
    agent_count=$((agent_count + 1))
done

# Validate agent installs
for agent_file in "${AGENTS_DST}"/*.md; do
    [[ -f "$agent_file" ]] || continue
    if [[ ! -r "$agent_file" ]]; then
        echo "ERROR: Broken agent: ${agent_file}" >&2
        exit 1
    fi
done

# Clean up old agents replaced by the discovery/exploit split
OLD_AGENTS=("web-agent.md" "ad-agent.md" "privesc-agent.md")
old_agent_count=0
for old_agent in "${OLD_AGENTS[@]}"; do
    old_dest="${AGENTS_DST}/${old_agent}"
    if [[ -f "$old_dest" || -L "$old_dest" ]]; then
        rm -f "$old_dest"
        echo "  Removed old agent: ${old_agent}"
        old_agent_count=$((old_agent_count + 1))
    fi
done
if [[ "$old_agent_count" -gt 0 ]]; then
    echo "  Cleaned up ${old_agent_count} old agent(s)"
fi

# --- Step 5: Set up MCP servers ---
echo ""
echo "Setting up MCP servers..."

if ! command -v uv &>/dev/null; then
    echo "ERROR: uv is required but not found." >&2
    echo "  Install: https://docs.astral.sh/uv/getting-started/installation/" >&2
    exit 1
fi

# Skill-router (ChromaDB + embeddings)
echo "  [skill-router] Installing Python dependencies..."
uv sync --directory "${MCP_SKILL_ROUTER}" --quiet

echo "  [skill-router] Indexing skills into ChromaDB (downloads embedding model on first run)..."
uv run --directory "${MCP_SKILL_ROUTER}" python indexer.py

# nmap-server
echo "  [nmap-server] Installing Python dependencies..."
uv sync --directory "${MCP_NMAP_SERVER}" --quiet

# Build Docker image for nmap
if command -v docker &>/dev/null && docker info &>/dev/null 2>&1; then
    echo "  [nmap-server] Building Docker image..."
    docker build -t red-run-nmap:latest "${MCP_NMAP_SERVER}" --quiet
    echo "  [nmap-server] Docker image: OK"
else
    echo ""
    echo "  WARNING: Docker required for nmap MCP server but not available."
    echo "  Install Docker and ensure the daemon is running, then re-run install.sh."
    echo ""
fi

# shell-server (TCP listener + reverse shell manager)
echo "  [shell-server] Installing Python dependencies..."
uv sync --directory "${MCP_SHELL_SERVER}" --quiet

# state-server (SQLite engagement state)
echo "  [state-server] Installing Python dependencies..."
uv sync --directory "${MCP_STATE_SERVER}" --quiet

# --- Step 6: Verify project config ---
config_warnings=0
if [[ ! -f "${REPO_DIR}/.mcp.json" ]]; then
    echo ""
    echo "WARNING: .mcp.json not found — MCP servers won't auto-start."
    config_warnings=$((config_warnings + 1))
fi

settings_file="${REPO_DIR}/.claude/settings.json"
if [[ -f "$settings_file" ]]; then
    if ! grep -q '"enableAllProjectMcpServers"' "$settings_file"; then
        echo ""
        echo "WARNING: enableAllProjectMcpServers not set in .claude/settings.json"
        config_warnings=$((config_warnings + 1))
    fi
fi

# --- Summary ---
echo ""
echo "Installed ${native_count} native skill(s) to ${SKILLS_DST}/ (${MODE} mode)"
echo "Installed ${agent_count} custom subagent(s) to ${AGENTS_DST}/"
echo "63 technique/discovery skills served via MCP skill-router"
echo "nmap MCP server ready (Dockerized nmap)"
echo "shell MCP server ready (TCP listener + reverse shell manager)"
echo "state MCP server ready (SQLite engagement state)"
if [[ "$config_warnings" -eq 0 ]]; then
    echo ""
    echo "Done! Start Claude Code from this repo directory to activate."
fi
