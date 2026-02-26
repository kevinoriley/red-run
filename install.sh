#!/usr/bin/env bash
set -euo pipefail

# install.sh — Install red-run skill library
#
# Installs the orchestrator as a native Claude Code skill and sets up the MCP
# skill-router server (ChromaDB + embeddings) for on-demand technique skill
# loading.
#
# Default: creates symlinks (edits in repo reflect immediately)
# --copy:  copies orchestrator (for machines without persistent repo access)
#
# The MCP server always reads skills from the repo, so the repo must stay in
# place regardless of mode.
#
# Requires: uv (https://docs.astral.sh/uv/)

REPO_DIR="$(cd "$(dirname "$0")" && pwd)"
SKILLS_SRC="${REPO_DIR}/skills"
SKILLS_DST="${HOME}/.claude/skills"
PREFIX="red-run"
MCP_DIR="${REPO_DIR}/tools/skill-router"

# Only the orchestrator is installed as a native Claude Code skill.
# Everything else is served on-demand via the MCP skill-router.
NATIVE_SKILLS=("orchestrator")

MODE="symlink"
if [[ "${1:-}" == "--copy" ]]; then
    MODE="copy"
fi

mkdir -p "${SKILLS_DST}"

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

# --- Step 4: Set up MCP skill-router ---
echo ""
echo "Setting up MCP skill-router..."

if ! command -v uv &>/dev/null; then
    echo "ERROR: uv is required but not found." >&2
    echo "  Install: https://docs.astral.sh/uv/getting-started/installation/" >&2
    exit 1
fi

echo "  Installing Python dependencies..."
uv sync --directory "${MCP_DIR}" --quiet

echo "  Indexing skills into ChromaDB (downloads embedding model on first run)..."
uv run --directory "${MCP_DIR}" python indexer.py

# --- Step 5: Verify project config ---
config_warnings=0
if [[ ! -f "${REPO_DIR}/.mcp.json" ]]; then
    echo ""
    echo "WARNING: .mcp.json not found — MCP server won't auto-start."
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
echo "63 technique/discovery skills served via MCP skill-router"
if [[ "$config_warnings" -eq 0 ]]; then
    echo ""
    echo "Done! Start Claude Code from this repo directory to activate."
fi
