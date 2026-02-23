#!/usr/bin/env bash
set -euo pipefail

# install.sh — Install red-run skills to ~/.claude/skills/
#
# Default: creates symlinks (edits in repo reflect immediately)
# --copy:  copies files (for distribution without the repo)

REPO_DIR="$(cd "$(dirname "$0")" && pwd)"
SKILLS_SRC="${REPO_DIR}/skills"
SKILLS_DST="${HOME}/.claude/skills"
PREFIX="red-run"
MODE="symlink"

if [[ "${1:-}" == "--copy" ]]; then
    MODE="copy"
fi

mkdir -p "${SKILLS_DST}"

count=0

# Find all SKILL.md files, skip _template
while IFS= read -r skill_file; do
    skill_dir="$(basename "$(dirname "$skill_file")")"

    if [[ "$skill_dir" == "_template" ]]; then
        continue
    fi

    installed_name="${PREFIX}-${skill_dir}"
    dest_dir="${SKILLS_DST}/${installed_name}"
    skill_src_dir="$(dirname "$skill_file")"

    mkdir -p "${dest_dir}"

    # Install SKILL.md
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
    count=$((count + 1))

done < <(find "${SKILLS_SRC}" -name "SKILL.md" -not -path "*/_template/*" | sort)

echo ""
echo "Installed ${count} skills to ${SKILLS_DST}/ (${MODE} mode)"
