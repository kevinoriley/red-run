#!/usr/bin/env bash
set -euo pipefail

# SubagentStop hook — copies subagent JSONL transcripts to engagement evidence.
# Reads hook JSON from stdin. Exits silently if no engagement directory exists.
# Always exits 0 to never block Claude Code.

INPUT=$(cat)
TRANSCRIPT_PATH=$(echo "$INPUT" | jq -r '.agent_transcript_path // empty')
AGENT_TYPE=$(echo "$INPUT" | jq -r '.agent_type // empty')

# No transcript path or file missing = nothing to copy
[[ -z "$TRANSCRIPT_PATH" ]] && exit 0
[[ ! -f "$TRANSCRIPT_PATH" ]] && exit 0

# No engagement directory = no logging (graceful degradation)
LOG_DIR="engagement/evidence/logs"
[[ ! -d "$LOG_DIR" ]] && exit 0

# Sanitize agent type for filename (alphanumeric, hyphens only)
SAFE_TYPE=$(echo "${AGENT_TYPE:-unknown}" | tr -cd 'a-zA-Z0-9-')
TIMESTAMP=$(date -u '+%Y%m%dT%H%M%SZ')

cp "$TRANSCRIPT_PATH" "${LOG_DIR}/${TIMESTAMP}-${SAFE_TYPE}.jsonl"
exit 0
