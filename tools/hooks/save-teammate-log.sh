#!/usr/bin/env bash
set -euo pipefail

# TeammateIdle hook — copies teammate JSONL transcripts to engagement evidence
# and checks for AUP/content filter errors (dead-man's switch).
# Reads hook JSON from stdin. Exits silently if no engagement directory exists.
# Always exits 0 to never block the teammate.

INPUT=$(cat)
TRANSCRIPT_PATH=$(echo "$INPUT" | jq -r '.transcript_path // empty')
SESSION_ID=$(echo "$INPUT" | jq -r '.session_id // empty')
TEAMMATE_NAME=$(echo "$INPUT" | jq -r '.teammate_name // empty')

# No transcript path or file missing = nothing to do
[[ -z "$TRANSCRIPT_PATH" ]] && exit 0
[[ ! -f "$TRANSCRIPT_PATH" ]] && exit 0

# No engagement directory = no logging (graceful degradation)
LOG_DIR="engagement/evidence/logs"
[[ ! -d "$LOG_DIR" ]] && exit 0

TIMESTAMP=$(date -u '+%Y%m%dT%H%M%SZ')
SAFE_ID=$(echo "${SESSION_ID:-unknown}" | tr -cd 'a-zA-Z0-9-' | head -c 20)
SAFE_NAME=$(echo "${TEAMMATE_NAME:-unknown}" | tr -cd 'a-zA-Z0-9-' | head -c 20)

# Copy transcript (teammate may continue, so this captures current state)
cp "$TRANSCRIPT_PATH" "${LOG_DIR}/${TIMESTAMP}-teammate-${SAFE_NAME}-${SAFE_ID}.jsonl"

# --- AUP / content filter detection ---
# Scan the last 200 lines of the transcript for content filter patterns.
# If detected, write a sentinel file so the orchestrator knows the teammate
# is poisoned and should be dismissed/respawned.
AUP_PATTERNS='content.policy|content.filter|content_policy|I cannot assist|I.m not able to help|unable to assist with this request|responsibleAI|Your request was flagged'

if tail -200 "$TRANSCRIPT_PATH" | grep -qiE "$AUP_PATTERNS" 2>/dev/null; then
    FLAG_FILE="engagement/evidence/aup-${SAFE_NAME}.flag"
    {
        echo "teammate: ${TEAMMATE_NAME}"
        echo "session: ${SESSION_ID}"
        echo "detected: ${TIMESTAMP}"
        echo "transcript: ${TRANSCRIPT_PATH}"
        # Extract the matching line for context
        echo "---"
        tail -200 "$TRANSCRIPT_PATH" | grep -iE "$AUP_PATTERNS" | tail -3
    } > "$FLAG_FILE"
fi

exit 0
