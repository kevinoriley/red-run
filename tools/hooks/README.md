# Hooks

Claude Code hook scripts for red-run engagement logging and state monitoring.
Configured in `.claude/settings.json` by `install.sh`.

## Scripts

### save-agent-log.sh

SubagentStop hook that copies agent JSONL transcripts to
`engagement/evidence/logs/` for post-engagement analysis.

**Trigger:** Runs automatically when any Claude Code subagent stops.

**Behavior:**

1. Reads hook JSON from stdin (`agent_transcript_path`, `agent_type`)
2. Checks that transcript file exists
3. Checks that `engagement/evidence/logs/` directory exists — exits silently
   if not (graceful degradation when no engagement is active)
4. Copies transcript with filename `{ISO-timestamp}-{agent-type}.jsonl`
   (e.g., `20260227T143052Z-web-exploit-agent.jsonl`)
5. Always exits 0 to never block Claude Code

**Scope:** Only triggers for red-run domain agents (network-recon,
web-discovery, web-exploit, ad-discovery, ad-exploit, password-spray,
linux-privesc, windows-privesc, evasion, credential-cracking). Built-in
subagents (Explore, Plan, general-purpose) produce transcripts too, but
are filtered by agent type naming.

**Dependencies:** `jq` for JSON parsing.

### event-watcher.sh

Background poller for the `state_events` table in engagement state. Spawned
by the orchestrator with `run_in_background: true` to get real-time
notifications when discovery agents write interim findings.

**Usage:**

```bash
bash tools/hooks/event-watcher.sh <cursor> <db_path>
```

- `cursor` — last seen `state_events.id` (0 to get all events)
- `db_path` — path to `engagement/state.db`

**Behavior:**

1. Polls `state_events` every 5 seconds for rows with `id > cursor`
2. When events are detected, waits 5 seconds (debounce) to let the agent
   finish its batch of writes
3. Prints all new events as JSON array and exits 0
4. Times out after 10 minutes with `{"timeout": true, "cursor": N}` to
   prevent zombie watchers

**Dependencies:** `python3` with `sqlite3` stdlib module (no sqlite3 CLI
needed).

## Configuration

Hooks are configured in `.claude/settings.json` under the `hooks` key.
The installer sets this up automatically. Example configuration:

```json
{
  "hooks": {
    "SubagentStop": [
      {
        "type": "command",
        "command": "bash /path/to/red-run/tools/hooks/save-agent-log.sh"
      }
    ]
  }
}
```

The event watcher is not a hook — it's a regular background script spawned
by the orchestrator via Bash `run_in_background`.
