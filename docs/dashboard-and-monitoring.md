# Dashboard & Monitoring

red-run provides real-time visibility into teammate execution through Claude Code agent teams and the state dashboard.

## Agent Teams (Primary)

red-run uses [Claude Code agent teams](https://code.claude.com/docs/en/agent-teams) for teammate coordination and visibility. Each teammate runs in its own tmux pane, giving the operator a live view of all parallel work.

**Operator controls:**

- **Watch** — see each teammate's output in its own tmux pane (reasoning, commands, results)
- **Interrupt** — press Escape in a teammate's pane to stop its current turn
- **Redirect** — type directly to any teammate to give new instructions or ask questions
- **Monitor task list** — press Ctrl+T to toggle the shared task list showing all assigned work

For split-pane mode, start Claude Code inside a tmux session. Without tmux, teammates run in-process mode — cycle through them with Shift+Down.

### Setup

Add to `.claude/settings.json` (project-level):

```json
{
  "env": {
    "CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS": "1"
  }
}
```

## Legacy Terminal Dashboard

The terminal-based agent dashboard (JSONL transcript viewer for legacy subagent runs) has been removed from this repo. If you need it for `/red-run-legacy` subagent monitoring, it's available in the [agentsee](https://github.com/blacklanternsecurity/agentsee) repo.

## Transcript Capture

Every agent's full JSONL transcript is automatically saved to `engagement/evidence/logs/` when the agent finishes. This is the accountability layer — the dashboard shows you what agents are doing in real time, and transcripts give you a permanent record of every tool call, command, and decision each agent made.

A `SubagentStop` hook (`tools/hooks/save-agent-log.sh`) handles this automatically:

1. Claude Code fires the `SubagentStop` event when any agent finishes
2. The hook reads `agent_transcript_path` and `agent_type` from the event JSON
3. Copies the transcript to `engagement/evidence/logs/{timestamp}-{agent-type}.jsonl`

Only red-run agents are captured (network-recon, web-discovery, web-exploit, ad-discovery, ad-exploit, password-spray, linux-privesc, windows-privesc, evasion, credential-cracking). Built-in subagents (Explore, Plan, general-purpose) are ignored.

No engagement directory = hook exits silently. The retrospective skill parses these logs for post-engagement analysis.

## Configuration

### Hook Setup

The `SubagentStop` hook is configured in `.claude/settings.json`:

```json
{
  "hooks": {
    "SubagentStop": [
      {
        "matcher": "",
        "hooks": [
          {
            "type": "command",
            "command": "bash tools/hooks/save-agent-log.sh"
          }
        ]
      }
    ]
  }
}
```

The hook always exits 0 to never block Claude Code, regardless of whether logging succeeds.
