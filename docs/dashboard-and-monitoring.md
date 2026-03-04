# Dashboard & Monitoring

red-run provides real-time visibility into agent execution through a multi-pane dashboard and background event polling.

## Agent Dashboard

The dashboard (`tools/agent-dashboard/tail-agent.py`) parses Claude Code's raw JSONL transcripts and displays agent activity with color-coded formatting.

### Single-Agent Modes

```bash
# One-shot — print formatted output and exit
python3 tools/agent-dashboard/tail-agent.py <output_file>

# Follow — live-tail like tail -f (Ctrl-C to stop)
python3 tools/agent-dashboard/tail-agent.py -f <output_file>

# Pipe — read from stdin
tail -f <output_file> | python3 tools/agent-dashboard/tail-agent.py
```

### Multi-Agent Dashboard

The curses-based dashboard shows multiple agents side by side in a split-pane terminal view:

```bash
# Explicit label:path pairs
python3 tools/agent-dashboard/tail-agent.py --dashboard web:path1 ad:path2

# From a .dashboard file (hot-reloaded)
python3 tools/agent-dashboard/tail-agent.py --dashboard --from .dashboard

# Wrapper script (reads from tools/agent-dashboard/.dashboard)
bash tools/agent-dashboard/dashboard.sh
```

The orchestrator writes the `.dashboard` file when launching parallel background agents.

### .dashboard File Format

One agent per line as `label:path`. Blank lines and `#` comments are ignored:

```
# Discovery agents
web-discovery:/tmp/claude-1000/web-discovery.output
network-recon:/tmp/claude-1000/network-recon.output

# Exploit agents
ad-exploit:/tmp/claude-1000/ad-exploit.output
```

The dashboard hot-reloads this file every ~1 second — panes are added and removed dynamically as entries change. Starts with "Waiting for agents..." if the file is empty or doesn't exist yet.

### Keybindings

| Key | Action |
|-----|--------|
| `Tab` | Switch to next pane |
| `Shift-Tab` | Switch to previous pane |
| `j` / `Down` | Scroll down |
| `k` / `Up` | Scroll up |
| `PgDn` | Page down |
| `PgUp` | Page up |
| `G` / `End` | Jump to bottom (resume live follow) |
| `g` / `Home` | Jump to top |
| `q` / `Ctrl-C` | Quit |

The status bar shows `LIVE` when auto-following new output or `scrolled +N` when scrolled up. Scrolling to the bottom re-enables live follow.

### Color Coding

| Color | Category | Content |
|-------|----------|---------|
| Cyan | Agent reasoning | Text output from the agent's thinking and analysis |
| Yellow (bold, `▶` prefix) | Shell/Bash commands | `send_command`, `start_process`, `start_listener`, Bash tool calls |
| Dim | Tool calls | Skill loads, state queries, file reads/writes, browser actions |

In dashboard mode, each pane header uses a rotating color palette (cyan, green, magenta, yellow) with the focused pane highlighted in reverse video.

### Output Format

The dashboard parses JSONL lines with `"type":"assistant"` and formats tool calls as compact one-liners:

| Format | Source |
|--------|--------|
| `SHELL[sid] command` | `send_command` |
| `LISTEN port=N label=X` | `start_listener` |
| `PROC command` | `start_process` |
| `BASH (description) command` | Bash tool |
| `SKILL get_skill(name)` | skill-router calls |
| `STATE get_summary` | state-server calls |
| `BROWSER navigate(url=...)` | browser-server calls |
| `READ/WRITE/EDIT path` | Built-in file tools |

## Transcript Capture

Every agent's full JSONL transcript is automatically saved to `engagement/evidence/logs/` when the agent finishes. This is the accountability layer — the dashboard shows you what agents are doing in real time, and transcripts give you a permanent record of every tool call, command, and decision each agent made.

A `SubagentStop` hook (`tools/hooks/save-agent-log.sh`) handles this automatically:

1. Claude Code fires the `SubagentStop` event when any agent finishes
2. The hook reads `agent_transcript_path` and `agent_type` from the event JSON
3. Copies the transcript to `engagement/evidence/logs/{timestamp}-{agent-type}.jsonl`

Only red-run agents are captured (network-recon, web-discovery, web-exploit, ad-discovery, ad-exploit, password-spray, linux-privesc, windows-privesc, evasion, credential-cracking). Built-in subagents (Explore, Plan, general-purpose) are ignored.

No engagement directory = hook exits silently. The retrospective skill parses these logs for post-engagement analysis.

## Event Watcher

The event watcher (`tools/hooks/event-watcher.sh`) acts as a push notification from discovery agents to the orchestrator. The orchestrator spawns one alongside every discovery agent as a background process.

**How it works:**

1. The orchestrator spawns `event-watcher.sh` with `run_in_background: true` alongside a discovery agent
2. The script polls `state_events` every 5 seconds for new rows
3. When a discovery agent writes an interim finding (credential, vuln, pivot, blocked), a new row appears
4. The watcher detects the change, waits 5 seconds (debounce to let the agent finish its batch), outputs the events as JSON, and **exits**
5. The process termination notifies the orchestrator, which checks the database for the new findings and can route accordingly — e.g., spraying newly discovered credentials against other targets

Without this, the orchestrator would have to continuously poll the database itself between agent turns, wasting tokens on repeated `poll_events()` calls that usually return nothing.

**Usage:**

```bash
# Spawned by orchestrator with run_in_background: true
bash tools/hooks/event-watcher.sh <cursor> <db_path>
```

**Parameters:**

- `cursor` — last `state_events` ID seen (events with `id > cursor` are new)
- `db_path` — path to `engagement/state.db`
- 10-minute timeout prevents zombie watchers if no events arrive

> **Note:** The event watcher uses Python 3's built-in `sqlite3` module. No sqlite3 CLI binary is required.

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
