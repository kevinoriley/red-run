# Agent Dashboard

Live-tail and multi-pane dashboard for monitoring Claude Code agent JSONL output.
Parses Claude Code's raw JSONL transcript format and displays agent reasoning,
shell commands, and tool calls with color-coded formatting.

Also available as a standalone tool: [agentsee](https://github.com/blacklanternsecurity/agentsee)

## Prerequisites

- Python 3.10+
- No additional dependencies (uses only stdlib: `curses`, `json`, `textwrap`,
  `threading`)

## Usage

### Single-agent modes

```bash
# One-shot: print formatted output and exit
python3 operator/agent-dashboard/tail-agent.py <output_file>

# Follow: live-tail like tail -f (Ctrl-C to stop)
python3 operator/agent-dashboard/tail-agent.py -f <output_file>

# Pipe: read from stdin
tail -f <output_file> | python3 operator/agent-dashboard/tail-agent.py
```

### Multi-agent dashboard mode

Curses-based split-pane view showing multiple agents side by side.
The dashboard auto-discovers new agents from Claude Code's tasks directory
and subagent JSONL directories. When an agent completes, its pane shows
a "stopped" indicator. Completed agents are accessible via the agent
browser (`b`). If no agents are active, the dashboard shows "Waiting for
agents..." until one spawns.

```bash
# Auto-discover agents (recommended)
python3 operator/agent-dashboard/tail-agent.py --dashboard

# Explicit label:path pairs
python3 operator/agent-dashboard/tail-agent.py --dashboard web:path1 ad:path2
```

### Dashboard wrapper script

`dashboard.sh` auto-detects the tasks directory for the current project:

```bash
bash operator/agent-dashboard/dashboard.sh

# With extra agents appended
bash operator/agent-dashboard/dashboard.sh extra-label:/tmp/.../extra.output
```

## Keybindings

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
| `d` | Dismiss focused pane (double-tap within 2s to confirm) |
| `b` | Open agent browser — add completed agents back to the dashboard |
| `q` / `Ctrl-C` | Quit |

The status bar shows `LIVE` when auto-following or `scrolled +N` when
scrolled up. Scrolling to the bottom re-enables live follow.

### Agent browser

Press `b` to open a modal overlay listing all agent output files from the
current session's tasks directory, sorted by most recent first. The browser
extracts skill names from agent JSONL transcripts for readable labels.

| Key | Action (in browser) |
|-----|---------------------|
| `j` / `Down` | Move cursor down |
| `k` / `Up` | Move cursor up |
| `Enter` | Add selected agent as a new pane |
| `b` / `Escape` | Close browser |

This lets you review completed agents that have already left the dashboard,
or re-add dismissed panes. The `--tasks-dir` flag (auto-set by `dashboard.sh`)
controls where the browser looks for output files.

### Purging agent history

To wipe all agent transcripts for the current project so they no longer
appear in the dashboard or browser:

```bash
bash dashboard.sh --purge
```

This deletes all `subagents/` directories under `~/.claude/projects/` for
the current project. Prompts for confirmation before deleting.

## Color coding

| Color | Category | Content |
|-------|----------|---------|
| Cyan | Agent reasoning | Text output from the agent's thinking |
| Yellow (bold, `▶` prefix) | Shell/Bash commands | `send_command`, `start_process`, `start_listener`, Bash tool calls |
| Dim | Tool calls | Skill loads, state queries, file reads/writes, browser actions, other MCP calls |

In single-agent mode, the same color scheme applies to terminal ANSI output.
In dashboard mode, each pane header is colored from a rotating palette (cyan,
green, magenta, yellow) with the focused pane highlighted in reverse video.

## Output format

The dashboard parses JSONL lines with `"type":"assistant"` and extracts:

- **Text blocks** → displayed as cyan agent reasoning
- **tool_use blocks** → formatted as compact one-liners:
  - `SHELL[sid] command` — shell-server send_command
  - `LISTEN port=N` — shell-server start_listener
  - `PROC command` — shell-server start_process
  - `BASH (description) command` — Bash tool
  - `SKILL get_skill(name)` — skill-router calls
  - `STATE get_summary` — state-server calls
  - `BROWSER navigate(url=...)` — browser-server calls
  - `READ/WRITE/EDIT/GREP/GLOB path` — built-in file tools
