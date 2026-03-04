# Agent Dashboard

Live-tail and multi-pane dashboard for monitoring red-run agent JSONL output.
Parses Claude Code's raw JSONL transcript format and displays agent reasoning,
shell commands, and tool calls with color-coded formatting.

## Prerequisites

- Python 3.10+
- No additional dependencies (uses only stdlib: `curses`, `json`, `textwrap`,
  `threading`)

## Usage

### Single-agent modes

```bash
# One-shot: print formatted output and exit
python3 tools/agent-dashboard/tail-agent.py <output_file>

# Follow: live-tail like tail -f (Ctrl-C to stop)
python3 tools/agent-dashboard/tail-agent.py -f <output_file>

# Pipe: read from stdin
tail -f <output_file> | python3 tools/agent-dashboard/tail-agent.py
```

### Multi-agent dashboard mode

Curses-based split-pane view showing multiple agents side by side:

```bash
# Explicit label:path pairs
python3 tools/agent-dashboard/tail-agent.py --dashboard web:path1 ad:path2

# From a .dashboard file (hot-reloaded)
python3 tools/agent-dashboard/tail-agent.py --dashboard --from .dashboard

# Mix both — file + extra agents
python3 tools/agent-dashboard/tail-agent.py --dashboard --from .dashboard extra:path
```

### Dashboard wrapper script

`dashboard.sh` reads from `tools/agent-dashboard/.dashboard` by default:

```bash
bash tools/agent-dashboard/dashboard.sh

# With extra agents appended
bash tools/agent-dashboard/dashboard.sh extra-label:/tmp/.../extra.output
```

The orchestrator writes the `.dashboard` file when launching parallel
background agents.

## .dashboard file format

One agent per line as `label:path`. Blank lines and `#` comments are ignored.

```
# Discovery agents
web-discovery:/tmp/claude-1000/web-discovery.output
network-recon:/tmp/claude-1000/network-recon.output

# Exploit agents
ad-exploit:/tmp/claude-1000/ad-exploit.output
```

The dashboard hot-reloads this file every ~1 second — panes are added and
removed dynamically as entries change. The dashboard stays open even when the
file is empty, showing "Waiting for agents..." until entries appear.

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
| `q` / `Ctrl-C` | Quit |

The status bar shows `LIVE` when auto-following or `scrolled +N` when
scrolled up. Scrolling to the bottom re-enables live follow.

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
