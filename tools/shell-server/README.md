# shell MCP Server

MCP server managing TCP listeners and reverse shell sessions for red-run
subagents. Solves the persistent shell problem — Claude Code's Bash tool runs
each command as a separate process, so interactive reverse shells and privilege
escalation tools that spawn new shells have no way to connect back.

## Prerequisites

### Install Python dependencies

```bash
uv sync --directory tools/shell-server
```

No sudo or special system configuration required. The server binds TCP
listeners as the current user.

## Usage

The server runs as an MCP server, started automatically by Claude Code via
`.mcp.json`. To test manually:

```bash
uv run --directory tools/shell-server python server.py
```

### Typical workflow

1. Agent calls `start_listener(port=4444)` to open a TCP listener
2. Agent sends a reverse shell payload through whatever RCE it has achieved
3. Target connects back — session is created automatically
4. Agent calls `stabilize_shell(session_id=...)` to upgrade to interactive PTY
5. Agent uses `send_command(session_id=..., command="id")` to interact
6. Agent calls `close_session(session_id=...)` when done — transcript saved

## Tools

| Tool | Parameters | Description |
|------|-----------|-------------|
| `start_listener` | `port` (required), `host` (default `0.0.0.0`), `timeout` (default 300s), `label` (optional) | Start TCP listener, wait for reverse shell |
| `send_command` | `session_id` (required), `command` (required), `timeout` (default 10s), `expect` (optional regex) | Send command and return output |
| `read_output` | `session_id` (required), `timeout` (default 2s) | Read buffered output without sending a command |
| `stabilize_shell` | `session_id` (required), `method` (default `auto`) | Upgrade raw shell to PTY (python3/python2/script) |
| `list_sessions` | (none) | List all listeners and sessions with status |
| `close_session` | `session_id` (required), `save_transcript` (default true) | Close session, optionally save transcript |

## Shell stabilization

`stabilize_shell` tries three methods in order (configurable via `method`):

1. **python3** — `python3 -c 'import pty; pty.spawn("/bin/bash")'`
2. **python2** — `python -c 'import pty; pty.spawn("/bin/bash")'`
3. **script** — `script -qc /bin/bash /dev/null`

After stabilization, sets `TERM=xterm-256color` and `stty rows 50 columns 200`
for proper terminal behavior.

## Output handling

- **PTY shells** (stabilized): Prompt detection — reads until the shell prompt
  pattern is matched or timeout.
- **Raw shells** (not stabilized): Marker-based — wraps commands with unique
  start/end markers and reads between them.

## Transcripts

Every send/recv is logged in memory. On `close_session(save_transcript=true)`,
the full transcript is written to `engagement/evidence/shell-{id}-{label}.log`
(if the engagement directory exists).
