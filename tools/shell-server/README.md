# shell MCP Server

MCP server managing TCP listeners, reverse shell sessions, and local interactive
processes for red-run agents. Solves the persistent shell problem — Claude
Code's Bash tool runs each command as a separate process, so interactive shells,
privilege escalation tools, and credential-based access tools (evil-winrm,
psexec.py, ssh, msfconsole) have no way to maintain state between calls.

## Prerequisites

### Install Python dependencies

```bash
uv sync --directory tools/shell-server
```

No sudo or special system configuration required. The server binds TCP
listeners as the current user.

### Docker pentest toolbox (recommended)

The Docker image contains a full pentest toolkit for interactive sessions:
evil-winrm, impacket (psexec/wmiexec/smbexec/smbclient/mssqlclient), chisel,
ligolo-ng, socat, Responder, mitm6, and tcpdump.

```bash
docker build -t red-run-shell:latest tools/shell-server/
```

The install script builds this automatically when Docker is available.

Tools in the image are accessed via `start_process(command=..., privileged=True)`.
This is required for tools not installed on the host (evil-winrm, chisel,
ligolo-ng) and for daemons needing raw sockets (Responder, mitm6).

## Usage

The server runs as an MCP server, started automatically by Claude Code via
`.mcp.json`. To test manually:

```bash
uv run --directory tools/shell-server python server.py
```

### Reverse shell workflow

1. Agent calls `start_listener(port=4444)` to open a TCP listener
2. Agent sends a reverse shell payload through whatever RCE it has achieved
3. Target connects back — session is created automatically
4. Agent calls `stabilize_shell(session_id=...)` to upgrade to interactive PTY
5. Agent uses `send_command(session_id=..., command="id")` to interact
6. Agent calls `close_session(session_id=...)` when done — transcript saved

### Local interactive process workflow

1. Agent calls `start_process(command="evil-winrm -i 10.10.10.5 -u admin -p pass")` to spawn a local tool in a persistent PTY
2. Agent uses `send_command(session_id=..., command="whoami")` to interact — same as a reverse shell session
3. Agent calls `close_session(session_id=...)` when done — transcript saved

Works with any interactive CLI tool: `evil-winrm`, `psexec.py`, `ssh`,
`msfconsole`, `smbclient`, `mysql`, `impacket-wmiexec`, etc.

## Tools

| Tool | Parameters | Description |
|------|-----------|-------------|
| `start_listener` | `port` (required), `host` (default `0.0.0.0`), `timeout` (default 300s), `label` (optional) | Start TCP listener, wait for reverse shell |
| `start_process` | `command` (required), `label` (optional), `timeout` (default 30s), `privileged` (default false) | Spawn a local interactive process in a persistent PTY |
| `send_command` | `session_id` (required), `command` (required), `timeout` (default 10s), `expect` (optional regex) | Send command and return output |
| `read_output` | `session_id` (required), `timeout` (default 2s) | Read buffered output without sending a command |
| `stabilize_shell` | `session_id` (required), `method` (default `auto`) | Upgrade raw shell to PTY (python3/python2/script) |
| `list_sessions` | (none) | List all listeners and sessions with status |
| `close_session` | `session_id` (required), `save_transcript` (default true) | Close session, optionally save transcript |

## Docker mode (`privileged=True`)

The `privileged` parameter runs the command inside the `red-run-shell` Docker
container. Use it for two cases:

1. **Docker-only tools** — evil-winrm, chisel, ligolo-ng, socat (not installed
   on the host, only in the Docker image)
2. **Raw socket tools** — Responder, mitm6, tcpdump (need NET_RAW/NET_ADMIN)

```python
# Docker-only tools
start_process(command="evil-winrm -i 10.10.10.5 -u admin -p pass", privileged=True)
start_process(command="chisel server --reverse --port 8080", privileged=True)
start_process(command="ligolo-proxy -selfcert", privileged=True)

# Raw socket daemons
start_process(command="python3 -u /opt/Responder/Responder.py -I tun0 -v", privileged=True)
start_process(command="mitm6 -d target.local", privileged=True)

# Host tools (no Docker needed)
start_process(command="ssh user@target")
start_process(command="msfconsole -q")
```

**What happens:**
- Command is wrapped in `docker run --rm -i --network=host --name red-run-<session_id>
  --cap-drop=ALL --cap-add=NET_RAW --cap-add=NET_ADMIN --cap-add=NET_BIND_SERVICE`
- Uses `-i` only (not `-it`) — the host PTY provides terminal behavior
- `--network=host` shares the host's full network namespace (including tun0/VPN)
- The PTY setup, prompt detection, and cleanup all work unchanged
- `close_session()` runs `docker kill` on the named container before killing the
  process — ensures the container is cleaned up even if SIGTERM to the docker CLI
  doesn't propagate

**Tools in the Docker image:**
- evil-winrm (Ruby gem)
- impacket (psexec.py, wmiexec.py, smbexec.py, smbclient.py, mssqlclient.py, etc.)
- chisel (TCP/UDP tunnel for pivoting)
- ligolo-ng proxy (TUN-based pivot proxy)
- socat (port forwarding)
- Responder (LLMNR/NBT-NS/mDNS poisoner)
- mitm6 (IPv6 DHCP poisoning)
- tcpdump (packet capture)
- openssh-client (ssh, scp)

**Capabilities granted:**
- `NET_RAW` — raw sockets (Responder, tcpdump, scapy)
- `NET_ADMIN` — network interface control (mitm6)
- `NET_BIND_SERVICE` — bind ports below 1024

**Environment variable:** `SHELL_DOCKER_IMAGE` overrides the default image name
(`red-run-shell:latest`).

**VPN note:** `--network=host` shares the host's full network namespace
including tun0. Responder and mitm6 should work over VPN, but this needs
empirical verification per environment.

**Responder in Docker:** Python buffers stdout when not connected to a TTY,
causing `read_output` to return nothing even when Responder has captured
hashes. Always use `python3 -u` (unbuffered) when launching Responder:
```python
start_process(command="python3 -u /opt/Responder/Responder.py -I tun0 -v", privileged=True)
```
Alternatively, run Responder in the background and poll its log file instead
of reading stdout — logs are written to `/opt/Responder/logs/` inside the
container:
```python
# Start Responder backgrounded, then check logs
start_process(command="python3 /opt/Responder/Responder.py -I tun0 -v", privileged=True)
send_command(session_id="...", command="ls /opt/Responder/logs/")
send_command(session_id="...", command="cat /opt/Responder/logs/Responder-Session.log")
```

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

Every send/recv is logged in real-time to a live log file at
`engagement/evidence/shell-{id}-{label}.log` (if the engagement directory
exists). The file is created when the session starts and appended to on every
send/recv — suitable for `tail -f` and dashboard tailing. The `live_log` path
is returned in the `start_process` and `list_sessions` responses.

On `close_session(save_transcript=true)`, the live log path is returned as the
transcript path (no duplicate write needed).
