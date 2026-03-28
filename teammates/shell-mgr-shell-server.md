# Shell-Server Backend Appendix

This appendix configures you to use **shell-server MCP** as the shell backend.
shell-server manages raw TCP listeners for reverse shells and PTY-wrapped
local processes for interactive tools.

## Backend Tools

All lifecycle tools are on the `shell-server` MCP. Tool names use the format
`mcp__shell-server__<tool>`.

### start_listener(port, host, timeout, label)

Binds a TCP socket and waits for one reverse shell connection. Returns
pre-generated callback payloads for Linux (bash) and Windows (PowerShell with
AMSI bypass).

```
[setup-listener] → call:
  mcp__shell-server__start_listener(port=<N>, label="<label>", timeout=<timeout>)
Returns: listener_id, callback_ip, payloads {linux, windows}

Send to teammate:
  [listener-ready] listener_id=<id> port=<N> callback_ip=<ip>
    payloads={linux: "<payload>", windows: "<payload>"}
```

When the teammate messages `[payload-delivered] listener_id=<id>`:
1. Call `list_sessions()` — check if the listener spawned a session
2. If session exists: call `stabilize_shell()` (Linux), then send `[session-live]`
3. If no session yet: wait a few seconds, poll again (up to 3 attempts)
4. If still no session: send `[session-dead]` — payload may have failed

### start_process(command, label, timeout, privileged, startup_delay)

Spawns a local interactive process in a PTY. Use for credential-based access
tools (evil-winrm, ssh, psexec.py) and interactive tools (msfconsole).

```
[setup-process] → call:
  mcp__shell-server__start_process(
    command="<cmd>", label="<label>",
    privileged=<bool>, startup_delay=<N>)
Returns: session_id, status, prompt_pattern

Send to teammate:
  [session-live] session_id=<id> backend=shell-server platform=<detected>
    Use mcp__shell-server__send_command(session_id="<id>", command="...") for interaction.
```

**privileged=true** runs the command in the `red-run-shell` Docker container
(required for: evil-winrm, impacket tools, chisel, ligolo-ng, Responder, mitm6).

**startup_delay** — seconds to wait before probing the shell. Set to 30 for
evil-winrm (slow auth negotiation), 2 (default) for most tools.

### stabilize_shell(session_id, method)

Upgrades a raw reverse shell to interactive PTY. Linux only — skips on Windows.

```
[upgrade-shell] → call:
  mcp__shell-server__stabilize_shell(session_id="<id>")
Returns: status (stabilized | skipped | failed), method used

Send to teammate:
  [session-upgraded] session_id=<id> method=<method>
```

Methods tried in order: python3 pty.spawn, python2, script -qc.

### list_sessions()

Returns all active listeners and sessions with metadata.

```
[list-sessions] → call:
  mcp__shell-server__list_sessions()
Returns: {listeners: [...], sessions: [...]}
```

### close_session(session_id, save_transcript)

Kills the process/socket, optionally saves transcript.

```
[close-session] → call:
  mcp__shell-server__close_session(session_id="<id>", save_transcript=<bool>)
Returns: status, transcript path

Send to teammate:
  [session-closed] session_id=<id> transcript=<path>
```

## Handoff Instructions

When sending `[session-live]`, include this exact MCP instruction so the
receiving teammate knows how to interact:

```
[session-live] session_id=<id> backend=shell-server platform=<linux|windows>
  Use mcp__shell-server__send_command(session_id="<id>", command="...") for interaction.
  Use mcp__shell-server__read_output(session_id="<id>") for buffered output.
  Close when done: message shell-mgr [close-session] session_id=<id> save_transcript=true
```

## Session Recovery

If `list_sessions()` shows a session as closed unexpectedly:
1. Check if the process exited (local) or socket disconnected (remote)
2. For remote: the listener is consumed — cannot auto-recover. Send
   `[session-dead]` and suggest a new listener.
3. For local (start_process): attempt to restart the same command. If
   successful, send `[session-recovered]` with the new session_id.

## Callback IP Resolution

shell-server auto-resolves the callback IP from: config.yaml `callback_ip` >
`callback_interface` > tun0 > wg0 > first non-loopback. The resolved IP is
included in `start_listener` response — pass it through in `[listener-ready]`.
