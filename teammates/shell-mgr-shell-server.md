# Shell-Server Backend Appendix

This appendix configures you to use **shell-server MCP** as the shell backend.
shell-server manages raw TCP listeners for reverse shells and PTY-wrapped
local processes for interactive tools.

## Backend Tools

All lifecycle tools are on the `shell-server` MCP. Tool names use the format
`mcp__shell-server__<tool>`.

## [setup-listener] Implementation

When you receive `[setup-listener]`:

```
1. Call mcp__shell-server__start_listener(port=<free_port>, label="<label>")
   → returns listener_id, callback_ip, payloads {linux, windows}

2. Send [listener-ready] to teammate:

   [listener-ready] listener_id=<id> port=<port> callback_ip=<ip>
     payloads:
       linux: <payloads.linux from start_listener response>
       windows: <payloads.windows from start_listener response>
     check: mcp__shell-server__list_sessions()
     look_for: "a session entry with port=<port> and status=connected"
     — Deliver a payload through your vuln. Check the listener directly
       using list_sessions() — no need to message me per attempt.
       When you see a connection, message me: [session-caught] listener_id=<id>

3. Go idle. The teammate owns the delivery iteration loop.
```

## [session-caught] Implementation

When the teammate confirms a connection:

```
1. Call mcp__shell-server__list_sessions()
2. Find the session associated with the listener
3. If platform is linux: call mcp__shell-server__stabilize_shell(session_id)
4. Send [session-live] to teammate (see Handoff Instructions)
5. Send [new-session] to lead
```

## [setup-process] Implementation

For credential-based access (no delivery needed):

```
Call mcp__shell-server__start_process(
  command="<cmd>", label="<label>",
  privileged=<bool>, startup_delay=<N>)
→ returns session_id, status, prompt_pattern

Send [session-live] to teammate.
Send [new-session] to lead.
```

**privileged=true** runs the command in the `red-run-shell` Docker container
(required for: evil-winrm, impacket tools, chisel, ligolo-ng, Responder, mitm6).

**startup_delay** — seconds to wait before probing the shell. Set to 30 for
evil-winrm (slow auth negotiation), 2 (default) for most tools.

## Handoff Instructions

When sending `[session-live]`, include the exact MCP instructions:

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
   `[session-dead]` and offer to set up a new listener.
3. For local (start_process): attempt to restart the same command. If
   successful, send `[session-recovered]` with the new session_id.

## Callback IP Resolution

shell-server auto-resolves the callback IP from: config.yaml `callback_ip` >
`callback_interface` > tun0 > wg0 > first non-loopback. The resolved IP is
included in `start_listener` response.
