# Shell-Server Backend Appendix

This appendix configures you to use **shell-server MCP** as the shell backend.
shell-server manages raw TCP listeners for reverse shells and PTY-wrapped
local processes for interactive tools.

## Backend Tools

All lifecycle tools are on the `shell-server` MCP. Tool names use the format
`mcp__shell-server__<tool>`.

## [establish-shell] Implementation

When you receive `[establish-shell]`:

```
1. Call mcp__shell-server__start_listener(port=<free_port>, label="<label>")
   → returns listener_id, callback_ip, payloads {linux, windows}

2. Pick the right payload for the platform:
   - linux: payloads.linux (bash reverse shell)
   - windows: payloads.windows (PowerShell with AMSI bypass)

3. Replace {CALLBACK} in the delivery command with the payload
   IMPORTANT: the payload may contain special chars. If the delivery
   command wraps {CALLBACK} in quotes, ensure proper escaping.

4. Execute the delivery command via Bash (dangerouslyDisableSandbox: true)

5. Poll mcp__shell-server__list_sessions() for a new session on that listener
   - Check every 3 seconds, up to 5 attempts (15 seconds total)
   - Look for a session with matching listener port

6. If session found:
   a. Platform is linux → call mcp__shell-server__stabilize_shell(session_id)
   b. Send [session-live] to teammate (see Handoff Instructions below)
   c. Send [new-session] to lead

7. If no session after timeout:
   a. Send [session-failed] to teammate with what was attempted
```

## [setup-process] Implementation

For credential-based access (no delivery needed):

```
Call mcp__shell-server__start_process(
  command="<cmd>", label="<label>",
  privileged=<bool>, startup_delay=<N>)
→ returns session_id, status, prompt_pattern

Send [session-live] to teammate.
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
   `[session-dead]` and suggest the teammate resend `[establish-shell]`.
3. For local (start_process): attempt to restart the same command. If
   successful, send `[session-recovered]` with the new session_id.

## Callback IP Resolution

shell-server auto-resolves the callback IP from: config.yaml `callback_ip` >
`callback_interface` > tun0 > wg0 > first non-loopback. The resolved IP is
included in `start_listener` response.
