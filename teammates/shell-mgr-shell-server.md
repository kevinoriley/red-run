# Shell-Server Backend Appendix

This appendix configures you to use **shell-server MCP** as the shell backend.
shell-server manages raw TCP listeners for reverse shells and PTY-wrapped
local processes for interactive tools.

## Backend Tools

All tools are on the `shell-server` MCP: `mcp__shell-server__<tool>`.

## [shell-established] Implementation

When a teammate hands you an established shell:

```
1. Verify session exists: call list_sessions(), confirm session_id is active
2. Stabilize (Linux only): call stabilize_shell(session_id)
3. Save delivery payload in your internal map for recovery
4. Send [session-ready] to teammate and lead
```

## [setup-process] Implementation

For credential-based access:

```
Call mcp__shell-server__start_process(
  command="<cmd>", label="<label>",
  privileged=<bool>, startup_delay=<N>)

Send [process-ready] to teammate. Send [session-ready] to lead.
```

**privileged=true** → Docker container (evil-winrm, impacket, chisel, etc.)
**startup_delay=30** for evil-winrm (slow auth), 2 (default) for most tools.

## [shell-dropped] Recovery

When re-establishing a dropped shell:

```
1. Call mcp__shell-server__start_listener(port=<new_port>, label="<label>")
2. Build callback from saved delivery payload + new listener's payloads
3. Execute delivery via Bash (dangerouslyDisableSandbox: true)
4. Poll list_sessions() for new session (3s intervals, 5 attempts)
5. If connected: stabilize_shell(), send [session-restored]
6. If failed: retry with different port, up to 3 total attempts
7. If all fail: send [session-dead]
```

## Handoff Instructions

In [session-ready] messages, include:
```
[session-ready] session_id=<id> backend=shell-server platform=<linux|windows>
  Use mcp__shell-server__send_command(session_id="<id>", command="...") for interaction.
  Use mcp__shell-server__read_output(session_id="<id>") for buffered output.
```

## Callback IP Resolution

shell-server auto-resolves callback IP from: config.yaml `callback_ip` >
`callback_interface` > tun0 > wg0 > first non-loopback.
