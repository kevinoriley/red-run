"""MCP server managing TCP listeners and reverse shell sessions.

Provides six tools:
- start_listener: Start TCP listener, wait for reverse shell connection
- send_command: Send command to session, return output
- read_output: Read buffered output without sending a command
- stabilize_shell: Upgrade raw shell to interactive PTY
- list_sessions: List all listeners and sessions
- close_session: Close session/listener, optionally save transcript

Solves the persistent shell problem — Claude Code's Bash tool runs each command
as a separate process, so interactive reverse shells and privesc tools that
spawn new shells (PwnKit, kernel exploits) have no way to connect back. This
server manages long-lived TCP sessions that persist across tool calls.

Usage:
    uv run python server.py
"""

from __future__ import annotations

import atexit
import json
import re
import select
import socket
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from mcp.server.fastmcp import FastMCP

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
    conn: socket.socket
    remote_addr: tuple[str, int]
    port: int
    label: str
    pty: bool = False
    prompt_pattern: str = ""
    status: str = "connected"  # "connected" | "stabilized" | "closed"
    connected_at: datetime = field(default_factory=lambda: datetime.now(tz=timezone.utc))
    transcript: list[tuple[str, str, str]] = field(default_factory=list)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def log(self, direction: str, data: str) -> None:
        ts = datetime.now(tz=timezone.utc).isoformat()
        self.transcript.append((ts, direction, data))

    def send(self, data: str) -> None:
        self.conn.sendall(data.encode())
        self.log("send", data)

    def recv(self, timeout: float = DEFAULT_READ_TIMEOUT) -> str:
        """Read available data from socket with timeout."""
        chunks: list[str] = []
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            ready, _, _ = select.select([self.conn], [], [], min(remaining, 0.5))
            if not ready:
                # If we already have data and nothing more is coming, return it
                if chunks:
                    break
                continue
            try:
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
        """Drain any pending output from the socket."""
        return self.recv(timeout=timeout)


def _detect_prompt(session: Session) -> str:
    """Probe the shell to detect its prompt pattern."""
    session.drain(timeout=1.0)
    session.send(f"{PROBE_COMMAND}\n")
    time.sleep(1.0)
    output = session.recv(timeout=3.0)

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
    mcp = FastMCP(
        "red-run-shell-server",
        instructions=(
            "Manages TCP listeners and reverse shell sessions for red-run "
            "subagents. Use start_listener to catch reverse shells, "
            "send_command to execute commands in sessions, stabilize_shell "
            "to upgrade to PTY, and close_session to clean up."
        ),
    )

    listeners: dict[str, Listener] = {}
    sessions: dict[str, Session] = {}

    def _cleanup() -> None:
        """Close all sockets on exit."""
        for session in sessions.values():
            try:
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
                session_id = str(uuid.uuid4())[:8]
                session = Session(
                    session_id=session_id,
                    conn=conn,
                    remote_addr=addr,
                    port=listener.port,
                    label=listener.label,
                )

                sessions[session_id] = session
                listener.session_id = session_id
                listener.status = "connected"

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

        return json.dumps({
            "listener_id": listener_id,
            "status": "listening",
            "address": f"{host}:{port}",
            "timeout": timeout,
            "label": listener.label,
            "message": (
                f"Listening on {host}:{port}. Send a reverse shell payload to "
                f"this port, then call list_sessions() to check for connections. "
                f"Listener will timeout after {timeout}s if no connection arrives."
            ),
        }, indent=2)

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
            session_id: Session ID from start_listener or list_sessions.
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

        with session._lock:
            # Drain any leftover output
            session.drain(timeout=0.3)

            if session.pty:
                # PTY shell — send command directly and wait for prompt
                session.send(f"{command}\n")
                output = _read_until_prompt(session, timeout, expect)
            else:
                # Raw shell — use markers to delimit output
                wrapped = (
                    f"echo {MARKER_START}; {command}; echo {MARKER_END}\n"
                )
                session.send(wrapped)
                output = _read_until_marker(session, timeout, expect)

            return output

    def _read_until_prompt(
        session: Session, timeout: float, expect: str
    ) -> str:
        """Read output until prompt pattern is detected or timeout."""
        chunks: list[str] = []
        deadline = time.monotonic() + timeout
        prompt_re = re.compile(session.prompt_pattern) if session.prompt_pattern else None
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

        # Strip the echoed command from the first line
        lines = result.split("\n")
        if lines and lines[0].strip().endswith(session_id if False else ""):
            lines = lines[1:]

        return result.strip()

    def _read_until_marker(
        session: Session, timeout: float, expect: str
    ) -> str:
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
                if MARKER_END in combined:
                    break
                if expect_re and expect_re.search(combined):
                    break
            elif chunks and MARKER_START in "".join(chunks):
                # We have the start marker but no more data — give it a moment
                time.sleep(0.2)

        combined = "".join(chunks)

        # Extract content between markers
        start_idx = combined.find(MARKER_START)
        end_idx = combined.find(MARKER_END)

        if start_idx != -1 and end_idx != -1:
            # Get content between markers, skip the marker line itself
            content = combined[start_idx + len(MARKER_START):end_idx]
            return content.strip()
        elif start_idx != -1:
            # Got start marker but not end — return what we have
            content = combined[start_idx + len(MARKER_START):]
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
            return f"ERROR: Unknown method '{method}'. Use: auto, python3, python2, script"

        with session._lock:
            for name, cmd in methods_to_try:
                session.drain(timeout=0.5)
                session.send(f"{cmd}\n")
                time.sleep(1.5)
                output = session.drain(timeout=2.0)

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

                    return json.dumps({
                        "status": "stabilized",
                        "method": name,
                        "session_id": session_id,
                        "prompt_pattern": prompt,
                        "message": (
                            f"Shell stabilized via {name}. PTY active, "
                            f"TERM=xterm-256color. Use send_command() for "
                            f"interactive commands."
                        ),
                    }, indent=2)

            return json.dumps({
                "status": "failed",
                "session_id": session_id,
                "tried": [name for name, _ in methods_to_try],
                "message": (
                    "Could not stabilize shell — none of the PTY methods "
                    "succeeded. The shell is still usable via send_command() "
                    "with marker-based output capture, but interactive programs "
                    "(sudo, su, ssh) may not work correctly."
                ),
            }, indent=2)

    @mcp.tool()
    def list_sessions() -> str:
        """List all listeners and sessions with status.

        Returns a summary of all active listeners (waiting for connections)
        and all shell sessions (connected, stabilized, or closed).
        """
        result: dict = {"listeners": [], "sessions": []}

        for lid, listener in listeners.items():
            result["listeners"].append({
                "listener_id": lid,
                "port": listener.port,
                "host": listener.host,
                "status": listener.status,
                "label": listener.label,
                "started_at": listener.started_at.isoformat(),
                "session_id": listener.session_id,
            })

        for sid, session in sessions.items():
            result["sessions"].append({
                "session_id": sid,
                "remote_addr": f"{session.remote_addr[0]}:{session.remote_addr[1]}",
                "port": session.port,
                "label": session.label,
                "status": session.status,
                "pty": session.pty,
                "connected_at": session.connected_at.isoformat(),
                "transcript_lines": len(session.transcript),
            })

        if not result["listeners"] and not result["sessions"]:
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
                evidence_dir = _PROJECT_ROOT / "engagement" / "evidence"
                if evidence_dir.exists():
                    safe_label = re.sub(r"[^a-zA-Z0-9_-]", "_", session.label)
                    filename = f"shell-{session_id}-{safe_label}.log"
                    transcript_path = evidence_dir / filename
                    _save_transcript(session, transcript_path)

            try:
                session.conn.close()
            except Exception:
                pass
            session.status = "closed"

            return json.dumps({
                "status": "closed",
                "session_id": session_id,
                "transcript_saved": str(transcript_path) if transcript_path else None,
                "transcript_lines": len(session.transcript),
            }, indent=2)

        # Check if it's a listener
        if session_id in listeners:
            listener = listeners[session_id]
            try:
                listener.sock.close()
            except Exception:
                pass
            listener.status = "closed"
            return json.dumps({
                "status": "closed",
                "listener_id": session_id,
                "message": "Listener closed.",
            }, indent=2)

        available = list(sessions.keys()) + list(listeners.keys())
        return f"ERROR: '{session_id}' not found. Available: {', '.join(available) or 'none'}"

    def _save_transcript(session: Session, path: Path) -> None:
        """Write session transcript to a log file."""
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w") as f:
            f.write(f"# Shell Transcript — {session.label}\n")
            f.write(f"# Remote: {session.remote_addr[0]}:{session.remote_addr[1]}\n")
            f.write(f"# Port: {session.port}\n")
            f.write(f"# Connected: {session.connected_at.isoformat()}\n")
            f.write(f"# PTY: {session.pty}\n")
            f.write(f"# Lines: {len(session.transcript)}\n\n")

            for ts, direction, data in session.transcript:
                prefix = ">>>" if direction == "send" else "<<<"
                f.write(f"[{ts}] {prefix}\n{data}\n\n")

    return mcp


def main() -> None:
    server = create_server()
    server.run()


if __name__ == "__main__":
    main()
