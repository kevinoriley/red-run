#!/usr/bin/env python3
"""Live-tail Claude Code agent output with clean formatting.

Usage:
    python3 tail-agent.py <output_file>              # one-shot (print and exit)
    python3 tail-agent.py -f <output_file>           # live follow (like tail -f)
    tail -f <output_file> | python3 tail-agent.py    # pipe mode
    python3 tail-agent.py --dashboard label1:path1   # multi-agent dashboard
    python3 tail-agent.py --dashboard                # auto-discover agents

Shows:
    Cyan    - agent reasoning text
    Yellow  - shell commands (▶ SHELL[session] command, ▶ BASH description)
    Green   - tool output (Bash results, shell-server responses)
    Dim     - other MCP tool calls, file reads/writes
"""

import curses
import glob as _glob
import json
import os
import queue
import re
import sys
import textwrap
import threading
import time


CYAN = "\033[36m"
YELLOW = "\033[33m"
DIM = "\033[2m"
RESET = "\033[0m"


def format_tool(name: str, inp: dict) -> tuple[str, str]:
    """Format a tool_use call into a compact one-liner."""
    if name == "mcp__shell-server__send_command":
        sid = inp.get("session_id", "")[:8]
        cmd = inp.get("command", "")
        return ("shell", f"SHELL[{sid}] {cmd}")
    if name == "mcp__shell-server__start_listener":
        return (
            "shell",
            f"LISTEN port={inp.get('port', '')} label={inp.get('label', '')}",
        )
    if name == "mcp__shell-server__start_process":
        return ("shell", f"PROC {inp.get('command', '')}")
    if name == "mcp__shell-server__read_output":
        return ("dim", f"READ[{inp.get('session_id', '')[:8]}]")
    if name == "mcp__shell-server__stabilize_shell":
        return ("dim", f"STABILIZE[{inp.get('session_id', '')[:8]}]")
    if "skill-router" in name:
        tool = name.split("__")[-1]
        args = ", ".join(str(v) for v in inp.values())
        return ("dim", f"SKILL {tool}({args})")
    if "state" in name:
        tool = name.split("__")[-1]
        return ("dim", f"STATE {tool}")
    if "browser" in name:
        tool = name.split("__")[-1]
        args = " ".join(f"{k}={str(v)[:60]}" for k, v in inp.items())
        return ("dim", f"BROWSER {tool}({args})")

    # Built-in Claude Code tools
    if name == "WebSearch":
        query = inp.get("query", "")
        return ("shell", f"SEARCH {query}")
    if name == "WebFetch":
        url = inp.get("url", "")
        return ("shell", f"FETCH {url}")
    if name == "Bash":
        cmd = inp.get("command", "")
        desc = inp.get("description", "")
        if desc:
            return ("shell", f"BASH ({desc}) {cmd}")
        return ("shell", f"BASH {cmd}")
    if name == "Read":
        return ("dim", f"READ {inp.get('file_path', '')}")
    if name == "Write":
        return ("dim", f"WRITE {inp.get('file_path', '')}")
    if name == "Edit":
        return ("dim", f"EDIT {inp.get('file_path', '')}")
    if name == "Grep":
        pattern = inp.get("pattern", "")
        path = inp.get("path", "")
        glob = inp.get("glob", "")
        suffix = f" (in {path or glob})" if path or glob else ""
        return ("dim", f"GREP {pattern}{suffix}")
    if name == "Glob":
        return ("dim", f"GLOB {inp.get('pattern', '')}")
    if name == "Agent":
        return ("dim", f"AGENT {inp.get('description', '')}")

    return ("dim", f"TOOL {name}")


# Tool IDs whose results should be rendered (Bash, shell-server commands)
_SHOW_RESULT_TOOLS = {
    "Bash",
    "mcp__shell-server__send_command",
    "mcp__shell-server__read_output",
    "mcp__shell-server__start_process",
    "mcp__shell-server__stabilize_shell",
}

# Regex to strip ANSI escape sequences (CSI sequences, cursor control, etc.)
_ANSI_RE = re.compile(r"\x1b\[[\x20-\x3f]*[\x40-\x7e]|\x1b[()][0-9A-B]|\x01|\x02")


def _clean_result(raw: str) -> str:
    """Extract readable content from a tool result string."""
    # Unwrap MCP JSON wrapper: {"result": "..."}
    if raw.startswith('{"result":'):
        try:
            obj = json.loads(raw)
            raw = obj.get("result", raw)
        except (json.JSONDecodeError, ValueError):
            pass
    # If it's still JSON (start_process response), extract key fields
    if raw.startswith("{"):
        try:
            obj = json.loads(raw)
            if "session_id" in obj:
                parts = [f"session={obj['session_id']}"]
                if obj.get("label"):
                    parts.append(obj["label"])
                if obj.get("message"):
                    parts.append(obj["message"])
                return " | ".join(parts)
        except (json.JSONDecodeError, ValueError):
            pass
    # Strip ANSI escapes and clean up
    clean = _ANSI_RE.sub("", raw)
    clean = clean.replace("\r\n", "\n").replace("\r", "\n")
    # Collapse redundant blank lines
    while "\n\n\n" in clean:
        clean = clean.replace("\n\n\n", "\n\n")
    return clean.strip()


def parse_line(line: str, pending: dict | None = None) -> list[tuple[str, str]]:
    """Parse a JSONL line and return list of (category, text) tuples.

    Args:
        pending: dict tracking tool_use_id -> tool_name for result rendering.
                 Mutated in-place across calls. Pass {} for stateful parsing.
    """
    if pending is None:
        pending = {}
    line = line.strip()
    if not line:
        return []
    try:
        obj = json.loads(line)
    except (json.JSONDecodeError, ValueError):
        return []

    msg_type = obj.get("type")
    results = []

    if msg_type == "assistant":
        for item in obj.get("message", {}).get("content", []):
            if not isinstance(item, dict):
                continue
            if item.get("type") == "text":
                text = item.get("text", "").strip()
                if text:
                    results.append(("text", text))
            elif item.get("type") == "tool_use":
                name = item.get("name", "")
                kind, msg = format_tool(name, item.get("input", {}))
                results.append((kind, msg))
                # Track tools whose output we want to display
                tool_id = item.get("id", "")
                if tool_id and name in _SHOW_RESULT_TOOLS:
                    pending[tool_id] = name

    elif msg_type == "user":
        for item in obj.get("message", {}).get("content", []):
            if not isinstance(item, dict):
                continue
            if item.get("type") == "tool_result":
                tid = item.get("tool_use_id", "")
                if tid in pending:
                    pending.pop(tid)
                    content = item.get("content", "")
                    if isinstance(content, str) and content.strip():
                        cleaned = _clean_result(content)
                        if cleaned:
                            results.append(("result", cleaned))

    return results


GREEN = "\033[32m"

# Shared pending state for non-dashboard mode
_cli_pending: dict = {}


def process_line(line: str) -> None:
    """Parse and print a single JSONL line (non-dashboard mode)."""
    for kind, msg in parse_line(line, _cli_pending):
        if kind == "text":
            print(f"{CYAN}{msg}{RESET}", flush=True)
        elif kind == "shell":
            print(f"{YELLOW}▶ {msg}{RESET}", flush=True)
        elif kind == "result":
            print(f"{GREEN}{msg}{RESET}", flush=True)
        else:
            print(f"{DIM}  {msg}{RESET}", flush=True)


# ---------------------------------------------------------------------------
# Dashboard mode (curses multi-agent view)
# ---------------------------------------------------------------------------

# Colors cycled per agent pane
PANE_COLORS = ["cyan", "green", "magenta", "yellow"]


def _curses_color_map() -> dict[str, int]:
    """Return color name -> curses constant map. Must be called after initscr."""
    return {
        "cyan": curses.COLOR_CYAN,
        "green": curses.COLOR_GREEN,
        "magenta": curses.COLOR_MAGENTA,
        "yellow": curses.COLOR_YELLOW,
    }


class AgentPane:
    """Manages one agent's column in the dashboard."""

    def __init__(self, label: str, filepath: str, color_idx: int):
        self.label = label
        self.filepath = filepath
        self.color_idx = color_idx  # index into PANE_COLORS
        self.lines: list[tuple[str, str]] = []  # (category, text)
        self.queue: queue.Queue = queue.Queue()
        self.scroll_offset: int = 0  # 0 = bottom (auto-follow), >0 = scrolled up
        self.auto_follow: bool = True  # snap to bottom on new content
        self._prev_wrapped_total: int = (
            0  # tracks wrapped line count for scroll anchoring
        )
        self.pending: dict = {}  # tool_use_id -> tool_name for result tracking


def tail_thread(pane: AgentPane, stop_event: threading.Event) -> None:
    """Background thread: read file, parse JSONL, push formatted lines."""
    # Wait for file to exist
    while not stop_event.is_set():
        if os.path.exists(pane.filepath):
            break
        time.sleep(0.5)

    if stop_event.is_set():
        return

    with open(pane.filepath) as f:
        while not stop_event.is_set():
            line = f.readline()
            if line:
                for kind, text in parse_line(line, pane.pending):
                    pane.queue.put((kind, text))
            else:
                time.sleep(0.3)


def _init_colors() -> dict[str, int]:
    """Initialize curses color pairs and return name -> pair_number map."""
    curses.start_color()
    curses.use_default_colors()
    cmap = _curses_color_map()
    pairs = {}
    for i, (name, color) in enumerate(cmap.items(), start=1):
        curses.init_pair(i, color, -1)
        pairs[name] = i
    # Pair for dim (white, dimmed via A_DIM)
    curses.init_pair(len(cmap) + 1, curses.COLOR_WHITE, -1)
    pairs["dim"] = len(cmap) + 1
    # Pair for border
    curses.init_pair(len(cmap) + 2, curses.COLOR_WHITE, -1)
    pairs["border"] = len(cmap) + 2
    # Idle severity: yellow → orange → red over time
    curses.init_pair(len(cmap) + 3, 178, -1)  # 256-color muted gold
    pairs["idle_warn"] = len(cmap) + 3
    curses.init_pair(len(cmap) + 4, 208, -1)  # 256-color orange
    pairs["idle_stale"] = len(cmap) + 4
    curses.init_pair(len(cmap) + 5, curses.COLOR_RED, -1)
    pairs["idle_dead"] = len(cmap) + 5
    # Pair for tool results (green)
    curses.init_pair(len(cmap) + 6, curses.COLOR_GREEN, -1)
    pairs["result"] = len(cmap) + 6
    return pairs


def _wrap_text(text: str, width: int) -> list[str]:
    """Word-wrap text to fit within width, preserving existing newlines."""
    if width <= 0:
        return []
    result = []
    for paragraph in text.split("\n"):
        if not paragraph:
            result.append("")
        else:
            result.extend(textwrap.wrap(paragraph, width=width) or [""])
    return result


def _format_age(seconds: float) -> str:
    """Format seconds as a human-readable age string."""
    s = int(max(0, seconds))
    if s < 60:
        return f"{s}s ago"
    elif s < 300:
        return f"{s // 60}m {s % 60}s ago"
    elif s < 3600:
        return f"{s // 60}m ago"
    elif s < 86400:
        return f"{s // 3600}h ago"
    else:
        return f"{s // 86400}d ago"


def _extract_label(filepath: str) -> str:
    """Extract a human-readable label from an agent output file.

    Detection strategy:
    - JSONL first line (custom agents): look for skill name or agent description
    - Plain text first line (built-in agents): identify type from keywords
    - Falls back to agent ID from filename
    """
    basename = os.path.basename(filepath).replace(".output", "").replace(".jsonl", "")
    try:
        with open(filepath) as f:
            first_line = f.readline()
        if not first_line:
            return basename

        # Try parsing as JSONL (custom agents produce structured output)
        try:
            obj = json.loads(first_line)
            if obj.get("type") == "user":
                content = ""
                msg = obj.get("message", {})
                if isinstance(msg, str):
                    content = msg
                elif isinstance(msg, dict):
                    c = msg.get("content", "")
                    if isinstance(c, str):
                        content = c
                    elif isinstance(c, list):
                        for block in c:
                            if isinstance(block, dict) and block.get("type") == "text":
                                content += block.get("text", "") + " "
                if content:
                    # "Load skill '<name>'" — custom skill agents
                    # "Research ..." — research-agent (no skill prefix)
                    if content.strip().startswith("Research "):
                        return "research-agent"
                    m = re.search(r"Load skill ['\"]([^'\"]+)['\"]", content)
                    if m:
                        return m.group(1)
                    # Built-in agent type detection from prompt content
                    # Use word boundaries to avoid false positives
                    # (e.g., "implant" matching "plan")
                    text_lower = content.strip().lower()
                    if re.search(
                        r"\b(?:plan|design|architect|implementation)\b", text_lower
                    ):
                        return "Plan agent"
                    if re.search(
                        r"\b(?:explore|search for|find files|find the|look for|codebase)\b",
                        text_lower,
                    ):
                        return "Explore agent"
                    # Summarize first line of prompt
                    summary = content.strip().split("\n")[0]
                    summary = re.sub(r"[*#`]", "", summary).strip()
                    if len(summary) > 22:
                        summary = summary[:19] + "..."
                    if summary:
                        return summary
            return basename
        except (json.JSONDecodeError, ValueError):
            pass

        # Plain text first line — built-in agent (Plan, Explore, general-purpose)
        text = first_line.strip().lower()
        if re.search(r"\b(?:plan|design|architect|implementation)\b", text):
            return "Plan agent"
        if re.search(
            r"\b(?:explore|search for|find files|find the|look for|codebase)\b", text
        ):
            return "Explore agent"
        # General-purpose or unknown — summarize
        summary = first_line.strip().split("\n")[0]
        summary = re.sub(r"[*#`]", "", summary).strip()
        if len(summary) > 22:
            summary = summary[:19] + "..."
        return summary or basename
    except (OSError, KeyError, TypeError):
        pass
    return basename


def _is_agent_active(filepath: str) -> bool:
    """Check if an agent is still running.

    For JSONL agent transcripts (symlinks or direct .jsonl files):
    1. If the last line is a completion message (assistant with
       stop_reason != "tool_use") AND mtime > 5s ago → stopped.
       The 5s debounce prevents flicker between turns.
    2. If mtime > 30s ago (file not written to in 30s) → stopped.
       Catches killed agents (TaskStop) whose last line is "user"
       or "progress" rather than a clean completion message.

    Fallback: mtime threshold for non-JSONL files (bash background tasks).
    """
    try:
        # Resolve to the actual JSONL file
        jsonl_path = None
        if os.path.islink(filepath):
            target = os.readlink(filepath)
            if target.endswith(".jsonl") and os.path.exists(target):
                jsonl_path = target
        elif filepath.endswith(".jsonl") and os.path.exists(filepath):
            jsonl_path = filepath

        if jsonl_path:
            mtime = os.path.getmtime(jsonl_path)
            age = time.time() - mtime
            # Clean completion: JSONL signal + 5s debounce
            if age > 5.0 and _jsonl_has_final_message(jsonl_path):
                return False
            # Killed/crashed: no writes in 30s = dead
            if age > 30.0:
                return False
            return True

        # Fallback for non-JSONL files (bash background tasks)
        mtime = os.path.getmtime(filepath)
        return (time.time() - mtime) < 120.0
    except OSError:
        return False


def _get_idle_seconds(filepath: str) -> float:
    """Return seconds since the file was last modified."""
    try:
        resolved = filepath
        if os.path.islink(filepath):
            target = os.readlink(filepath)
            if os.path.exists(target):
                resolved = target
        return max(0.0, time.time() - os.path.getmtime(resolved))
    except OSError:
        return 0.0


def _jsonl_has_final_message(filepath: str) -> bool:
    """Check if a JSONL transcript ends with a completion message.

    A completed agent ends with type=assistant, stop_reason != "tool_use".
    Returns True if the agent is done, False if still running.
    """
    try:
        with open(filepath, "rb") as f:
            f.seek(0, 2)
            size = f.tell()
            if size == 0:
                return False
            chunk_size = min(8192, size)
            f.seek(-chunk_size, 2)
            chunk = f.read().decode("utf-8", errors="replace")

        lines = chunk.strip().split("\n")
        if not lines:
            return False

        last = json.loads(lines[-1])
        if last.get("type") == "assistant":
            msg = last.get("message", {})
            if isinstance(msg, dict):
                stop_reason = msg.get("stop_reason")
                return stop_reason != "tool_use"
        return False
    except (json.JSONDecodeError, OSError, KeyError):
        return False


def _discover_agents(
    tasks_dir: str, displayed_paths: set[str], project_dir: str = ""
) -> list[tuple[str, str, float, bool]]:
    """Discover agent output files, returning (label, path, mtime, in_dashboard) sorted newest-first.

    Searches two locations:
    1. tasks_dir — symlinks or JSONL files from Claude Code's task system
    2. ~/.claude/projects/<project>/<session>/subagents/ — direct JSONL transcripts

    The subagents path is the reliable source (always created). The tasks_dir
    path is a fallback for compatibility.
    """
    seen: set[str] = set()  # dedupe by resolved path
    results = []
    cutoff = time.time() - 86400  # only show agents from last 24 hours

    # Source 1: tasks dir (symlinks to agent JSONL transcripts only)
    if tasks_dir and os.path.isdir(tasks_dir):
        for filepath in _glob.glob(os.path.join(tasks_dir, "*.output")):
            if not os.path.islink(filepath):
                continue  # skip non-symlinks (bash tasks, event watchers)
            resolved = os.path.realpath(filepath)
            seen.add(resolved)
            try:
                mtime = os.path.getmtime(filepath)
            except OSError:
                continue
            if mtime < cutoff:
                continue
            label = _extract_label(filepath)
            in_dashboard = filepath in displayed_paths or resolved in displayed_paths
            results.append((label, filepath, mtime, in_dashboard))

    # Source 2: subagent JSONL directories (reliable, always created)
    for subdir in _find_subagent_dirs(project_dir):
        for filepath in _glob.glob(os.path.join(subdir, "agent-*.jsonl")):
            resolved = os.path.realpath(filepath)
            if resolved in seen:
                continue
            seen.add(resolved)
            try:
                mtime = os.path.getmtime(filepath)
            except OSError:
                continue
            if mtime < cutoff:
                continue
            in_dashboard = filepath in displayed_paths or resolved in displayed_paths
            label = _extract_label(filepath)
            results.append((label, filepath, mtime, in_dashboard))

    results.sort(key=lambda x: x[2], reverse=True)  # newest first
    return results


def _build_browser_list(
    tasks_dir: str,
    displayed_paths: set[str],
    panes: list["AgentPane"],
    project_dir: str = "",
) -> list[tuple[str, str, float, bool]]:
    """Build the unified browser list: discovered agents + currently displayed panes.

    Ensures every pane visible on the dashboard also appears in the browser
    (with in_dash=True), even if its file is older than the 24h discovery cutoff.
    """
    items = _discover_agents(tasks_dir, displayed_paths, project_dir)
    seen = {os.path.realpath(path) for _, path, _, _ in items}

    # Add currently-displayed panes that _discover_agents missed (>24h old)
    for pane in panes:
        resolved = os.path.realpath(pane.filepath)
        if resolved not in seen:
            try:
                mtime = os.path.getmtime(pane.filepath)
            except OSError:
                continue
            seen.add(resolved)
            items.append((pane.label, pane.filepath, mtime, True))

    items.sort(key=lambda x: x[2], reverse=True)
    return items


def _infer_tasks_dir(panes: list[AgentPane]) -> str:
    """Infer the tasks directory from existing pane filepaths."""
    for pane in panes:
        d = os.path.dirname(pane.filepath)
        if d and os.path.isdir(d):
            return d
    # Try well-known pattern
    candidates = _glob.glob(f"/tmp/claude-{os.getuid()}/*/tasks")
    if candidates:
        return max(candidates, key=os.path.getmtime)
    return ""


def _find_subagent_dirs(project_dir: str = "") -> list[str]:
    """Find Claude Code subagent JSONL directories for the current project.

    Searches ~/.claude/projects/<project>/<session>/subagents/ for all
    sessions. Returns directories sorted newest-first.

    If project_dir is given, use it to derive the project path. Otherwise
    fall back to cwd. If neither matches, search all recent project dirs.
    """
    projects_root = os.path.expanduser("~/.claude/projects")
    project_base = ""

    # Try explicit project_dir first, then cwd
    for candidate in [project_dir, os.getcwd()]:
        if not candidate:
            continue
        encoded = candidate.replace("/", "-").lstrip("-")
        path = os.path.join(projects_root, f"-{encoded}")
        if os.path.isdir(path):
            project_base = path
            break

    # Fallback: find most recently modified project dir
    if not project_base and os.path.isdir(projects_root):
        candidates = []
        for entry in os.scandir(projects_root):
            if entry.is_dir() and entry.name.startswith("-"):
                try:
                    candidates.append((entry.stat().st_mtime, entry.path))
                except OSError:
                    continue
        if candidates:
            candidates.sort(reverse=True)
            project_base = candidates[0][1]

    if not project_base:
        return []
    results = []
    for session_dir in _glob.glob(os.path.join(project_base, "*/subagents")):
        if os.path.isdir(session_dir):
            try:
                mtime = os.path.getmtime(session_dir)
                results.append((mtime, session_dir))
            except OSError:
                continue
    results.sort(reverse=True)  # newest session first
    return [d for _, d in results]


def dashboard(
    agents: list[tuple[str, str]], tasks_dir: str = "", project_dir: str = ""
) -> None:
    """Curses main loop: layout panes, drain queues, redraw.

    Starts with explicit agents (if any) and auto-discovers new agents
    from the tasks directory.  The dashboard stays open even with no
    agents — it shows "waiting for agents" until one spawns.
    """
    panes: list[AgentPane] = [
        AgentPane(label, path, i % len(PANE_COLORS))
        for i, (label, path) in enumerate(agents)
        if os.path.exists(path)
        or (os.path.islink(path) and os.path.exists(os.readlink(path)))
    ]

    stop_event = threading.Event()
    threads: list[threading.Thread] = []
    # Map filepath -> (pane, thread) for hot-reload bookkeeping
    pane_map: dict[str, tuple[AgentPane, threading.Thread]] = {}
    # Paths dismissed by the user — never re-add via hot-reload
    dismissed_paths: set[str] = set()
    # Paths auto-removed because agent completed — re-addable via browser
    completed_paths: set[str] = set()

    def _start_pane(pane: AgentPane) -> threading.Thread:
        t = threading.Thread(target=tail_thread, args=(pane, stop_event), daemon=True)
        t.start()
        return t

    for pane in panes:
        t = _start_pane(pane)
        threads.append(t)
        pane_map[pane.filepath] = (pane, t)

    def run_curses(stdscr: "curses.window") -> None:
        nonlocal tasks_dir
        stdscr.nodelay(True)
        curses.curs_set(0)
        color_pairs = _init_colors()
        focused = 0  # index of pane receiving scroll input
        reload_counter = 0  # check file every ~1s (10 iterations * 0.1s)

        # Double-tap dismiss state
        dismiss_pending = False
        dismiss_time: float = 0.0

        # Agent browser state
        browser_open = False
        browser_items: list[
            tuple[str, str, float, bool]
        ] = []  # (label, path, mtime, in_dashboard)
        browser_cursor = 0
        browser_scroll = 0

        while True:
            # --- Periodic checks (~1s interval) ---
            reload_counter += 1
            if reload_counter >= 10:
                reload_counter = 0

                # Auto-discover new agents from tasks directory and subagent dirs
                if not tasks_dir:
                    tasks_dir = _infer_tasks_dir(panes)
                # Resolve symlinks so .output symlinks and direct JSONL paths dedup
                displayed = set(pane_map.keys()) | {
                    os.path.realpath(p) for p in pane_map
                }
                for label, path, mtime, in_dash in _discover_agents(
                    tasks_dir, displayed, project_dir
                ):
                    if (
                        not in_dash
                        and path not in dismissed_paths
                        and path not in completed_paths
                    ):
                        p = AgentPane(label, path, len(panes) % len(PANE_COLORS))
                        t = _start_pane(p)
                        panes.append(p)
                        threads.append(t)
                        pane_map[path] = (p, t)

                # Track completed agents (no longer auto-removed — they show *stopped* in header)
                for path in list(pane_map.keys()):
                    if not _is_agent_active(path):
                        completed_paths.add(path)

                # Clamp focused index
                if panes:
                    focused = min(focused, len(panes) - 1)
                else:
                    focused = 0

            # Clear stale dismiss confirmation
            if dismiss_pending and (time.monotonic() - dismiss_time) >= 2.0:
                dismiss_pending = False

            # Handle keyboard input
            try:
                key = stdscr.getch()
                while key != -1:
                    if key == ord("q") or key == 3:  # q or Ctrl-C (always works)
                        return

                    if browser_open:
                        # --- Browser overlay key handling ---
                        if key == 27 or key == ord("b"):  # Escape or 'a' to close
                            browser_open = False
                        elif key == curses.KEY_UP or key == ord("k"):
                            browser_cursor = max(0, browser_cursor - 1)
                        elif key == curses.KEY_DOWN or key == ord("j"):
                            if browser_items:
                                browser_cursor = min(
                                    len(browser_items) - 1, browser_cursor + 1
                                )
                        elif (
                            key == ord(" ")
                            or key == ord("a")
                            or key == 10
                            or key == curses.KEY_ENTER
                        ):  # Space/a/Enter to toggle
                            if browser_items and browser_cursor < len(browser_items):
                                label, path, _, in_dash = browser_items[browser_cursor]
                                # Resolve path for pane_map lookup (browser may have .output symlink, pane_map has .jsonl)
                                resolved_path = os.path.realpath(path)
                                pane_key = (
                                    path
                                    if path in pane_map
                                    else (
                                        resolved_path
                                        if resolved_path in pane_map
                                        else None
                                    )
                                )
                                if in_dash and pane_key is not None:
                                    # Remove from dashboard
                                    old_pane, _ = pane_map.pop(pane_key)
                                    if old_pane in panes:
                                        panes.remove(old_pane)
                                    dismissed_paths.add(path)
                                    dismissed_paths.add(resolved_path)
                                    browser_items[browser_cursor] = (
                                        label,
                                        path,
                                        browser_items[browser_cursor][2],
                                        False,
                                    )
                                    if panes:
                                        focused = min(focused, len(panes) - 1)
                                    else:
                                        focused = 0
                                elif not in_dash:
                                    # Add to dashboard
                                    p = AgentPane(
                                        label, path, len(panes) % len(PANE_COLORS)
                                    )
                                    t = _start_pane(p)
                                    panes.append(p)
                                    threads.append(t)
                                    pane_map[path] = (p, t)
                                    dismissed_paths.discard(path)
                                    dismissed_paths.discard(resolved_path)
                                    completed_paths.discard(path)
                                    completed_paths.discard(resolved_path)
                                    focused = len(panes) - 1
                                    browser_items[browser_cursor] = (
                                        label,
                                        path,
                                        browser_items[browser_cursor][2],
                                        True,
                                    )
                    elif panes:
                        # --- Normal pane key handling ---
                        fp = panes[focused]
                        if key == ord("\t"):  # Tab: switch focused pane
                            focused = (focused + 1) % len(panes)
                            dismiss_pending = False
                        elif key == curses.KEY_BTAB:  # Shift-Tab: reverse
                            focused = (focused - 1) % len(panes)
                            dismiss_pending = False
                        elif key == curses.KEY_UP or key == ord("k"):
                            fp.scroll_offset += 1
                            fp.auto_follow = False
                        elif key == curses.KEY_DOWN or key == ord("j"):
                            fp.scroll_offset = max(0, fp.scroll_offset - 1)
                            if fp.scroll_offset == 0:
                                fp.auto_follow = True
                                fp._prev_wrapped_total = 0
                        elif key == curses.KEY_PPAGE:  # Page Up
                            max_y, _ = stdscr.getmaxyx()
                            fp.scroll_offset += max(1, max_y - 2)
                            fp.auto_follow = False
                        elif key == curses.KEY_NPAGE:  # Page Down
                            max_y, _ = stdscr.getmaxyx()
                            fp.scroll_offset = max(
                                0, fp.scroll_offset - max(1, max_y - 2)
                            )
                            if fp.scroll_offset == 0:
                                fp.auto_follow = True
                                fp._prev_wrapped_total = 0
                        elif key == curses.KEY_END or key == ord("G"):
                            fp.scroll_offset = 0
                            fp.auto_follow = True
                            fp._prev_wrapped_total = 0
                        elif key == curses.KEY_HOME or key == ord("g"):
                            fp.auto_follow = False
                            fp.scroll_offset = 999999
                        elif key == ord("d"):
                            now = time.monotonic()
                            if dismiss_pending and (now - dismiss_time) < 2.0:
                                # Second press within 2s — actually dismiss
                                dismissed = panes.pop(focused)
                                pane_map.pop(dismissed.filepath, None)
                                dismissed_paths.add(dismissed.filepath)
                                if panes:
                                    focused = min(focused, len(panes) - 1)
                                else:
                                    focused = 0
                                dismiss_pending = False
                            else:
                                # First press — arm the confirmation
                                dismiss_pending = True
                                dismiss_time = now
                        elif key == ord("b"):
                            # Open agent browser
                            if not tasks_dir:
                                tasks_dir = _infer_tasks_dir(panes)
                            displayed = set(p.filepath for p in panes)
                            browser_items = _build_browser_list(
                                tasks_dir, displayed, panes, project_dir
                            )
                            browser_cursor = 0
                            browser_scroll = 0
                            browser_open = True
                            dismiss_pending = False
                    else:
                        # No panes — only 'a' to open browser
                        if key == ord("b"):
                            if not tasks_dir:
                                tasks_dir = _infer_tasks_dir(panes)
                            displayed = set(p.filepath for p in panes)
                            browser_items = _build_browser_list(
                                tasks_dir, displayed, panes, project_dir
                            )
                            browser_cursor = 0
                            browser_scroll = 0
                            browser_open = True

                    key = stdscr.getch()
            except curses.error:
                pass

            # Drain queues
            for pane in panes:
                while True:
                    try:
                        item = pane.queue.get_nowait()
                        pane.lines.append(item)
                    except queue.Empty:
                        break

            # Get terminal size
            max_y, max_x = stdscr.getmaxyx()
            if max_y < 3 or max_x < 10:
                time.sleep(0.1)
                continue

            stdscr.erase()

            if not panes and not browser_open:
                # No agents — show waiting message (status bar still drawn below)
                msg = "Waiting for agents..."
                try:
                    stdscr.addnstr(
                        max_y // 2,
                        max(0, (max_x - len(msg)) // 2),
                        msg,
                        max_x,
                        curses.A_DIM,
                    )
                    hint = "b: browse agents  q: quit"
                    stdscr.addnstr(
                        max_y // 2 + 1,
                        max(0, (max_x - len(hint)) // 2),
                        hint,
                        max_x,
                        curses.A_DIM,
                    )
                except curses.error:
                    pass

            # --- Draw panes ---
            if panes:
                num_panes = len(panes)
                border_cols = num_panes - 1
                usable_width = max_x - border_cols
                col_width = max(10, usable_width // num_panes)
                content_height = max_y - 2  # 1 for header, 1 for status bar

                for pi, pane in enumerate(panes):
                    x_off = pi * (col_width + 1)
                    pane_color_name = PANE_COLORS[pane.color_idx]
                    pane_pair = color_pairs[pane_color_name]

                    # Draw header — spinner while thinking, idle text when stale
                    idle_secs = _get_idle_seconds(pane.filepath)
                    show_idle = idle_secs >= 5.0
                    idle_tag = ""
                    idle_color = None
                    if show_idle:
                        if idle_secs < 120:
                            # Spinner + elapsed time until red
                            _spin = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
                            frame = _spin[int(time.time() * 4) % len(_spin)]
                            idle_tag = (
                                f"{frame} {_format_age(idle_secs).removesuffix(' ago')}"
                            )
                            if idle_secs >= 60:
                                idle_color = "idle_stale"
                            elif idle_secs >= 30:
                                idle_color = "idle_warn"
                        else:
                            # Red: show idle duration
                            idle_tag = (
                                f"idle {_format_age(idle_secs).removesuffix(' ago')}"
                            )
                            idle_color = "idle_dead"
                    if not show_idle:
                        header = pane.label.center(col_width)[:col_width]
                    else:
                        header_text = f"{pane.label}  {idle_tag}"
                        header = header_text.center(col_width)[:col_width]
                    hdr_attr = curses.color_pair(pane_pair) | curses.A_BOLD
                    if pi == focused:
                        hdr_attr |= curses.A_REVERSE
                    try:
                        stdscr.addnstr(0, x_off, header, col_width, hdr_attr)
                        if show_idle and idle_tag and idle_color:
                            tag_pos = header.find(idle_tag)
                            if tag_pos >= 0:
                                idle_attr = (
                                    curses.color_pair(color_pairs[idle_color])
                                    | curses.A_BOLD
                                )
                                if pi == focused:
                                    idle_attr |= curses.A_REVERSE
                                stdscr.addnstr(
                                    0,
                                    x_off + tag_pos,
                                    idle_tag,
                                    col_width - tag_pos,
                                    idle_attr,
                                )
                    except curses.error:
                        pass

                    # Prepare wrapped lines for this pane
                    display_width = col_width - 1
                    wrapped: list[tuple[str, str]] = []
                    for kind, text in pane.lines:
                        prefix = "▶ " if kind == "shell" else "  "
                        first_width = display_width - len(prefix)
                        if first_width <= 0:
                            first_width = 1
                        lines_w = _wrap_text(text, first_width)
                        if not lines_w:
                            lines_w = [""]
                        wrapped.append((kind, prefix + lines_w[0]))
                        for continuation in lines_w[1:]:
                            cont_lines = _wrap_text(continuation, display_width)
                            for cl in cont_lines or [""]:
                                wrapped.append((kind, "  " + cl))

                    # Anchor viewport when scrolled up: absorb new lines into offset
                    total = len(wrapped)
                    if not pane.auto_follow and pane._prev_wrapped_total > 0:
                        new_lines = total - pane._prev_wrapped_total
                        if new_lines > 0:
                            pane.scroll_offset += new_lines
                    pane._prev_wrapped_total = total

                    # Clamp scroll offset
                    max_scroll = max(0, total - content_height)
                    pane.scroll_offset = min(pane.scroll_offset, max_scroll)

                    # Select visible window
                    if pane.auto_follow or pane.scroll_offset == 0:
                        visible = wrapped[-(content_height):] if wrapped else []
                    else:
                        end = total - pane.scroll_offset
                        start = max(0, end - content_height)
                        visible = wrapped[start:end]

                    for li, (kind, wline) in enumerate(visible):
                        row = 1 + li
                        if row >= max_y - 1:
                            break
                        if kind == "text":
                            attr = curses.color_pair(color_pairs["cyan"])
                        elif kind == "shell":
                            attr = (
                                curses.color_pair(color_pairs["yellow"]) | curses.A_BOLD
                            )
                        elif kind == "result":
                            attr = curses.color_pair(color_pairs["result"])
                        else:
                            attr = curses.color_pair(color_pairs["dim"]) | curses.A_DIM
                        try:
                            stdscr.addnstr(
                                row, x_off, wline.replace("\x00", ""), col_width, attr
                            )
                        except curses.error:
                            pass

                    # Draw vertical border
                    if pi < num_panes - 1:
                        border_x = x_off + col_width
                        for row in range(max_y):
                            try:
                                stdscr.addch(
                                    row,
                                    border_x,
                                    "│",
                                    curses.color_pair(color_pairs["border"])
                                    | curses.A_DIM,
                                )
                            except curses.error:
                                pass

            # --- Draw agent browser overlay ---
            if browser_open:
                overlay_w = min(max_x - 4, max(60, max_x * 3 // 5))
                overlay_h = min(max_y - 2, max(10, max_y * 4 // 5))
                overlay_x = (max_x - overlay_w) // 2
                overlay_y = (max_y - overlay_h) // 2

                # Draw background
                for row in range(overlay_y, overlay_y + overlay_h):
                    try:
                        stdscr.addnstr(
                            row, overlay_x, " " * overlay_w, overlay_w, curses.A_REVERSE
                        )
                    except curses.error:
                        pass

                # Title bar
                title = f" Agent Browser ({len(browser_items)}) "
                try:
                    stdscr.addnstr(
                        overlay_y,
                        overlay_x + (overlay_w - len(title)) // 2,
                        title,
                        overlay_w,
                        curses.A_BOLD | curses.A_REVERSE,
                    )
                except curses.error:
                    pass

                # Column headers
                hdr = f"     {'Agent':<26s} {'Last active':>11s}"
                hdr = hdr[: overlay_w - 2]
                try:
                    stdscr.addnstr(
                        overlay_y + 1,
                        overlay_x + 1,
                        hdr.ljust(overlay_w - 2),
                        overlay_w - 2,
                        curses.A_REVERSE | curses.A_BOLD | curses.A_UNDERLINE,
                    )
                except curses.error:
                    pass

                if not browser_items:
                    msg = "No other agent outputs found"
                    try:
                        stdscr.addnstr(
                            overlay_y + 3,
                            overlay_x + 2,
                            msg,
                            overlay_w - 4,
                            curses.A_DIM | curses.A_REVERSE,
                        )
                    except curses.error:
                        pass
                else:
                    list_h = overlay_h - 3  # title + header + bottom margin
                    # Keep cursor visible
                    if browser_cursor < browser_scroll:
                        browser_scroll = browser_cursor
                    elif browser_cursor >= browser_scroll + list_h:
                        browser_scroll = browser_cursor - list_h + 1

                    now = time.time()
                    for i in range(list_h):
                        idx = browser_scroll + i
                        if idx >= len(browser_items):
                            break
                        label, path, mtime, in_dash = browser_items[idx]
                        age = _format_age(now - mtime)
                        marker = " ●" if in_dash else "  "
                        line_text = f"{marker} {label:<26s} {age:>11s}"
                        line_text = line_text[: overlay_w - 2]

                        row = overlay_y + 2 + i
                        if idx == browser_cursor:
                            # Focused item: bold highlight
                            attr = (
                                curses.color_pair(color_pairs["cyan"]) | curses.A_BOLD
                            )
                        else:
                            # Non-focused: reverse video (visible on overlay bg)
                            attr = curses.A_REVERSE
                            if in_dash:
                                attr |= curses.A_BOLD
                        try:
                            stdscr.addnstr(
                                row,
                                overlay_x + 1,
                                line_text.ljust(overlay_w - 2),
                                overlay_w - 2,
                                attr,
                            )
                        except curses.error:
                            pass

            # --- Status bar ---
            if browser_open:
                n = len(browser_items)
                status = f" Agent Browser: {n} agent{'s' if n != 1 else ''}  |  ● = in dashboard  |  Space: toggle  j/k: navigate  b/Esc: close  q: quit "
                status_attr = curses.color_pair(color_pairs["cyan"]) | curses.A_REVERSE
            elif panes:
                fp = panes[focused]
                if dismiss_pending:
                    status = f" [{fp.label}] tap d again to dismiss  |  Tab: switch  b: browse agents  q: quit "
                    status_attr = (
                        curses.color_pair(color_pairs["yellow"])
                        | curses.A_BOLD
                        | curses.A_REVERSE
                    )
                elif fp.auto_follow:
                    status = f" [{fp.label}] LIVE ↓  |  Tab: switch  ↑↓/jk: scroll  d: dismiss  b: browse  q: quit "
                    status_attr = curses.A_REVERSE
                else:
                    status = f" [{fp.label}] scrolled +{fp.scroll_offset}  |  Tab: switch  ↑↓/jk: scroll  G: live  d: dismiss  b: browse  q: quit "
                    status_attr = curses.A_REVERSE
            else:
                status = " No panes  |  b: browse agents  q: quit "
                status_attr = curses.A_REVERSE

            status = status[: max_x - 1]
            try:
                stdscr.addnstr(
                    max_y - 1, 0, status.ljust(max_x - 1), max_x - 1, status_attr
                )
            except curses.error:
                pass

            stdscr.refresh()
            time.sleep(0.1)

    try:
        curses.wrapper(run_curses)
    except KeyboardInterrupt:
        pass
    except curses.error:
        print(
            "Error: dashboard requires a terminal (not a pipe or non-interactive shell).",
            file=sys.stderr,
        )
    finally:
        stop_event.set()
        for t in threads:
            t.join(timeout=1.0)
        print("\nDashboard closed.")
        for pane in panes:
            print(f"  {pane.label}: {len(pane.lines)} events from {pane.filepath}")


def _purge_agents(project_dir: str = "") -> None:
    """Delete all subagent JSONL transcripts for the current project."""
    import shutil

    dirs = _find_subagent_dirs(project_dir)
    if not dirs:
        print("No subagent directories found.")
        return
    # All subagent dirs share a common project base
    project_base = os.path.dirname(os.path.dirname(dirs[0]))
    total = sum(len(_glob.glob(os.path.join(d, "agent-*.jsonl"))) for d in dirs)
    print(f"Found {total} agent transcript(s) across {len(dirs)} session(s)")
    print(f"  in {project_base}/*/subagents/")
    confirm = input("Delete all? [y/N] ").strip().lower()
    if confirm != "y":
        print("Aborted.")
        return
    for d in dirs:
        shutil.rmtree(d, ignore_errors=True)
    print(f"Purged {len(dirs)} subagent director{'y' if len(dirs) == 1 else 'ies'}.")


def main() -> None:
    args = sys.argv[1:]

    # Purge mode — delete all agent transcripts
    if "--purge" in args:
        args.remove("--purge")
        project_dir = ""
        if "--project-dir" in args:
            idx = args.index("--project-dir")
            args.pop(idx)
            if idx < len(args):
                project_dir = args.pop(idx)
        _purge_agents(project_dir)
        return

    # Dashboard mode
    if "--dashboard" in args:
        args.remove("--dashboard")
        agents = []

        # --tasks-dir DIR: directory to scan for agent output files
        tasks_dir = ""
        if "--tasks-dir" in args:
            idx = args.index("--tasks-dir")
            args.pop(idx)
            if idx < len(args):
                tasks_dir = args.pop(idx)

        # --project-dir DIR: project root for subagent JSONL discovery
        project_dir = ""
        if "--project-dir" in args:
            idx = args.index("--project-dir")
            args.pop(idx)
            if idx < len(args):
                project_dir = args.pop(idx)

        # Remaining positional args: label:path pairs
        for arg in args:
            if ":" in arg:
                label, path = arg.split(":", 1)
                agents.append((label, path))
            else:
                agents.append((os.path.basename(arg), arg))

        # Allow starting with no agents — auto-discovery will find them
        dashboard(agents, tasks_dir=tasks_dir, project_dir=project_dir)
        return

    # Original modes
    follow = False
    input_file = ""
    for arg in args:
        if arg == "-f":
            follow = True
        else:
            input_file = arg

    if input_file:
        with open(input_file) as f:
            for line in f:
                process_line(line)
            if follow:
                try:
                    while True:
                        line = f.readline()
                        if line:
                            process_line(line)
                        else:
                            time.sleep(0.3)
                except KeyboardInterrupt:
                    pass
    else:
        # Stdin pipe mode
        try:
            for line in sys.stdin:
                process_line(line)
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    main()
