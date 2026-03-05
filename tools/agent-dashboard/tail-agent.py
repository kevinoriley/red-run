#!/usr/bin/env python3
"""Live-tail a red-run agent's output with clean formatting.

Usage:
    python3 tools/tail-agent.py <output_file>              # one-shot (print and exit)
    python3 tools/tail-agent.py -f <output_file>           # live follow (like tail -f)
    tail -f <output_file> | python3 tools/tail-agent.py    # pipe mode
    python3 tools/tail-agent.py --dashboard label1:path1 label2:path2  # multi-agent dashboard
    bash tools/agent-dashboard/dashboard.sh                                            # dashboard from /tmp/red-run.dashboard

Shows:
    Cyan    - agent reasoning text
    Yellow  - shell commands sent to targets (▶ SHELL[session] command)
    Yellow  - bash commands (▶ BASH description)
    Dim     - skill loads, state queries, file reads/writes, other MCP tool calls
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
        return ("shell", f"LISTEN port={inp.get('port', '')} label={inp.get('label', '')}")
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
    if name == "Bash":
        cmd = inp.get("command", "")
        if len(cmd) > 200:
            cmd = cmd[:200] + "…"
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


def parse_line(line: str) -> list[tuple[str, str]]:
    """Parse a JSONL line and return list of (category, text) tuples."""
    line = line.strip()
    if not line or '"type":"assistant"' not in line:
        return []
    try:
        obj = json.loads(line)
    except (json.JSONDecodeError, ValueError):
        return []
    if obj.get("type") != "assistant":
        return []

    results = []
    for item in obj.get("message", {}).get("content", []):
        if not isinstance(item, dict):
            continue
        if item.get("type") == "text":
            text = item.get("text", "").strip()
            if text:
                results.append(("text", text))
        elif item.get("type") == "tool_use":
            kind, msg = format_tool(item.get("name", ""), item.get("input", {}))
            results.append((kind, msg))
    return results


def process_line(line: str) -> None:
    """Parse and print a single JSONL line (non-dashboard mode)."""
    for kind, msg in parse_line(line):
        if kind == "text":
            print(f"{CYAN}{msg}{RESET}", flush=True)
        elif kind == "shell":
            print(f"{YELLOW}▶ {msg}{RESET}", flush=True)
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
                for kind, text in parse_line(line):
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


def _read_agents_file(path: str) -> list[tuple[str, str]]:
    """Read label:path pairs from an agents file."""
    agents = []
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if ":" in line:
                    label, fpath = line.split(":", 1)
                    agents.append((label.strip(), fpath.strip()))
    except FileNotFoundError:
        pass
    return agents


def _format_age(seconds: float) -> str:
    """Format seconds as a human-readable age string."""
    s = int(max(0, seconds))
    if s < 60:
        return f"{s}s ago"
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
    basename = os.path.basename(filepath).replace(".output", "")
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
                    # "Load skill '<name>'" — pentest skill agents
                    m = re.search(r"Load skill ['\"]([^'\"]+)['\"]", content)
                    if m:
                        return m.group(1)
                    # Built-in agent type detection from prompt content
                    text_lower = content.strip().lower()
                    if any(kw in text_lower for kw in ("plan", "design", "architect",
                                                        "implementation")):
                        return "Plan agent"
                    if any(kw in text_lower for kw in ("explore", "search for",
                                                        "find files", "find the",
                                                        "look for", "codebase")):
                        return "Explore agent"
                    # Summarize first line of prompt
                    summary = content.strip().split("\n")[0]
                    summary = re.sub(r"[*#`]", "", summary).strip()
                    if len(summary) > 30:
                        summary = summary[:27] + "..."
                    if summary:
                        return summary
            return basename
        except (json.JSONDecodeError, ValueError):
            pass

        # Plain text first line — built-in agent (Plan, Explore, general-purpose)
        text = first_line.strip().lower()
        if any(kw in text for kw in ("plan", "design", "architect", "implementation")):
            return "Plan agent"
        if any(kw in text for kw in ("explore", "search for", "find files",
                                      "find the", "look for", "codebase")):
            return "Explore agent"
        # General-purpose or unknown — summarize
        summary = first_line.strip().split("\n")[0]
        summary = re.sub(r"[*#`]", "", summary).strip()
        if len(summary) > 30:
            summary = summary[:27] + "..."
        return summary or basename
    except (OSError, KeyError, TypeError):
        pass
    return basename


def _discover_agents(tasks_dir: str, displayed_paths: set[str]) -> list[tuple[str, str, float, bool]]:
    """Discover agent output files, returning (label, path, mtime, in_dashboard) sorted newest-first.

    Only includes symlinks (agent JSONL transcripts). Non-symlinks are Bash tool
    outputs and event watcher results. All agents are returned — those already
    displayed in the dashboard are marked with in_dashboard=True.
    """
    results = []
    if not tasks_dir or not os.path.isdir(tasks_dir):
        return results
    for filepath in _glob.glob(os.path.join(tasks_dir, "*.output")):
        # Only include symlinks (agent JSONL transcripts)
        if not os.path.islink(filepath):
            continue
        try:
            mtime = os.path.getmtime(filepath)
        except OSError:
            continue
        label = _extract_label(filepath)
        in_dashboard = filepath in displayed_paths
        results.append((label, filepath, mtime, in_dashboard))
    results.sort(key=lambda x: x[2], reverse=True)  # newest first
    return results


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


def dashboard(agents: list[tuple[str, str]], agents_file: str = "",
              tasks_dir: str = "") -> None:
    """Curses main loop: layout panes, drain queues, redraw.

    If agents_file is set, the file is re-read periodically and panes are
    added/removed to match.  The dashboard stays open even when the file
    is empty — it just shows "waiting for agents".
    """
    panes: list[AgentPane] = [
        AgentPane(label, path, i % len(PANE_COLORS))
        for i, (label, path) in enumerate(agents)
    ]

    stop_event = threading.Event()
    threads: list[threading.Thread] = []
    # Map filepath -> (pane, thread) for hot-reload bookkeeping
    pane_map: dict[str, tuple[AgentPane, threading.Thread]] = {}

    def _start_pane(pane: AgentPane) -> threading.Thread:
        t = threading.Thread(target=tail_thread, args=(pane, stop_event), daemon=True)
        t.start()
        return t

    for pane in panes:
        t = _start_pane(pane)
        threads.append(t)
        pane_map[pane.filepath] = (pane, t)

    # Track agents file mtime for hot-reload
    last_mtime: float = 0.0
    if agents_file:
        try:
            last_mtime = os.path.getmtime(agents_file)
        except OSError:
            pass

    def run_curses(stdscr: "curses.window") -> None:
        nonlocal last_mtime, tasks_dir
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
        browser_items: list[tuple[str, str, float, bool]] = []  # (label, path, mtime, in_dashboard)
        browser_cursor = 0
        browser_scroll = 0

        while True:
            # --- Hot-reload agents file ---
            if agents_file:
                reload_counter += 1
                if reload_counter >= 10:  # every ~1 second
                    reload_counter = 0
                    try:
                        mtime = os.path.getmtime(agents_file)
                    except OSError:
                        mtime = 0.0
                    if mtime != last_mtime:
                        last_mtime = mtime
                        new_agents = _read_agents_file(agents_file)
                        new_paths = {path for _, path in new_agents}
                        old_paths = set(pane_map.keys())

                        # Add new panes
                        for label, path in new_agents:
                            if path not in old_paths:
                                p = AgentPane(label, path, len(panes) % len(PANE_COLORS))
                                t = _start_pane(p)
                                panes.append(p)
                                threads.append(t)
                                pane_map[path] = (p, t)

                        # Remove stale panes
                        for path in old_paths - new_paths:
                            if path in pane_map:
                                old_pane, _ = pane_map.pop(path)
                                if old_pane in panes:
                                    panes.remove(old_pane)

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
                                browser_cursor = min(len(browser_items) - 1, browser_cursor + 1)
                        elif key == 10 or key == curses.KEY_ENTER:  # Enter to add
                            if browser_items and browser_cursor < len(browser_items):
                                label, path, _, in_dash = browser_items[browser_cursor]
                                if not in_dash:
                                    p = AgentPane(label, path, len(panes) % len(PANE_COLORS))
                                    t = _start_pane(p)
                                    panes.append(p)
                                    threads.append(t)
                                    pane_map[path] = (p, t)
                                    focused = len(panes) - 1
                                browser_open = False
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
                        elif key == curses.KEY_PPAGE:  # Page Up
                            max_y, _ = stdscr.getmaxyx()
                            fp.scroll_offset += max(1, max_y - 2)
                            fp.auto_follow = False
                        elif key == curses.KEY_NPAGE:  # Page Down
                            max_y, _ = stdscr.getmaxyx()
                            fp.scroll_offset = max(0, fp.scroll_offset - max(1, max_y - 2))
                            if fp.scroll_offset == 0:
                                fp.auto_follow = True
                        elif key == curses.KEY_END or key == ord("G"):
                            fp.scroll_offset = 0
                            fp.auto_follow = True
                        elif key == curses.KEY_HOME or key == ord("g"):
                            fp.auto_follow = False
                            fp.scroll_offset = 999999
                        elif key == ord("d"):
                            now = time.monotonic()
                            if dismiss_pending and (now - dismiss_time) < 2.0:
                                # Second press within 2s — actually dismiss
                                dismissed = panes.pop(focused)
                                pane_map.pop(dismissed.filepath, None)
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
                            browser_items = _discover_agents(tasks_dir, displayed)
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
                            browser_items = _discover_agents(tasks_dir, displayed)
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
                # No agents — show waiting message
                msg = "Waiting for agents..."
                try:
                    stdscr.addnstr(max_y // 2, max(0, (max_x - len(msg)) // 2),
                                   msg, max_x, curses.A_DIM)
                    hint = "b: browse agents  q: quit"
                    stdscr.addnstr(max_y // 2 + 1, max(0, (max_x - len(hint)) // 2),
                                   hint, max_x, curses.A_DIM)
                except curses.error:
                    pass
                stdscr.refresh()
                time.sleep(0.1)
                continue

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

                    # Draw header — highlight focused pane
                    header = pane.label.center(col_width)[:col_width]
                    hdr_attr = curses.color_pair(pane_pair) | curses.A_BOLD
                    if pi == focused:
                        hdr_attr |= curses.A_REVERSE
                    try:
                        stdscr.addnstr(0, x_off, header, col_width, hdr_attr)
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
                            for cl in (cont_lines or [""]):
                                wrapped.append((kind, "  " + cl))

                    # Clamp scroll offset
                    total = len(wrapped)
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
                            attr = curses.color_pair(color_pairs["yellow"]) | curses.A_BOLD
                        else:
                            attr = curses.color_pair(color_pairs["dim"]) | curses.A_DIM
                        try:
                            stdscr.addnstr(row, x_off, wline, col_width, attr)
                        except curses.error:
                            pass

                    # Draw vertical border
                    if pi < num_panes - 1:
                        border_x = x_off + col_width
                        for row in range(max_y):
                            try:
                                stdscr.addch(row, border_x, "│",
                                             curses.color_pair(color_pairs["border"]) | curses.A_DIM)
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
                        stdscr.addnstr(row, overlay_x, " " * overlay_w, overlay_w,
                                       curses.A_REVERSE)
                    except curses.error:
                        pass

                # Title bar
                title = " Agent Browser "
                try:
                    stdscr.addnstr(overlay_y, overlay_x + (overlay_w - len(title)) // 2,
                                   title, overlay_w, curses.A_BOLD | curses.A_REVERSE)
                except curses.error:
                    pass

                # Column headers
                hdr = f"     {'Agent':<26s} {'Age':>8s}"
                hdr = hdr[:overlay_w - 2]
                try:
                    stdscr.addnstr(overlay_y + 1, overlay_x + 1, hdr.ljust(overlay_w - 2),
                                   overlay_w - 2,
                                   curses.A_REVERSE | curses.A_BOLD | curses.A_UNDERLINE)
                except curses.error:
                    pass

                if not browser_items:
                    msg = "No other agent outputs found"
                    try:
                        stdscr.addnstr(overlay_y + 3, overlay_x + 2, msg, overlay_w - 4,
                                       curses.A_DIM | curses.A_REVERSE)
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
                        line_text = f"{marker} {label:<26s} {age:>8s}"
                        line_text = line_text[:overlay_w - 2]

                        row = overlay_y + 2 + i
                        if idx == browser_cursor:
                            if in_dash:
                                attr = curses.color_pair(color_pairs["dim"]) | curses.A_BOLD
                            else:
                                attr = curses.color_pair(color_pairs["cyan"]) | curses.A_BOLD
                        else:
                            if in_dash:
                                attr = curses.A_REVERSE | curses.A_DIM
                            else:
                                attr = curses.A_REVERSE
                        try:
                            stdscr.addnstr(row, overlay_x + 1, line_text.ljust(overlay_w - 2),
                                           overlay_w - 2, attr)
                        except curses.error:
                            pass

            # --- Status bar ---
            if browser_open:
                n = len(browser_items)
                status = f" Agent Browser: {n} agent{'s' if n != 1 else ''}  |  ● = in dashboard  |  j/k: navigate  Enter: add  b/Esc: close  q: quit "
                status_attr = curses.color_pair(color_pairs["cyan"]) | curses.A_REVERSE
            elif panes:
                fp = panes[focused]
                if dismiss_pending:
                    status = f" [{fp.label}] tap d again to dismiss  |  Tab: switch  b: browse agents  q: quit "
                    status_attr = curses.color_pair(color_pairs["yellow"]) | curses.A_BOLD | curses.A_REVERSE
                elif fp.auto_follow:
                    status = f" [{fp.label}] LIVE ↓  |  Tab: switch  ↑↓/jk: scroll  d: dismiss  b: browse  q: quit "
                    status_attr = curses.A_REVERSE
                else:
                    status = f" [{fp.label}] scrolled +{fp.scroll_offset}  |  Tab: switch  ↑↓/jk: scroll  G: live  d: dismiss  b: browse  q: quit "
                    status_attr = curses.A_REVERSE
            else:
                status = " No panes  |  b: browse agents  q: quit "
                status_attr = curses.A_REVERSE

            status = status[:max_x - 1]
            try:
                stdscr.addnstr(max_y - 1, 0, status.ljust(max_x - 1), max_x - 1,
                               status_attr)
            except curses.error:
                pass

            stdscr.refresh()
            time.sleep(0.1)

    try:
        curses.wrapper(run_curses)
    except KeyboardInterrupt:
        pass
    except curses.error:
        print("Error: dashboard requires a terminal (not a pipe or non-interactive shell).",
              file=sys.stderr)
    finally:
        stop_event.set()
        for t in threads:
            t.join(timeout=1.0)
        print("\nDashboard closed.")
        for pane in panes:
            print(f"  {pane.label}: {len(pane.lines)} events from {pane.filepath}")


def main() -> None:
    args = sys.argv[1:]

    # Dashboard mode
    if "--dashboard" in args:
        args.remove("--dashboard")
        agents = []

        # --from FILE: read label:path pairs from a file (hot-reloaded)
        # File doesn't need to exist yet — dashboard starts empty and picks
        # up agents as the file is created/updated.
        agents_file = ""
        if "--from" in args:
            idx = args.index("--from")
            args.pop(idx)
            if idx < len(args):
                agents_file = args.pop(idx)
                agents = _read_agents_file(agents_file)

        # --tasks-dir DIR: directory to scan for agent output files
        tasks_dir = ""
        if "--tasks-dir" in args:
            idx = args.index("--tasks-dir")
            args.pop(idx)
            if idx < len(args):
                tasks_dir = args.pop(idx)

        # Remaining positional args: label:path pairs
        for arg in args:
            if ":" in arg:
                label, path = arg.split(":", 1)
                agents.append((label, path))
            else:
                agents.append((os.path.basename(arg), arg))

        # With --from, allow starting with no agents (file will be watched)
        if not agents and not agents_file:
            print("Usage: tail-agent.py --dashboard [--from agents_file] [--tasks-dir DIR] [label:path ...]",
                  file=sys.stderr)
            sys.exit(1)
        dashboard(agents, agents_file=agents_file, tasks_dir=tasks_dir)
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
