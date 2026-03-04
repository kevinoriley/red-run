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
import json
import os
import queue
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


def dashboard(agents: list[tuple[str, str]], agents_file: str = "") -> None:
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
        nonlocal last_mtime
        stdscr.nodelay(True)
        curses.curs_set(0)
        color_pairs = _init_colors()
        focused = 0  # index of pane receiving scroll input
        reload_counter = 0  # check file every ~1s (10 iterations * 0.1s)

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

            # Handle keyboard input
            if panes:
                try:
                    key = stdscr.getch()
                    while key != -1:
                        fp = panes[focused]
                        if key == ord("q") or key == 3:  # q or Ctrl-C
                            return
                        elif key == ord("\t"):  # Tab: switch focused pane
                            focused = (focused + 1) % len(panes)
                        elif key == curses.KEY_BTAB:  # Shift-Tab: reverse
                            focused = (focused - 1) % len(panes)
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
                        key = stdscr.getch()
                except curses.error:
                    pass
            else:
                # No panes — just check for quit
                try:
                    key = stdscr.getch()
                    if key == ord("q") or key == 3:
                        return
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

            if not panes:
                # No agents — show waiting message
                msg = "Waiting for agents..."
                try:
                    stdscr.addnstr(max_y // 2, max(0, (max_x - len(msg)) // 2),
                                   msg, max_x, curses.A_DIM)
                    hint = "Dashboard will update when agents are launched.  q: quit"
                    stdscr.addnstr(max_y // 2 + 1, max(0, (max_x - len(hint)) // 2),
                                   hint, max_x, curses.A_DIM)
                except curses.error:
                    pass
                stdscr.refresh()
                time.sleep(0.1)
                continue

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

            # Status bar
            fp = panes[focused]
            if fp.auto_follow:
                status = f" [{fp.label}] LIVE ↓  |  Tab: switch pane  ↑↓/jk: scroll  PgUp/PgDn  g/G: top/bottom  q: quit "
            else:
                status = f" [{fp.label}] scrolled +{fp.scroll_offset}  |  Tab: switch  ↑↓/jk: scroll  G/End: resume live  q: quit "
            status = status[:max_x - 1]
            try:
                stdscr.addnstr(max_y - 1, 0, status.ljust(max_x - 1), max_x - 1,
                               curses.A_REVERSE)
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

        # Remaining positional args: label:path pairs
        for arg in args:
            if ":" in arg:
                label, path = arg.split(":", 1)
                agents.append((label, path))
            else:
                agents.append((os.path.basename(arg), arg))

        # With --from, allow starting with no agents (file will be watched)
        if not agents and not agents_file:
            print("Usage: tail-agent.py --dashboard [--from agents_file] [label:path ...]",
                  file=sys.stderr)
            sys.exit(1)
        dashboard(agents, agents_file=agents_file)
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
