# MCP Servers

red-run uses five MCP (Model Context Protocol) servers to give agents access to capabilities that Claude Code's built-in tools can't provide: network scanning, persistent shell sessions, browser automation, semantic skill search, and engagement state management.

MCP servers run as local processes, started automatically by Claude Code when you open a session in the repo directory. Each server exposes tools that agents call during skill execution.

## Configuration

All servers are configured in `.mcp.json` at the repo root:

```json
{
  "mcpServers": {
    "skill-router": {
      "command": "uv",
      "args": ["run", "--directory", "tools/skill-router", "python", "server.py"],
      "env": { "HF_HUB_OFFLINE": "1" }
    },
    "nmap-server": {
      "command": "uv",
      "args": ["run", "--directory", "tools/nmap-server", "python", "server.py"]
    },
    "shell-server": {
      "command": "uv",
      "args": ["run", "--directory", "tools/shell-server", "python", "server.py"]
    },
    "browser-server": {
      "command": "uv",
      "args": ["run", "--directory", "tools/browser-server", "python", "server.py"]
    },
    "state-reader": {
      "command": "uv",
      "args": ["run", "--directory", "tools/state-server", "python", "server.py",
               "--mode", "read"]
    },
    "state-interim": {
      "command": "uv",
      "args": ["run", "--directory", "tools/state-server", "python", "server.py",
               "--mode", "interim"]
    },
    "state-writer": {
      "command": "uv",
      "args": ["run", "--directory", "tools/state-server", "python", "server.py",
               "--mode", "write"]
    }
  }
}
```

> **Note:** The state-server runs as three separate instances with different `--mode` flags. All three share the same `engagement/state.db` file. See [Engagement State](engagement-state.md) for details.

---

## skill-router

**Location:** `tools/skill-router/` · **3 tools**

Semantic skill discovery and retrieval. Skills are indexed from YAML frontmatter into ChromaDB with `all-MiniLM-L6-v2` sentence-transformer embeddings. The orchestrator calls `search_skills()` to find the right skill for a situation, then tells the agent which skill to load. Agents call `get_skill()` to load the full methodology — they never call `search_skills()` themselves.

| Tool | Description |
|------|-------------|
| `search_skills(query, n=5, category?, min_similarity=0.4)` | Semantic search across all indexed skills |
| `get_skill(name)` | Load a skill's full SKILL.md content |
| `list_skills(category?)` | List available skills, optionally filtered |

**Indexing:** Run `uv run --directory tools/skill-router python indexer.py` after adding or modifying skills. The indexer extracts description, keywords, tools, and opsec fields from frontmatter and builds embedding documents. ChromaDB data lives at `tools/skill-router/.chromadb/`.

---

## nmap-server

**Location:** `tools/nmap-server/` · **3 tools** · **Requires Docker**

Runs nmap inside a Docker container with minimal capabilities — no sudo needed. All inputs are validated before reaching `subprocess.run()`.

| Tool | Description |
|------|-------------|
| `nmap_scan(target, options="-A -p- -T4", save_to?)` | Run nmap in Docker, return parsed JSON |
| `get_scan(scan_id)` | Retrieve previous scan results |
| `list_scans()` | List all scans from this session |

**Container isolation:**

- `--network=host` for raw socket access to the target network
- `--cap-drop=ALL --cap-add=NET_RAW --cap-add=NET_ADMIN` — only network capabilities
- `--rm` — container removed after each scan
- No volume mounts — XML output goes to stdout

**Input validation:**

- Blocklist of dangerous nmap flags (`-iL`, `-oN`, `--datadir`, etc.)
- Target strings checked for shell metacharacters and path traversal
- `--script` arguments must be bare names (no paths or URLs)
- Evidence paths must be under `engagement/evidence/`

**Output:** Returns structured JSON — hosts, ports, services, banners, NSE script results, OS detection. Raw XML is saved to `engagement/evidence/nmap-<target>.xml` when the engagement directory exists.

| Variable | Default | Description |
|----------|---------|-------------|
| `NMAP_TIMEOUT` | `600` | Max scan duration (seconds) |
| `NMAP_DOCKER_IMAGE` | `red-run-nmap:latest` | Docker image name |

---

## shell-server

**Location:** `tools/shell-server/` · **7 tools**

Manages TCP listeners, reverse shell sessions, and local interactive processes. Solves the persistent shell problem — Claude Code's Bash tool runs each command as a separate process, so interactive shells and credential-based access tools have no way to maintain state between calls.

| Tool | Description |
|------|-------------|
| `start_listener(port, host="0.0.0.0", timeout=300, label?)` | Start TCP listener, wait for reverse shell |
| `start_process(command, label?, timeout=30, privileged=false)` | Spawn local interactive process in a persistent PTY |
| `send_command(session_id, command, timeout=10, expect?)` | Send command to session, return output |
| `read_output(session_id, timeout=2)` | Read buffered output without sending a command |
| `stabilize_shell(session_id, method="auto")` | Upgrade raw shell to interactive PTY |
| `list_sessions()` | List all listeners and sessions with status |
| `close_session(session_id, save_transcript=true)` | Close session and save transcript |

### Reverse shell workflow

```
start_listener(port=4444)       → Wait for callback
# ... agent sends reverse shell payload via RCE ...
stabilize_shell(session_id)     → Upgrade to PTY
send_command(session_id, "id")  → Interact
close_session(session_id)       → Save transcript
```

### Docker mode (`privileged=true`)

The `privileged` parameter runs commands inside the `red-run-shell` Docker container, which packages the tools that need persistent sessions or raw sockets:

| Category | Tools |
|----------|-------|
| Windows access | evil-winrm |
| Impacket | psexec.py, wmiexec.py, smbexec.py, smbclient.py, mssqlclient.py |
| Pivoting | chisel, ligolo-ng proxy, socat |
| Poisoning | Responder, mitm6 |
| Capture | tcpdump |
| SSH | openssh-client |

Use `privileged=true` for Docker-only tools (evil-winrm, chisel, ligolo-ng) and for daemons needing raw sockets (Responder, mitm6, tcpdump). Containers run with `--network=host` to share the host's network namespace including VPN tunnels.

### Shell stabilization

`stabilize_shell` tries three methods in order: python3, python2, then `script(1)`. After stabilization, sets `TERM=xterm-256color` and configures terminal size.

### Transcripts

Every send/recv is logged in memory. On `close_session(save_transcript=true)`, the full transcript is written to `engagement/evidence/shell-{id}-{label}.log`.

---

## browser-server

**Location:** `tools/browser-server/` · **11 tools**

Headless Chromium automation via Playwright. Handles CSRF tokens, session cookies, JavaScript-rendered forms, and multi-step auth flows that curl can't manage. Each session maintains its own cookie jar and localStorage.

| Tool | Description |
|------|-------------|
| `browser_open(url, ignore_tls=true)` | Create session + navigate, returns page as markdown |
| `browser_navigate(session_id, url)` | Navigate within existing session |
| `browser_get_page(session_id, selector?)` | Re-read page content, optionally scoped by CSS selector |
| `browser_click(session_id, selector, wait_until="load")` | Click element and wait for navigation |
| `browser_fill(session_id, selector, value)` | Fill a form field |
| `browser_select(session_id, selector, value)` | Select dropdown option |
| `browser_screenshot(session_id, save_to?)` | Take full-page PNG screenshot |
| `browser_cookies(session_id)` | Get all cookies as JSON |
| `browser_evaluate(session_id, expression)` | Run JavaScript in page context |
| `close_browser(session_id)` | Close session and free resources |
| `list_browser_sessions()` | List active sessions |

**Content handling:** HTML is converted to markdown via `markdownify`. Scripts and styles are stripped. Output capped at 50KB — use `browser_get_page` with a CSS selector to scope large pages.

**Session isolation:** Each `browser_open` creates a new Chromium browser context with its own cookie jar, localStorage, and cache. TLS errors are ignored by default for self-signed pentesting targets.

**When to use browser vs curl:** Browser tools are the default for navigating sites and managing sessions. Use curl as fallback for precise payload control in injection testing.

---

## state-server

**Location:** `tools/state-server/` · **3 instances, up to 24 tools**

SQLite-backed engagement state management. The same server runs as three instances in different modes — each exposes a different set of tools depending on the agent's role.

| Mode | Instance | Used By | Access |
|------|----------|---------|--------|
| `read` | state-reader | Technique agents | 8 read-only tools |
| `interim` | state-interim | Discovery agents | 8 read + 4 add-only writes |
| `write` | state-writer | Orchestrator | 8 read + all write/update tools |

All three instances open the same `engagement/state.db`. SQLite WAL mode + `busy_timeout=5000` handles concurrency safely.

See [Engagement State](engagement-state.md) for the full schema, mode architecture, and how state drives vulnerability chaining.

---

## Server details

For complete documentation of each server — parameters, environment variables, architecture, and edge cases — see the README in each server's directory:

- [`tools/skill-router/README.md`](https://github.com/blacklanternsecurity/red-run/blob/main/tools/skill-router/README.md)
- [`tools/nmap-server/README.md`](https://github.com/blacklanternsecurity/red-run/blob/main/tools/nmap-server/README.md)
- [`tools/shell-server/README.md`](https://github.com/blacklanternsecurity/red-run/blob/main/tools/shell-server/README.md)
- [`tools/browser-server/README.md`](https://github.com/blacklanternsecurity/red-run/blob/main/tools/browser-server/README.md)
- [`tools/state-server/README.md`](https://github.com/blacklanternsecurity/red-run/blob/main/tools/state-server/README.md)
