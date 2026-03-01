# browser MCP Server

MCP server providing headless browser automation for red-run agents. Solves
the web interaction problem — curl can't handle CSRF tokens, session rotation,
JavaScript-rendered forms, or multi-step authentication flows. Each session
maintains its own cookie jar and localStorage across tool calls.

## Prerequisites

### Install Python dependencies

```bash
uv sync --directory tools/browser-server
```

### Install Chromium

Playwright needs a Chromium binary. If not already installed:

```bash
uv run --directory tools/browser-server playwright install chromium
```

This downloads a self-contained Chromium build (~150MB) into Playwright's cache
directory. No system-level browser installation required.

## Usage

The server runs as an MCP server, started automatically by Claude Code via
`.mcp.json`. To test manually:

```bash
uv run --directory tools/browser-server python server.py
```

### Typical workflow

1. Agent calls `browser_open(url="https://target.htb/login")` — creates a
   session with its own cookie jar and returns page content as markdown
2. Agent calls `browser_fill(session_id=..., selector="input[name=username]", value="admin")`
3. Agent calls `browser_fill(session_id=..., selector="input[name=password]", value="password")`
4. Agent calls `browser_click(session_id=..., selector="button[type=submit]")` — submits form, returns new page
5. Agent calls `browser_cookies(session_id=...)` to inspect session tokens
6. Agent calls `browser_screenshot(session_id=...)` to capture evidence
7. Agent calls `close_browser(session_id=...)` when done

### When to use browser vs curl

- **Browser tools** (default) — navigating sites, filling forms, managing
  sessions, capturing screenshots, inspecting JS-rendered content
- **curl** (fallback) — crafted payloads needing precise header/body control,
  injection testing where exact request structure matters

## Tools

| Tool | Parameters | Description |
|------|-----------|-------------|
| `browser_open` | `url` (required), `ignore_tls` (default true) | Create session + navigate to URL, returns page as markdown |
| `browser_navigate` | `session_id` (required), `url` (required) | Navigate within existing session, preserving cookies |
| `browser_get_page` | `session_id` (required), `selector` (optional) | Re-read page content, optionally scoped to CSS selector |
| `browser_click` | `session_id` (required), `selector` (required), `wait_until` (default `load`) | Click element and wait for navigation/loading |
| `browser_fill` | `session_id` (required), `selector` (required), `value` (required) | Fill a single form field (clears first) |
| `browser_select` | `session_id` (required), `selector` (required), `value` (required) | Select dropdown option by value |
| `browser_screenshot` | `session_id` (required), `save_to` (optional) | Take full-page PNG screenshot |
| `browser_cookies` | `session_id` (required) | Get all cookies as JSON |
| `browser_evaluate` | `session_id` (required), `expression` (required) | Run JavaScript in page context |
| `close_browser` | `session_id` (required) | Close browser session and free resources |
| `list_browser_sessions` | (none) | List all active sessions with URLs and timestamps |

## Content handling

- HTML is converted to markdown via `markdownify` for compact, readable output
- `<script>` and `<style>` blocks are stripped before conversion
- Output is capped at 50KB — large pages are truncated with a notice
- Use `browser_get_page` with a CSS selector to scope to specific page sections
  when full-page content is too noisy

## Session isolation

Each `browser_open` call creates a new Chromium browser context with its own:
- Cookie jar
- localStorage / sessionStorage
- Cache

Sessions are independent — logging into one site doesn't affect another session.
TLS certificate errors are ignored by default (`ignore_tls=true`), which is
typical for pentesting targets with self-signed certs.

## Screenshots

`browser_screenshot` saves full-page PNGs. Default path:
`engagement/evidence/browser-<timestamp>.png` (if the engagement directory
exists). Provide `save_to` to override.

## Architecture

The server uses Playwright's async API with headless Chromium. The browser
instance is launched lazily on first `browser_open` call and shared across all
sessions. Each session gets its own browser context (isolated cookie jar).
The browser is cleaned up automatically on server exit via `atexit`.
