# State Dashboard

Read-only web dashboard for engagement state (`state.db`). Single-file Python
stdlib HTTP server — no dependencies beyond Python 3.10+.

## Usage

```bash
python3 operator/state-dashboard/server.py [--port 8099] [--db engagement/state.db]
```

### Options

| Flag | Default | Description |
|------|---------|-------------|
| `--port` | `8099` | HTTP listen port |
| `--db` | `<project-root>/engagement/state.db` | Path to state database |

## Authentication

By default the server binds to `127.0.0.1` with no authentication — safe for
local-only access. To access from a host machine (e.g., when red-run is in a
VM), generate a token:

```bash
bash operator/state-dashboard/generate-token.sh
```

This writes a random 64-character token to `~/.config/red-run/viewer-token`.
When the server detects a token file on startup, it:

1. **Binds to `0.0.0.0`** — accessible from any interface
2. **Requires authentication** on all endpoints
3. Serves a login page at `/login` where you paste the token
4. Sets an `HttpOnly` session cookie (HMAC-signed, 24h expiry)

API clients can also use `Authorization: Bearer <token>` header:

```bash
curl -H "Authorization: Bearer $(cat ~/.config/red-run/viewer-token)" \
  http://<vm-ip>:8099/api/state
```

To disable remote access, delete the token file:

```bash
rm ~/.config/red-run/viewer-token
```

## Features

- **Kill-chain attack graph** — SVG directed graph showing hosts, vulns,
  credentials, access, pivots, and blocked techniques. Evolves in real-time
  as the engagement progresses. Nodes are color-coded by type, edges show
  confirmed/pending/blocked relationships.
- **State tables** — Targets, credentials, access, vulns, pivot map, tunnels,
  blocked, and event timeline. Collapsible sections, sortable columns, global
  text filter.
- **Summary cards** — At-a-glance counts for targets, credentials, active
  access, vulns (with severity breakdown), pivots, tunnels, blocked.
- **Live updates** — SSE stream pushes incremental events every 2s and full
  state refresh every 10s. No manual reload needed.
- **Graceful degradation** — If the database doesn't exist yet, shows a
  "Waiting for engagement..." banner and checks on each SSE tick.

## Endpoints

| Route | Method | Purpose |
|-------|--------|---------|
| `/` | GET | HTML dashboard |
| `/login` | GET | Login page (only when token is configured) |
| `/login` | POST | Submit token (sets session cookie) |
| `/api/state` | GET | Full state JSON (all tables, joined) |
| `/api/events?since=N` | GET | New state_events since cursor ID |
| `/api/stream` | GET | SSE — events every 2s, full state every 10s |

## Architecture

- **Read-only** — opens SQLite with `?mode=ro` URI parameter
- **WAL-safe** — `busy_timeout=5000` for concurrent reads while agents write
- **ThreadingHTTPServer** — SSE long-lived connections don't block page/API
- **Zero dependencies** — Python stdlib only (`http.server`, `sqlite3`, `json`)
- **Inline frontend** — HTML/CSS/JS is embedded in `server.py`
- **Token auth** — HMAC-signed session cookies, constant-time comparison
