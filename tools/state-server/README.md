# state MCP Server

MCP server providing SQLite-backed engagement state management for red-run.
Single instance with full read/write access for all agents and the orchestrator.
Opens `engagement/state.db`.

## Prerequisites

### Install Python dependencies

```bash
uv sync --directory tools/state-server
```

## Usage

The server runs as an MCP server, started automatically by Claude Code via
`.mcp.json`:

```bash
uv run --directory tools/state-server python server.py
```

### Deduplication

**Credentials:** `add_credential` checks for an existing row matching
`(username, secret_type, secret)` before INSERT. If a duplicate exists, it
returns `{"status": "duplicate_skipped", "credential_id": N}` without creating
a new row or emitting an event.

**Vulnerabilities:** `add_vuln` deduplicates in two passes: first by
`(target_id, title)`, then by `(target_id, vuln_type)` if `vuln_type` is set.
The type-based check catches near-duplicate titles (e.g., "LFI in /foo" vs
"LFI via /foo" both have `vuln_type="lfi"`). If a duplicate exists, it returns
`{"status": "duplicate_skipped", "vuln_id": N}` with the existing record's
title, status, and severity.

### Event emission

All write operations emit rows into the `state_events` table. Agents and the
orchestrator can poll for new events via `poll_events(since_id)` for real-time
monitoring of findings as they happen.

### Concurrent writes

SQLite WAL mode + `PRAGMA busy_timeout=30000` handles concurrent writers
safely. The 30-second timeout accommodates agent teams where multiple
teammates may write simultaneously.

### Typical workflow

1. Orchestrator calls `init_engagement()` to create `engagement/state.db`
2. Orchestrator records targets, ports via write tools
3. Agents call `get_state_summary()` on activation to read current state
4. Agents record findings directly via write tools (credentials, vulns, pivots, blocked)
5. Orchestrator reads state to decide next actions

## Tools

### Read tools

| Tool | Parameters | Description |
|------|-----------|-------------|
| `get_state_summary` | `max_lines` (default 200) | Compact markdown summary of all engagement state |
| `get_targets` | `ip` (optional filter) | Targets with their ports and services |
| `get_credentials` | `untested_only` (default false) | Credentials with tested-against information |
| `get_access` | `target` (optional), `active_only` (default true) | Current footholds and sessions |
| `get_vulns` | `status` (optional), `target` (optional) | Confirmed vulnerabilities |
| `get_pivot_map` | `status` (optional) | Pivot path edges (what leads where) |
| `get_blocked` | `target` (optional) | Failed technique attempts |
| `get_tunnels` | `status` (optional), `pivot_host` (optional) | Active tunnels |
| `poll_events` | `since_id` (default 0), `limit` (default 50) | Poll for state events since a cursor (real-time monitoring) |

### Write tools

| Tool | Parameters | Description |
|------|-----------|-------------|
| `init_engagement` | `name` (optional), `mode` (optional, default 'ctf') | Create state.db with full schema |
| `close_engagement` | (none) | Mark engagement as closed |
| `add_target` | `ip` (required), `hostname`, `os`, `role`, `notes`, `ports` (JSON) | Add or update a target (upserts on ip) |
| `update_target` | `ip` (required), `hostname`, `os`, `role`, `notes` | Update fields on an existing target |
| `add_port` | `ip` (required), `port` (required), `protocol`, `service`, `banner` | Add port to target (upserts on target+port+protocol) |
| `add_credential` | `username`, `secret`, `secret_type`, `domain`, `source` | Record a credential (deduplicates on username+type+secret) |
| `update_credential` | `id` (required), `cracked`, `secret`, `notes` | Update credential (e.g., mark hash as cracked) |
| `test_credential` | `credential_id`, `ip`, `service`, `works` (all required) | Record whether a credential works against a target/service |
| `add_access` | `ip` (required), `access_type`, `username`, `privilege`, `method` | Record a new foothold on a target |
| `update_access` | `id` (required), `active`, `privilege`, `notes` | Update access record (e.g., revoke) |
| `add_vuln` | `title` (required), `ip` (required), `vuln_type`, `severity`, `details` | Record a vulnerability (deduplicates on target+title) |
| `update_vuln` | `id` (required), `status`, `severity`, `details` | Update vulnerability status (found/exploited/blocked) |
| `add_pivot` | `source`, `destination` (required), `method`, `status` | Record a pivot path |
| `update_pivot` | `id` (required), `status`, `notes` | Update pivot path status |
| `add_blocked` | `technique`, `reason` (required), `ip`, `retry`, `notes` | Record a blocked/failed technique |
| `add_tunnel` | `tunnel_type`, `pivot_host`, `target_subnet`, `local_endpoint`, `remote_endpoint`, `requires_proxychains` | Record an established tunnel |
| `update_tunnel` | `id` (required), `status`, `notes` | Update tunnel status (active/down/closed) |

## Schema

The database has 10 tables:

| Table | Purpose |
|-------|---------|
| `engagement` | Singleton row — engagement name, status, mode (`ctf` or `pentest`), timestamps |
| `targets` | Host IPs/hostnames, OS, role |
| `ports` | Per-target ports, services, banners (1:many from targets) |
| `credentials` | Username/secret pairs with type (password, ntlm_hash, net_ntlm, kerberos_tgs, dcc2, webapp_hash, dpapi, etc.) |
| `credential_access` | Where each credential has been tested and whether it worked |
| `access` | Active footholds — shells, sessions, tokens |
| `vulns` | Confirmed vulnerabilities with severity and status (found/exploited/blocked) |
| `pivot_map` | Directed edges showing what leads where |
| `blocked` | Failed techniques with reasons and retry assessment |
| `tunnels` | Active tunnels — type, pivot host, target subnet, endpoints, proxychains requirement |
| `state_events` | Event log for all writes — enables real-time polling |

Schema versioning uses `PRAGMA user_version` for future migrations. Current version: 6.

## Data

The database lives at `engagement/state.db` (relative to project root, not the
server directory). The `engagement/` directory is created by the orchestrator
and is gitignored.
