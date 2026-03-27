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

**Vulnerabilities:** `add_vuln` deduplicates on exact `(target_id, title)`
match — returns `{"status": "duplicate_skipped"}` without inserting. When
`vuln_type` is set and another vuln with the same type exists on the target,
the insert proceeds but the response includes `"warning": "possible_duplicate"`
with the existing record's ID and title. This lets the orchestrator decide
whether two vulns of the same type are genuinely distinct (e.g., SQLi on
different endpoints) or near-duplicates (e.g., LFI with different wording).

### Event emission

All write operations emit rows into the `state_events` table. Agents and the
orchestrator can poll for new events via `poll_events(since_id)` for real-time
monitoring of findings as they happen.

### Client-side dedup (agent teams)

In the agent teams orchestrator (`/red-run-ctf`), all state writes are routed
through the `state-mgr` teammate, which applies LLM-level semantic dedup
before writing. This catches cases that server-side string matching cannot
(e.g., "LFI file read" vs "LFI via absolute path" are the same finding).
Server-side dedup (exact title hard block, `vuln_type` soft warning) remains
as a safety net but is not the primary dedup mechanism.

### Flow graph pruning

The server automatically manages `in_graph` flags to keep the dashboard flow
graph clean:

- **On exploitation**: `update_vuln(status="exploited")` sets `in_graph=0` on
  sibling `found` vulns sharing the same `via_access_id` and target. Response
  includes `"siblings_pruned": N`.

- **On abandonment**: `update_vuln(status="blocked")` or
  `update_access(active=false)` restores pruned siblings (`in_graph=1`) if no
  other exploited vuln exists from the same access. Response includes
  `"siblings_restored": N`.

- **Manual override**: `update_vuln(id=N, in_graph=0|1)` to force
  visibility. Overrides automatic pruning.

### Concurrent writes

SQLite WAL mode + `PRAGMA busy_timeout=30000` handles concurrent writers
safely. The 30-second timeout accommodates agent teams where multiple
teammates may write simultaneously. In practice, with state-mgr as the sole
writer, contention is minimal.

### Typical workflow

1. Orchestrator calls `init_engagement()` to create `engagement/state.db`
2. **Agent teams:** state-mgr teammate is the sole writer — other teammates send
   structured messages to state-mgr, which writes to state.db after dedup
3. **Legacy:** Agents record findings directly via write tools
4. All agents/teammates call `get_state_summary()` on activation to read current state
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
| `get_chain` | (none) | Walk provenance links to build the access chain |
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
| `add_credential` | `username`, `secret`, `secret_type`, `domain`, `source`, `via_access_id`, `via_vuln_id`, `discovered_by` | Record a credential (deduplicates on username+type+secret) |
| `update_credential` | `id` (required), `cracked`, `secret`, `notes`, `via_vuln_id`, `in_graph` | Update credential (e.g., mark hash as cracked, hide superseded hash from graph) |
| `test_credential` | `credential_id`, `ip`, `service`, `works` (all required) | Record whether a credential works against a target/service |
| `add_access` | `ip` (required), `access_type`, `username`, `privilege`, `method`, `session_ref`, `via_credential_id`, `via_access_id`, `via_vuln_id`, `technique_id`, `chain_order`, `discovered_by` | Record a new foothold on a target (chain provenance via credential, access, or vuln) |
| `update_access` | `id` (required), `active`, `username`, `access_type`, `privilege`, `notes`, `via_credential_id`, `via_access_id`, `via_vuln_id`, `technique_id`, `in_graph` | Update access record (e.g., revoke, fix provenance, patch username). Restores pruned sibling vulns on revocation |
| `add_vuln` | `title` (required), `ip` (required), `vuln_type`, `severity`, `status`, `details`, `evidence_path`, `via_access_id`, `via_credential_id`, `technique_id`, `chain_order`, `discovered_by` | Record a vulnerability (deduplicates on target+title) |
| `update_vuln` | `id` (required), `status`, `severity`, `details`, `in_graph`, `via_access_id`, `via_credential_id`, `technique_id` | Update vulnerability status (found/exploited/blocked). Auto-prunes sibling found vulns on exploit, restores on block |
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

Schema versioning uses `PRAGMA user_version` for future migrations. Current version: 18.

## Data

The database lives at `engagement/state.db` (relative to project root, not the
server directory). The `engagement/` directory is created by the orchestrator
and is gitignored.
