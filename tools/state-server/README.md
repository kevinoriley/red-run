# state MCP Server

MCP server providing SQLite-backed engagement state management for red-run.
Runs as three instances from the same codebase — a read-only `state-reader`
for technique agents, an `state-interim` with 4 add-only write tools for
discovery agents, and a full read-write `state-writer` for the orchestrator.
All three open the same `engagement/state.db`.

## Prerequisites

### Install Python dependencies

```bash
uv sync --directory tools/state-server
```

## Usage

The server runs as an MCP server, started automatically by Claude Code via
`.mcp.json`. Three instances are configured — one per mode:

```bash
# Read-only (technique agents)
uv run --directory tools/state-server python server.py --mode read

# Read + 4 add-only writes (discovery agents)
uv run --directory tools/state-server python server.py --mode interim

# Read + all writes (orchestrator)
uv run --directory tools/state-server python server.py --mode write
```

### Three-mode architecture

| Mode | Instance | Agents | Write Access |
|------|----------|--------|-------------|
| `read` | state-reader | Technique agents (web-exploit, ad-exploit, etc.) | None |
| `interim` | state-interim | Discovery agents (network-recon, web-discovery, ad-discovery, linux-privesc, windows-privesc) | 4 add-only tools: `add_credential`, `add_vuln`, `add_pivot`, `add_blocked` |
| `write` | state-writer | Orchestrator only | All read + write tools |

**Why interim mode?** Discovery agents run for 5-15 minutes. Without interim
writes, credentials found at minute 2 aren't visible to concurrent agents
until the discovery agent returns. Interim mode lets discovery agents write
actionable findings immediately so the orchestrator and concurrent agents can
see them mid-run.

**Why only 4 tools?** These are add-only (INSERT), never update existing
records, and represent findings that other agents can act on immediately:
credentials (spray/test), vulns (exploit), pivots (plan chains), blocked
(skip dead ends). Target/port/access management and all UPDATE operations
remain orchestrator-only to avoid contention.

SQLite WAL mode + `PRAGMA busy_timeout=5000` handles concurrent readers and
interim writers safely. Interim agents only INSERT into separate tables, so
write conflicts with the orchestrator are prevented by the busy timeout.

### Typical workflow

1. Orchestrator calls `init_engagement()` to create `engagement/state.db`
2. Orchestrator records targets, ports, credentials, vulns via write tools
3. Agents call `get_state_summary()` on activation to read current state
4. Agents report findings in their return summary
5. Orchestrator parses returns and records state changes
6. Orchestrator calls `get_state_summary()` to decide next actions

## Tools

### Read tools (both modes)

| Tool | Parameters | Description |
|------|-----------|-------------|
| `get_state_summary` | `max_lines` (default 200) | Compact markdown summary of all engagement state |
| `get_targets` | `host` (optional filter) | Targets with their ports and services |
| `get_credentials` | `untested_only` (default false) | Credentials with tested-against information |
| `get_access` | `target` (optional), `active_only` (default true) | Current footholds and sessions |
| `get_vulns` | `status` (optional), `target` (optional) | Confirmed vulnerabilities |
| `get_pivot_map` | `status` (optional) | Pivot path edges (what leads where) |
| `get_blocked` | `target` (optional) | Failed technique attempts |

### Interim tools (interim mode only)

| Tool | Parameters | Description |
|------|-----------|-------------|
| `add_credential` | `username`, `secret`, `secret_type`, `domain`, `source` | Record a credential (password, hash, key, token) |
| `add_vuln` | `title` (required), `host`, `vuln_type`, `severity`, `endpoint`, `details` | Record a confirmed vulnerability |
| `add_pivot` | `source`, `destination` (required), `method`, `status` | Record a pivot path |
| `add_blocked` | `technique`, `reason` (required), `host`, `retry`, `notes` | Record a blocked/failed technique |

### Write tools (write mode only)

| Tool | Parameters | Description |
|------|-----------|-------------|
| `init_engagement` | `name` (optional) | Create state.db with full schema |
| `close_engagement` | (none) | Mark engagement as closed |
| `add_target` | `host` (required), `os`, `role`, `notes`, `ports` (JSON) | Add or update a target host (upserts on host) |
| `update_target` | `host` (required), `os`, `role`, `notes` | Update fields on an existing target |
| `add_port` | `host` (required), `port` (required), `protocol`, `service`, `banner` | Add port to target (upserts on target+port+protocol) |
| `add_credential` | `username`, `secret`, `secret_type`, `domain`, `source` | Record a credential (password, hash, key, token) |
| `update_credential` | `id` (required), `cracked`, `secret`, `notes` | Update credential (e.g., mark hash as cracked) |
| `test_credential` | `credential_id`, `host`, `service`, `works` (all required) | Record whether a credential works against a target/service |
| `add_access` | `host` (required), `access_type`, `username`, `privilege`, `method` | Record a new foothold on a target |
| `update_access` | `id` (required), `active`, `privilege`, `notes` | Update access record (e.g., revoke) |
| `add_vuln` | `title` (required), `host`, `vuln_type`, `severity`, `endpoint`, `details` | Record a confirmed vulnerability |
| `update_vuln` | `id` (required), `status`, `severity`, `details` | Update vulnerability status |
| `add_pivot` | `source`, `destination` (required), `method`, `status` | Record a pivot path |
| `update_pivot` | `id` (required), `status`, `notes` | Update pivot path status |
| `add_blocked` | `technique`, `reason` (required), `host`, `retry`, `notes` | Record a blocked/failed technique |

## Schema

The database has 8 tables:

| Table | Purpose |
|-------|---------|
| `engagement` | Singleton row — engagement name, status, timestamps |
| `targets` | Host IPs/hostnames, OS, role |
| `ports` | Per-target ports, services, banners (1:many from targets) |
| `credentials` | Username/secret pairs with type (password, ntlm_hash, ssh_key, etc.) |
| `credential_access` | Where each credential has been tested and whether it worked |
| `access` | Active footholds — shells, sessions, tokens |
| `vulns` | Confirmed vulnerabilities with severity and status |
| `pivot_map` | Directed edges showing what leads where |
| `blocked` | Failed techniques with reasons and retry assessment |

Schema versioning uses `PRAGMA user_version` for future migrations.

## Data

The database lives at `engagement/state.db` (relative to project root, not the
server directory). The `engagement/` directory is created by the orchestrator
and is gitignored.
