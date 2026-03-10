# Engagement State

red-run tracks all engagement data in a SQLite database at `engagement/state.db`. This database persists across context compactions, so targets, credentials, vulnerabilities, and access records survive long multi-hour engagements where conversation history is trimmed.

The orchestrator is the sole owner of engagement state. It creates the database, writes all records, and uses the state to make routing decisions — which skill to run next, which credentials to spray, which vulnerabilities to chain.

## Engagement directory

```
engagement/
├── scope.md          # Target scope, credentials, rules of engagement
├── state.db          # SQLite engagement state
├── activity.md       # Chronological action log (orchestrator writes)
├── findings.md       # Confirmed vulnerabilities (orchestrator writes)
└── evidence/         # Saved output, responses, dumps
    └── logs/         # Subagent JSONL transcripts
```

The orchestrator creates this directory at the start of an engagement. Skills degrade gracefully when it doesn't exist — they just skip logging.

## Schema

The database has 10 tables:

| Table | Purpose | Key Fields |
|-------|---------|------------|
| `engagement` | Singleton — engagement metadata | name, status, timestamps |
| `targets` | Host IPs and hostnames | host, os, role |
| `ports` | Per-target open ports (1:many from targets) | port, protocol, service, banner |
| `credentials` | Username/secret pairs | username, secret, secret_type, domain |
| `credential_access` | Where each credential has been tested | credential_id, target_id, service, works |
| `access` | Active footholds and sessions | host, access_type, username, privilege |
| `vulns` | Confirmed vulnerabilities | title, host, vuln_type, severity, status |
| `pivot_map` | Directed edges — what leads where | source, destination, method, status |
| `blocked` | Failed techniques with reasons | technique, reason, host, retry |
| `state_events` | Event log for interim writes | event_type, table_name, row_id, agent |

### Credential types

The `secret_type` field in `credentials` supports: `password`, `ntlm_hash`, `aes_key`, `kerberos_tgt`, `kerberos_tgs`, `ssh_key`, `token`, `certificate`, `other`.

### Vulnerability lifecycle

Vulns have three statuses:

- **found** — Identified but not yet exploited
- **active** — Currently being exploited
- **done** — Fully exploited, access obtained

### Pivot map

The `pivot_map` table captures directed edges showing how findings chain together:

```
SQLi on 10.10.10.5:/search  →  DB creds for 10.10.10.1:mssql
ADCS ESC1 on DC01            →  Domain Admin TGT
```

The orchestrator reads the pivot map to identify unexploited chains and decide which skill to invoke next.

## Three-mode architecture

The state-server runs as three MCP instances from the same codebase, each with different write permissions:

```mermaid
graph LR
    Orch[Orchestrator] -->|full read/write| SW[(state-writer)]
    Agents[All Agents] -->|read + 5 adds| SI[(state-interim)]
    SW --> DB[(state.db)]
    SI --> DB
```

| Mode | Instance | Agents | Write Access |
|------|----------|--------|--------------|
| `read` | state-reader | (retained for fallback) | None — read only |
| `interim` | state-interim | All agents | 5 add-only tools |
| `write` | state-writer | Orchestrator only | All read + write + update tools |

### Why interim mode exists

Agents run for 5-15 minutes. Without interim writes, credentials captured at minute 2 aren't visible to concurrent agents or the orchestrator until the agent finishes and the orchestrator parses its return summary. Interim mode solves this by letting all agents write critical discoveries immediately — especially important for technique agents that capture hashes or credentials during exploitation.

The five interim tools are all **add-only** (INSERT, never UPDATE):

| Tool | What it records | Why it's actionable |
|------|----------------|-------------------|
| `add_credential` | Passwords, hashes, keys, tokens | Orchestrator can route cracking or spray immediately |
| `add_vuln` | Confirmed vulnerabilities | Orchestrator can route exploitation |
| `add_pivot` | What leads where | Orchestrator can plan chains |
| `add_blocked` | Failed techniques | Prevents other agents from retrying |
| `add_tunnel` | Established tunnels | Orchestrator can route through new network paths |

Target/port/access management and all UPDATE operations remain orchestrator-only to prevent contention.

### Concurrency

SQLite WAL mode + `PRAGMA busy_timeout=5000` handles concurrent readers and interim writers safely. Interim agents only INSERT into separate tables, so write conflicts are prevented by the busy timeout.

## How state drives chaining

The orchestrator uses state queries to make routing decisions:

```
get_state_summary()           → Full engagement snapshot (~200 lines)
get_credentials(untested_only=True) → Creds not yet tested everywhere
get_vulns(status="found")     → Vulns ready to exploit
get_pivot_map()               → Chains to follow
get_blocked()                 → Dead ends to avoid
get_access(active_only=True)  → Current footholds
```

**Chaining example:**

1. `web-discovery` finds SQLi on `10.10.10.5:/search` → writes `add_vuln`
2. Orchestrator sees the vuln, spawns `web-exploit` with `sql-injection-union` skill
3. `web-exploit` dumps DB creds → reports in return summary
4. Orchestrator writes creds to state, spawns `password-spray` to test against all targets
5. Creds work on `10.10.10.1:winrm` → orchestrator records access, spawns `windows-privesc`

Each step is driven by state queries — the orchestrator checks what's known, what's untested, and what chains are available.

## Event polling

Each interim write (add_credential, add_vuln, add_pivot, add_blocked) emits a row in the `state_events` table.

### Event watcher (push notification)

When the orchestrator spawns a discovery agent, it also spawns `event-watcher.sh` as a background process. This script is a Python loop that polls `state_events` for new rows. When it detects a change, it exits — and the process termination acts as a push notification to the orchestrator. The orchestrator sees the background process end, checks the database for interim findings, and can route accordingly (e.g., spray newly discovered credentials against other targets).

Without this, the orchestrator would have to continuously poll the database itself between agent turns, wasting tokens on repeated `poll_events()` calls that usually return nothing.

```bash
# Orchestrator spawns this in the background alongside each discovery agent
bash tools/hooks/event-watcher.sh <cursor> engagement/state.db
```

The watcher polls every 5 seconds, debounces for 5 seconds after detecting events (to let the agent finish its batch), and has a 10-minute timeout to prevent zombie processes.

### Direct polling

The orchestrator can also query events directly via the state-writer MCP:

```
poll_events(since_id=0)  → Returns new events + cursor for next call
```

This is useful for checking what happened after a watcher fires, or when the orchestrator needs to inspect events at specific checkpoints.

## Manual queries

You can inspect the database directly with `sqlite3`:

```bash
sqlite3 engagement/state.db
```

```sql
-- All targets with open ports
SELECT t.host, t.os, p.port, p.service
FROM targets t JOIN ports p ON t.id = p.target_id
WHERE p.state = 'open' ORDER BY t.host, p.port;

-- Untested credentials
SELECT c.username, c.secret_type, c.domain
FROM credentials c
WHERE c.id NOT IN (SELECT credential_id FROM credential_access);

-- Active footholds
SELECT host, access_type, username, privilege
FROM access WHERE active = 1;

-- Pivot chains
SELECT source, destination, method, status
FROM pivot_map ORDER BY id;

-- What failed and why
SELECT technique, host, reason, retry
FROM blocked ORDER BY id;

-- Recent interim events
SELECT id, event_type, table_name, summary, created_at
FROM state_events ORDER BY id DESC LIMIT 20;
```

> **WAL mode:** The database uses WAL mode, so you can query it while the engagement is running without blocking agents. Use `.mode column` and `.headers on` in sqlite3 for readable output.

## Schema versioning

The database uses `PRAGMA user_version` for schema versioning. The `init_engagement()` tool creates all tables with `CREATE TABLE IF NOT EXISTS`, making it safe to call multiple times. Future migrations will increment `user_version` and apply ALTER statements.
