# Engagement State

red-run tracks all engagement data in a SQLite database at `engagement/state.db`. This database persists across context compactions, so targets, credentials, vulnerabilities, and access records survive long multi-hour engagements where conversation history is trimmed.

State writes are centralized through the **state-mgr** teammate — the sole writer to state.db. Other teammates and the lead send structured messages to state-mgr instead of writing directly. State reads are direct (any teammate, any time). The lead uses state queries to make routing decisions — which skill to assign next, which credentials to test, which vulnerabilities to chain.

## Engagement directory

```
engagement/
├── scope.md          # Target scope, credentials, rules of engagement
├── state.db          # SQLite engagement state
├── dump-state.sh     # Export state.db as markdown (from operator/templates/)
└── evidence/         # Saved output, responses, dumps
    └── logs/         # Teammate JSONL transcripts
```

The orchestrator creates this directory at the start of an engagement. Skills degrade gracefully when it doesn't exist — they just skip logging.

### dump-state.sh

The orchestrator copies `operator/templates/dump-state.sh` into the engagement directory at init time. Run it to view or back up state as markdown:

```bash
cd engagement && bash dump-state.sh
bash dump-state.sh --db /path/to/state.db > snapshot.md
```

Produces the same sections as `get_state_summary()` but without truncation limits, plus a Timeline section showing all `state_events` rows.

## Schema

The database has 10 tables:

| Table | Purpose | Key Fields |
|-------|---------|------------|
| `engagement` | Singleton — engagement metadata | name, status, timestamps |
| `targets` | Host IPs and hostnames | host, os, role |
| `ports` | Per-target open ports (1:many from targets) | port, protocol, service, banner |
| `credentials` | Username/secret pairs | username, secret, secret_type, domain |
| `credential_access` | Where each credential has been tested | credential_id, target_id, service, works |
| `access` | Active footholds and sessions | ip, access_type, username, privilege, via_credential_id, via_access_id, via_vuln_id |
| `vulns` | Confirmed vulnerabilities | title, host, vuln_type, severity, status |
| `pivot_map` | Directed edges — what leads where | source, destination, method, status |
| `blocked` | Failed techniques with reasons | technique, reason, host, retry |
| `state_events` | Event log for state writes | event_type, table_name, row_id, agent |

### Credential types

The `secret_type` field in `credentials` supports: `password`, `ntlm_hash`, `net_ntlm`, `aes_key`, `kerberos_tgt`, `kerberos_tgs`, `dcc2`, `ssh_key`, `token`, `certificate`, `webapp_hash`, `dpapi`, `other`.

### Vulnerability lifecycle

Vulns have three statuses:

- **found** — Identified but not yet actioned
- **exploited** — Successfully actioned, access obtained
- **blocked** — Exploitation attempted but failed or not possible

### Pivot map

The `pivot_map` table captures directed edges showing how findings chain together:

```
SQLi on 10.10.10.5:/search  →  DB creds for 10.10.10.1:mssql
ADCS ESC1 on DC01            →  Domain Admin TGT
```

The orchestrator reads the pivot map to identify un-actioned chains and decide which skill to invoke next.

## State server architecture

The state-server runs as a single MCP instance. In the agent teams model, all state writes are centralized through state-mgr:

```
Lead ──messages──► state-mgr ──writes──► state.db
Teammates ──messages──► state-mgr ──writes──► state.db
Any teammate ──reads──► state.db (direct, any time)
```

State-mgr provides LLM-level deduplication that database constraints can't (e.g., "LFI file read" vs "LFI via absolute path" are the same vuln). It also enforces provenance linking — credentials from active techniques must have a corresponding vuln record. DB-level dedup (UNIQUE constraints) remains as a safety net.

### Concurrency

SQLite WAL mode + `PRAGMA busy_timeout=30000` handles concurrent readers and writers safely. The 30-second timeout accommodates agent teams where multiple teammates may read simultaneously while state-mgr writes.

## How state drives chaining

The orchestrator uses state queries to make routing decisions:

```
get_state_summary()           → Full engagement snapshot (~200 lines)
get_credentials(untested_only=True) → Creds not yet tested everywhere
get_vulns(status="found")     → Vulns not yet actioned
get_pivot_map()               → Chains to follow
get_blocked()                 → Dead ends to avoid
get_access(active_only=True)  → Current footholds
```

**Chaining example:**

1. `web-enum` finds SQLi on `10.10.10.5:/search` → messages state-mgr with `[add-vuln]`
2. Lead sees the vuln, assigns `sql-injection-union` skill to `web-ops`
3. `web-ops` dumps DB creds → messages state-mgr with `[add-cred]`
4. Lead assigns credential testing to `net-enum`, spawns `spray` teammate
5. Creds work on `10.10.10.1:winrm` → state-mgr records access, lead spawns `win-enum`

Each step is driven by state queries — the orchestrator checks what's known, what's untested, and what chains are available.

## Event polling

Each state write (add_credential, add_vuln, add_pivot, add_blocked, etc.) emits a row in the `state_events` table.

### Teammate messaging as notification channel

In the agent teams model, teammate messages replace the v1 event watcher. When a teammate discovers something actionable mid-task, it messages the lead immediately. The lead checks state and acts — this is the primary notification mechanism. Teammates also write to state.db (via state-mgr) for durability, but the message is what triggers the lead to look.

### Direct polling

The lead can also query events directly via the state MCP:

```
poll_events(since_id=0)  → Returns new events + cursor for next call
```

This is useful for checking what happened between tasks, or when the lead needs to inspect events at specific checkpoints.

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

-- Recent state events
SELECT id, event_type, table_name, summary, created_at
FROM state_events ORDER BY id DESC LIMIT 20;
```

> **WAL mode:** The database uses WAL mode, so you can query it while the engagement is running without blocking teammates. Use `.mode column` and `.headers on` in sqlite3 for readable output.

## Schema versioning

The database uses `PRAGMA user_version` for schema versioning. The `init_engagement()` tool creates all tables with `CREATE TABLE IF NOT EXISTS`, making it safe to call multiple times. Future migrations will increment `user_version` and apply ALTER statements.
