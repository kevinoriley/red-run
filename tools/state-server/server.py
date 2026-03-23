"""MCP server for SQLite-backed engagement state management.

Single-mode server — all tools (read + write) are always available.
Every agent and the orchestrator connect to the same instance.

All write operations emit state_events rows for real-time monitoring
via poll_events(). Deduplication is built into add_vuln() and
add_credential() to handle concurrent writes from multiple agents.

Usage:
    uv run python server.py
"""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from schema import init_db

# Resolve engagement directory relative to the project root, not the server's
# own directory.  uv run --directory changes cwd to tools/state-server/, so
# bare Path("engagement/...") would land artifacts inside the tools tree.
_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
DB_PATH = _PROJECT_ROOT / "engagement" / "state.db"


@contextmanager
def _get_db():
    """Open connection to the state database with guaranteed cleanup."""
    if not DB_PATH.exists():
        raise FileNotFoundError(
            "No engagement state database found. "
            "The orchestrator must call init_engagement() first."
        )
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=30000")
    try:
        yield conn
    finally:
        conn.close()


def _rows_to_dicts(rows: list[sqlite3.Row]) -> list[dict]:
    """Convert sqlite3.Row objects to plain dicts for JSON serialization."""
    return [dict(row) for row in rows]


def _resolve_target_id(conn: sqlite3.Connection, host: str) -> int | None:
    """Look up target_id by host. Returns None if not found."""
    row = conn.execute("SELECT id FROM targets WHERE host = ?", (host,)).fetchone()
    return row["id"] if row else None


def _now_sql() -> str:
    """SQLite expression for current UTC timestamp."""
    return "strftime('%Y-%m-%dT%H:%M:%SZ', 'now')"


def _emit_event(
    conn: sqlite3.Connection,
    event_type: str,
    record_id: int,
    summary: str,
    agent: str = "",
) -> None:
    """Insert a state_events row inside the current transaction.

    Called by all write tools so agents and the orchestrator can poll for
    real-time findings via poll_events().  Silently skips if the table
    doesn't exist (older DBs without the v2 schema).
    """
    try:
        conn.execute(
            "INSERT INTO state_events (event_type, record_id, summary, agent) "
            "VALUES (?, ?, ?, ?)",
            (event_type, record_id, summary, agent),
        )
    except sqlite3.OperationalError:
        pass  # table doesn't exist in older DBs — skip silently


# ---------------------------------------------------------------------------
# Server setup
# ---------------------------------------------------------------------------


def create_server() -> FastMCP:
    """Create and configure the state MCP server."""
    mcp = FastMCP(
        "red-run-state",
        instructions=(
            "Provides engagement state management for red-run. "
            "Full read/write access to engagement state. Use write tools "
            "to record targets, credentials, access, vulns, pivots, and "
            "blocked items. Use get_state_summary() for a compact overview."
        ),
    )

    # ------------------------------------------------------------------
    # Read tools
    # ------------------------------------------------------------------

    @mcp.tool()
    def get_state_summary(max_lines: int = 200) -> str:
        """Get compact markdown summary of engagement state.

        Returns the same format as the old state.md — a compact snapshot
        of targets, credentials, access, vulns, pivot map, and blocked items.
        Capped at max_lines to prevent context bloat.

        Args:
            max_lines: Maximum lines in the summary (default 200).
        """
        try:
            db = _get_db()
        except FileNotFoundError:
            return "No engagement state database found. Run init_engagement() first."

        with db as conn:
            sections: list[str] = ["# Engagement State\n"]

            # Engagement metadata
            eng = conn.execute(
                "SELECT name, status, created_at, mode FROM engagement WHERE id = 1"
            ).fetchone()
            if eng:
                sections.append(
                    f"**Mode: {eng['mode']}** | Status: {eng['status']} | Created: {eng['created_at']}\n"
                )

            # Targets
            sections.append("## Targets\n")
            targets = conn.execute(
                "SELECT t.id, t.host, t.os, t.role FROM targets t ORDER BY t.id"
            ).fetchall()
            for t in targets:
                ports = conn.execute(
                    "SELECT port, protocol, service FROM ports "
                    "WHERE target_id = ? ORDER BY port",
                    (t["id"],),
                ).fetchall()
                port_str = ",".join(
                    f"{p['port']}/{p['protocol']}"
                    if p["protocol"] != "tcp"
                    else str(p["port"])
                    for p in ports
                )
                svc_str = ",".join(p["service"] for p in ports if p["service"])
                parts = [t["host"]]
                if t["os"]:
                    parts.append(t["os"])
                if t["role"]:
                    parts.append(t["role"])
                if port_str:
                    parts.append(port_str)
                if svc_str:
                    parts.append(f"({svc_str})")
                sections.append(f"- {' | '.join(parts)}")
            if not targets:
                sections.append("_(none)_")
            sections.append("")

            # Credentials — skip uncracked capture hashes (net_ntlm, kerberos_tgs,
            # dcc2, webapp_hash) to keep summary compact. They're still in the DB
            # and visible via get_credentials(). Show them once cracked.
            sections.append("## Credentials\n")
            creds = conn.execute(
                "SELECT id, username, secret, secret_type, domain, cracked, notes "
                "FROM credentials "
                "WHERE cracked = 1 "
                "   OR secret_type NOT IN ('net_ntlm', 'kerberos_tgs', 'dcc2', 'webapp_hash') "
                "ORDER BY id"
            ).fetchall()
            for c in creds:
                display_secret = c["secret"]
                if c["secret_type"] not in ("password",) and len(display_secret) > 32:
                    display_secret = display_secret[:32] + "..."
                parts = []
                if c["domain"]:
                    parts.append(f"{c['domain']}\\{c['username']}")
                else:
                    parts.append(c["username"])
                parts.append(f"{display_secret} ({c['secret_type']})")
                if c["cracked"]:
                    parts.append("[cracked]")
                # Show where it works
                access_rows = conn.execute(
                    "SELECT t.host, ca.service, ca.works FROM credential_access ca "
                    "JOIN targets t ON ca.target_id = t.id "
                    "WHERE ca.credential_id = ?",
                    (c["id"],),
                ).fetchall()
                works_on = [
                    f"{r['host']}:{r['service']}" for r in access_rows if r["works"]
                ]
                fails_on = [
                    f"{r['host']}:{r['service']}" for r in access_rows if not r["works"]
                ]
                if works_on:
                    parts.append(f"works: {', '.join(works_on)}")
                if fails_on:
                    parts.append(f"fails: {', '.join(fails_on)}")
                if c["notes"]:
                    parts.append(c["notes"])
                sections.append(f"- {' | '.join(parts)}")
            if not creds:
                sections.append("_(none)_")
            # Note hidden uncracked hashes
            hidden = conn.execute(
                "SELECT COUNT(*) as cnt FROM credentials "
                "WHERE cracked = 0 AND secret_type IN ('net_ntlm', 'kerberos_tgs', 'dcc2', 'webapp_hash')"
            ).fetchone()["cnt"]
            if hidden:
                sections.append(f"_({hidden} uncracked hash(es) hidden — use get_credentials() to view)_")
            sections.append("")

            # Access
            sections.append("## Access\n")
            accesses = conn.execute(
                "SELECT a.*, t.host FROM access a "
                "JOIN targets t ON a.target_id = t.id "
                "WHERE a.active = 1 ORDER BY a.id"
            ).fetchall()
            for a in accesses:
                parts = [
                    a["host"],
                    f"{a['username']} via {a['access_type']}",
                    f"[{a['privilege']}]",
                ]
                if a["method"]:
                    parts.append(f"from {a['method']}")
                if a["session_ref"]:
                    parts.append(f"session:{a['session_ref']}")
                if a["notes"]:
                    parts.append(a["notes"])
                sections.append(f"- {' | '.join(parts)}")
            # Also show revoked access
            revoked = conn.execute(
                "SELECT a.*, t.host FROM access a "
                "JOIN targets t ON a.target_id = t.id "
                "WHERE a.active = 0 ORDER BY a.id"
            ).fetchall()
            for a in revoked:
                sections.append(
                    f"- ~~{a['host']} | {a['username']} via {a['access_type']}~~ [revoked]"
                )
            if not accesses and not revoked:
                sections.append("_(none)_")
            sections.append("")

            # Vulns
            sections.append("## Vulns\n")
            vulns = conn.execute(
                "SELECT v.*, t.host FROM vulns v "
                "LEFT JOIN targets t ON v.target_id = t.id "
                "ORDER BY v.id"
            ).fetchall()
            for v in vulns:
                host = v["host"] or "unknown"
                parts = [
                    f"{v['title']} [{v['status']}]",
                    f"[{v['severity']}]",
                    host,
                ]
                if v["details"]:
                    parts.append(v["details"][:80])
                sections.append(f"- {' | '.join(parts)}")
            if not vulns:
                sections.append("_(none)_")
            sections.append("")

            # Pivot Map
            sections.append("## Pivot Map\n")
            pivots = conn.execute("SELECT * FROM pivot_map ORDER BY id").fetchall()
            for p in pivots:
                parts = [
                    f"{p['source']} -> {p['destination']}",
                    f"via {p['method']}" if p["method"] else "",
                    f"[{p['status']}]",
                ]
                if p["notes"]:
                    parts.append(p["notes"])
                sections.append(f"- {' | '.join(pt for pt in parts if pt)}")
            if not pivots:
                sections.append("_(none)_")
            sections.append("")

            # Tunnels
            sections.append("## Tunnels\n")
            if conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='tunnels'"
            ).fetchone():
                tunnels = conn.execute(
                    "SELECT * FROM tunnels WHERE status != 'closed' ORDER BY id"
                ).fetchall()
                for tun in tunnels:
                    proxy_note = (
                        "(proxychains required)"
                        if tun["requires_proxychains"]
                        else "(transparent)"
                    )
                    parts = [
                        tun["tunnel_type"],
                        f"via {tun['pivot_host']}" if tun["pivot_host"] else "",
                        f"→ {tun['target_subnet']}" if tun["target_subnet"] else "→ *",
                    ]
                    if tun["local_endpoint"]:
                        parts.append(tun["local_endpoint"])
                    parts.append(f"[{tun['status']}]")
                    parts.append(proxy_note)
                    if tun["notes"]:
                        parts.append(tun["notes"])
                    sections.append(f"- {' | '.join(pt for pt in parts if pt)}")
                if not tunnels:
                    sections.append("_(none)_")
            else:
                sections.append("_(none)_")
            sections.append("")

            # Blocked
            sections.append("## Blocked\n")
            blocked = conn.execute(
                "SELECT b.*, t.host FROM blocked b "
                "LEFT JOIN targets t ON b.target_id = t.id "
                "ORDER BY b.id"
            ).fetchall()
            for b in blocked:
                host = b["host"] or ""
                parts = [b["technique"]]
                if host:
                    parts.append(host)
                parts.append(b["reason"])
                parts.append(f"[{b['retry']}]")
                if b["notes"]:
                    parts.append(b["notes"])
                sections.append(f"- {' | '.join(parts)}")
            if not blocked:
                sections.append("_(none)_")

            result = "\n".join(sections)
            lines = result.split("\n")
            if len(lines) > max_lines:
                lines = lines[:max_lines]
                lines.append(f"\n_(truncated at {max_lines} lines)_")
            return "\n".join(lines)

    @mcp.tool()
    def get_targets(host: str = "") -> str:
        """Get targets with their ports and services.

        Args:
            host: Filter by host (empty = all targets).
        """
        with _get_db() as conn:
            if host:
                targets = conn.execute(
                    "SELECT * FROM targets WHERE host = ?", (host,)
                ).fetchall()
            else:
                targets = conn.execute("SELECT * FROM targets ORDER BY id").fetchall()

            result = []
            for t in targets:
                t_dict = dict(t)
                ports = conn.execute(
                    "SELECT port, protocol, state, service, banner FROM ports "
                    "WHERE target_id = ? ORDER BY port",
                    (t["id"],),
                ).fetchall()
                t_dict["ports"] = _rows_to_dicts(ports)
                result.append(t_dict)

            return json.dumps(result, indent=2)

    @mcp.tool()
    def get_credentials(untested_only: bool = False) -> str:
        """Get credentials with tested-against information.

        Args:
            untested_only: If true, only return credentials that haven't been
                          tested against all known target/service combinations.
        """
        with _get_db() as conn:
            creds = conn.execute("SELECT * FROM credentials ORDER BY id").fetchall()

            result = []
            for c in creds:
                c_dict = dict(c)
                access_rows = conn.execute(
                    "SELECT ca.*, t.host FROM credential_access ca "
                    "JOIN targets t ON ca.target_id = t.id "
                    "WHERE ca.credential_id = ?",
                    (c["id"],),
                ).fetchall()
                c_dict["tested_against"] = _rows_to_dicts(access_rows)

                if untested_only:
                    # Count total target/service combos vs tested
                    tested_count = len(access_rows)
                    total_targets = conn.execute(
                        "SELECT COUNT(*) as cnt FROM targets"
                    ).fetchone()["cnt"]
                    if tested_count >= total_targets and total_targets > 0:
                        continue

                result.append(c_dict)

            return json.dumps(result, indent=2)

    @mcp.tool()
    def get_access(target: str = "", active_only: bool = True) -> str:
        """Get current footholds/access.

        Args:
            target: Filter by target host (empty = all).
            active_only: Only return active sessions (default true).
        """
        with _get_db() as conn:
            query = "SELECT a.*, t.host FROM access a JOIN targets t ON a.target_id = t.id"
            conditions = []
            params: list = []

            if target:
                conditions.append("t.host = ?")
                params.append(target)
            if active_only:
                conditions.append("a.active = 1")

            if conditions:
                query += " WHERE " + " AND ".join(conditions)
            query += " ORDER BY a.id"

            rows = conn.execute(query, params).fetchall()
            return json.dumps(_rows_to_dicts(rows), indent=2)

    @mcp.tool()
    def get_vulns(status: str = "", target: str = "") -> str:
        """Get vulnerabilities.

        Args:
            status: Filter by status (found/exploited/blocked, empty = all).
            target: Filter by target host (empty = all).
        """
        with _get_db() as conn:
            query = (
                "SELECT v.*, t.host FROM vulns v LEFT JOIN targets t ON v.target_id = t.id"
            )
            conditions = []
            params: list = []

            if status:
                conditions.append("v.status = ?")
                params.append(status)
            if target:
                conditions.append("t.host = ?")
                params.append(target)

            if conditions:
                query += " WHERE " + " AND ".join(conditions)
            query += " ORDER BY v.id"

            rows = conn.execute(query, params).fetchall()
            return json.dumps(_rows_to_dicts(rows), indent=2)

    @mcp.tool()
    def get_pivot_map(status: str = "") -> str:
        """Get pivot map edges.

        Args:
            status: Filter by status (identified/exploited/blocked, empty = all).
        """
        with _get_db() as conn:
            if status:
                rows = conn.execute(
                    "SELECT * FROM pivot_map WHERE status = ? ORDER BY id",
                    (status,),
                ).fetchall()
            else:
                rows = conn.execute("SELECT * FROM pivot_map ORDER BY id").fetchall()
            return json.dumps(_rows_to_dicts(rows), indent=2)

    @mcp.tool()
    def get_blocked(target: str = "") -> str:
        """Get blocked techniques.

        Args:
            target: Filter by target host (empty = all).
        """
        with _get_db() as conn:
            if target:
                rows = conn.execute(
                    "SELECT b.*, t.host FROM blocked b "
                    "LEFT JOIN targets t ON b.target_id = t.id "
                    "WHERE t.host = ? ORDER BY b.id",
                    (target,),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT b.*, t.host FROM blocked b "
                    "LEFT JOIN targets t ON b.target_id = t.id "
                    "ORDER BY b.id"
                ).fetchall()
            return json.dumps(_rows_to_dicts(rows), indent=2)

    @mcp.tool()
    def get_tunnels(status: str = "", pivot_host: str = "") -> str:
        """Get active tunnels.

        Args:
            status: Filter by status (active/down/closed, empty = all).
            pivot_host: Filter by pivot host (empty = all).
        """
        with _get_db() as conn:
            # Backward compat: check table exists
            if not conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='tunnels'"
            ).fetchone():
                return json.dumps([])

            query = "SELECT * FROM tunnels"
            conditions = []
            params: list = []

            if status:
                conditions.append("status = ?")
                params.append(status)
            if pivot_host:
                conditions.append("pivot_host = ?")
                params.append(pivot_host)

            if conditions:
                query += " WHERE " + " AND ".join(conditions)
            query += " ORDER BY id"

            rows = conn.execute(query, params).fetchall()
            return json.dumps(_rows_to_dicts(rows), indent=2)

    @mcp.tool()
    def poll_events(since_id: int = 0, limit: int = 50) -> str:
        """Poll for state events since a checkpoint.

        Returns new events written by agents plus a cursor for the next call.
        Use this for real-time monitoring of findings as they happen — call
        repeatedly with the returned cursor.

        Args:
            since_id: Last event ID seen (0 = from the beginning).
            limit: Maximum events to return (default 50).
        """
        try:
            db = _get_db()
        except FileNotFoundError:
            return json.dumps({"events": [], "cursor": 0, "count": 0})

        with db as conn:
            # Backward compat: check table exists (older DBs without v2 schema)
            if not conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='state_events'"
            ).fetchone():
                return json.dumps({"events": [], "cursor": 0, "count": 0})

            rows = conn.execute(
                "SELECT * FROM state_events WHERE id > ? ORDER BY id LIMIT ?",
                (since_id, limit),
            ).fetchall()
            events = _rows_to_dicts(rows)
            cursor = events[-1]["id"] if events else since_id
            return json.dumps(
                {"events": events, "cursor": cursor, "count": len(events)},
                indent=2,
            )

    # ------------------------------------------------------------------
    # Write tools
    # ------------------------------------------------------------------

    @mcp.tool()
    def init_engagement(name: str = "", mode: str = "ctf") -> str:
        """Initialize the engagement state database.

        Creates engagement/state.db with the full schema. Safe to call
        multiple times — uses CREATE TABLE IF NOT EXISTS.

        Args:
            name: Optional engagement name.
            mode: Engagement mode — 'ctf' (default) or 'pentest'.
        """
        if mode not in ("ctf", "pentest"):
            return json.dumps(
                {"error": f"Invalid mode '{mode}'. Must be 'ctf' or 'pentest'."}
            )
        DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        conn = init_db(DB_PATH)
        try:
            # Insert singleton engagement row if not exists
            existing = conn.execute("SELECT id FROM engagement WHERE id = 1").fetchone()
            if not existing:
                conn.execute(
                    "INSERT INTO engagement (id, name, mode) VALUES (1, ?, ?)",
                    (name, mode),
                )
            else:
                updates = ["mode = ?"]
                params: list[str] = [mode]
                if name:
                    updates.append("name = ?")
                    params.append(name)
                conn.execute(
                    f"UPDATE engagement SET {', '.join(updates)} WHERE id = 1",
                    params,
                )
            conn.commit()
        finally:
            conn.close()
        return json.dumps(
            {
                "status": "initialized",
                "db_path": str(DB_PATH),
                "name": name,
                "mode": mode,
            },
            indent=2,
        )

    @mcp.tool()
    def close_engagement() -> str:
        """Mark the engagement as closed."""
        with _get_db() as conn:
            conn.execute(
                f"UPDATE engagement SET status = 'closed', "
                f"closed_at = {_now_sql()} WHERE id = 1"
            )
            conn.commit()
            return json.dumps({"status": "closed"})

    @mcp.tool()
    def add_target(
        host: str,
        os: str = "",
        role: str = "",
        notes: str = "",
        discovered_by: str = "",
        ports: str = "",
    ) -> str:
        """Add or update a target host. Upserts on host.

        Args:
            host: IP address or hostname.
            os: Operating system (e.g., "Ubuntu 22.04", "Windows Server 2019").
            role: Role (e.g., "DC", "Web", "DB").
            notes: Additional notes.
            discovered_by: Skill that discovered this target.
            ports: JSON array of port objects, each with: port (int),
                   protocol (str, default "tcp"), state (str, default "open"),
                   service (str), banner (str).
                   Example: [{"port": 80, "service": "http"}, {"port": 443, "service": "https"}]
        """
        with _get_db() as conn:
            existing = conn.execute(
                "SELECT id FROM targets WHERE host = ?", (host,)
            ).fetchone()

            if existing:
                target_id = existing["id"]
                updates = []
                params: list = []
                if os:
                    updates.append("os = ?")
                    params.append(os)
                if role:
                    updates.append("role = ?")
                    params.append(role)
                if notes:
                    updates.append("notes = ?")
                    params.append(notes)
                if discovered_by:
                    updates.append("discovered_by = ?")
                    params.append(discovered_by)
                if updates:
                    updates.append(f"updated_at = {_now_sql()}")
                    params.append(target_id)
                    conn.execute(
                        f"UPDATE targets SET {', '.join(updates)} WHERE id = ?",
                        params,
                    )
            else:
                cursor = conn.execute(
                    "INSERT INTO targets (host, os, role, notes, discovered_by) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (host, os, role, notes, discovered_by),
                )
                target_id = cursor.lastrowid

            # Process ports if provided
            if ports:
                port_list = json.loads(ports) if isinstance(ports, str) else ports
                for p in port_list:
                    port_num = p["port"]
                    protocol = p.get("protocol", "tcp")
                    state = p.get("state", "open")
                    service = p.get("service", "")
                    banner = p.get("banner", "")
                    conn.execute(
                        "INSERT INTO ports (target_id, port, protocol, state, service, banner) "
                        "VALUES (?, ?, ?, ?, ?, ?) "
                        "ON CONFLICT(target_id, port, protocol) DO UPDATE SET "
                        "state = excluded.state, "
                        "service = CASE WHEN excluded.service != '' THEN excluded.service ELSE ports.service END, "
                        "banner = CASE WHEN excluded.banner != '' THEN excluded.banner ELSE ports.banner END",
                        (target_id, port_num, protocol, state, service, banner),
                    )

            action = "updated" if existing else "created"
            _emit_event(conn, "target", target_id, f"{host} ({action})", discovered_by)
            conn.commit()
            return json.dumps(
                {
                    "target_id": target_id,
                    "host": host,
                    "action": action,
                },
                indent=2,
            )

    @mcp.tool()
    def update_target(
        host: str,
        os: str = "",
        role: str = "",
        notes: str = "",
    ) -> str:
        """Update fields on an existing target.

        Args:
            host: Target host to update (must exist).
            os: New OS value (empty = no change).
            role: New role value (empty = no change).
            notes: New notes value (empty = no change).
        """
        with _get_db() as conn:
            target_id = _resolve_target_id(conn, host)
            if target_id is None:
                return f"ERROR: Target '{host}' not found."

            updates = []
            params: list = []
            if os:
                updates.append("os = ?")
                params.append(os)
            if role:
                updates.append("role = ?")
                params.append(role)
            if notes:
                updates.append("notes = ?")
                params.append(notes)

            if not updates:
                return "No fields to update."

            updates.append(f"updated_at = {_now_sql()}")
            params.append(target_id)
            conn.execute(
                f"UPDATE targets SET {', '.join(updates)} WHERE id = ?",
                params,
            )
            conn.commit()
            return json.dumps({"target_id": target_id, "host": host, "updated": True})

    @mcp.tool()
    def add_port(
        host: str,
        port: int,
        protocol: str = "tcp",
        state: str = "open",
        service: str = "",
        banner: str = "",
    ) -> str:
        """Add a port to an existing target. Upserts on (target, port, protocol).

        Args:
            host: Target host (must exist).
            port: Port number.
            protocol: Protocol (default "tcp").
            state: Port state (default "open").
            service: Service name (e.g., "http", "ssh").
            banner: Service banner/version string.
        """
        with _get_db() as conn:
            target_id = _resolve_target_id(conn, host)
            if target_id is None:
                return f"ERROR: Target '{host}' not found. Add the target first."

            conn.execute(
                "INSERT INTO ports (target_id, port, protocol, state, service, banner) "
                "VALUES (?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(target_id, port, protocol) DO UPDATE SET "
                "state = excluded.state, "
                "service = CASE WHEN excluded.service != '' THEN excluded.service ELSE ports.service END, "
                "banner = CASE WHEN excluded.banner != '' THEN excluded.banner ELSE ports.banner END",
                (target_id, port, protocol, state, service, banner),
            )
            conn.commit()
            return json.dumps(
                {
                    "host": host,
                    "port": port,
                    "protocol": protocol,
                    "service": service,
                }
            )

    @mcp.tool()
    def add_credential(
        username: str = "",
        secret: str = "",
        secret_type: str = "password",
        domain: str = "",
        source: str = "",
        via_access_id: int | None = None,
        discovered_by: str = "",
    ) -> str:
        """Add a credential (password, hash, key, token, etc.).

        Deduplicates on (username, secret_type, secret). Returns existing
        record if duplicate found.

        Args:
            username: Username or account name.
            secret: The credential value (password, hash, key, token).
            secret_type: Type of secret: password, ntlm_hash, net_ntlm,
                        aes_key, kerberos_tgt, kerberos_tgs, dcc2,
                        ssh_key, token, certificate, webapp_hash,
                        dpapi, other.
            domain: Domain (for AD credentials).
            source: Where this credential was found.
            via_access_id: Access ID that led to finding this credential
                          (for kill-chain provenance). None = provided/external.
            discovered_by: Skill that found this credential.
        """
        with _get_db() as conn:
            if not secret:
                return "ERROR: secret is required. Use targets.notes for username-only lists."

            existing = conn.execute(
                "SELECT id FROM credentials "
                "WHERE username = ? AND secret_type = ? AND secret = ?",
                (username, secret_type, secret),
            ).fetchone()
            if existing:
                return json.dumps(
                    {
                        "credential_id": existing["id"],
                        "status": "duplicate_skipped",
                        "username": username,
                        "secret_type": secret_type,
                        "domain": domain,
                    },
                    indent=2,
                )
            cursor = conn.execute(
                "INSERT INTO credentials "
                "(username, secret, secret_type, domain, source, via_access_id, discovered_by) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    username,
                    secret,
                    secret_type,
                    domain,
                    source,
                    via_access_id,
                    discovered_by,
                ),
            )
            cred_id = cursor.lastrowid
            summary = (
                f"{domain}\\{username} ({secret_type})"
                if domain
                else f"{username} ({secret_type})"
            )
            _emit_event(conn, "credential", cred_id, summary, discovered_by)
            conn.commit()
            return json.dumps(
                {
                    "credential_id": cred_id,
                    "username": username,
                    "secret_type": secret_type,
                    "domain": domain,
                },
                indent=2,
            )

    @mcp.tool()
    def update_credential(
        id: int,
        cracked: bool | None = None,
        secret: str = "",
        notes: str = "",
    ) -> str:
        """Update a credential (e.g., mark as cracked, add plaintext).

        Args:
            id: Credential ID.
            cracked: Set to true when the hash has been cracked.
            secret: Updated secret value (e.g., cracked plaintext).
            notes: Additional notes.
        """
        with _get_db() as conn:
            updates = []
            params: list = []
            if cracked is not None:
                updates.append("cracked = ?")
                params.append(1 if cracked else 0)
            if secret:
                updates.append("secret = ?")
                params.append(secret)
            if notes:
                updates.append("notes = ?")
                params.append(notes)

            if not updates:
                return "No fields to update."

            updates.append(f"updated_at = {_now_sql()}")
            params.append(id)
            conn.execute(
                f"UPDATE credentials SET {', '.join(updates)} WHERE id = ?",
                params,
            )
            _emit_event(conn, "credential_update", id, f"credential #{id} updated")
            conn.commit()
            return json.dumps({"credential_id": id, "updated": True})

    @mcp.tool()
    def test_credential(
        credential_id: int,
        host: str,
        service: str,
        works: bool,
        tested_by: str = "",
    ) -> str:
        """Record whether a credential works against a target/service.

        Upserts on (credential_id, target_id, service).

        Args:
            credential_id: ID of the credential to test.
            host: Target host (must exist in targets table).
            service: Service tested (e.g., "smb", "ssh", "rdp", "winrm", "web").
            works: Whether the credential authenticated successfully.
            tested_by: Skill that performed the test.
        """
        with _get_db() as conn:
            target_id = _resolve_target_id(conn, host)
            if target_id is None:
                return f"ERROR: Target '{host}' not found."

            conn.execute(
                "INSERT INTO credential_access "
                "(credential_id, target_id, service, works, tested_by) "
                "VALUES (?, ?, ?, ?, ?) "
                "ON CONFLICT(credential_id, target_id, service) DO UPDATE SET "
                "works = excluded.works, "
                "tested_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now'), "
                "tested_by = excluded.tested_by",
                (credential_id, target_id, service, 1 if works else 0, tested_by),
            )
            result_str = "works" if works else "fails"
            _emit_event(
                conn, "credential_test", credential_id,
                f"cred #{credential_id} {result_str} on {host}:{service}",
                tested_by,
            )
            conn.commit()
            return json.dumps(
                {
                    "credential_id": credential_id,
                    "host": host,
                    "service": service,
                    "works": works,
                }
            )

    @mcp.tool()
    def add_access(
        host: str,
        access_type: str = "shell",
        username: str = "",
        privilege: str = "user",
        method: str = "",
        session_ref: str = "",
        discovered_by: str = "",
        notes: str = "",
    ) -> str:
        """Record a new foothold/access on a target.

        Args:
            host: Target host (must exist in targets table).
            access_type: Type of access: shell, ssh, winrm, rdp, web_shell,
                        db, token, vpn, other.
            username: User/account that has access.
            privilege: Privilege level: user, admin, root, system, service,
                      domain_admin, other.
            method: How access was gained (e.g., "XXE -> webshell -> rev shell").
            session_ref: Reference to shell-server session ID if applicable.
            discovered_by: Skill that gained access.
            notes: Additional notes.
        """
        with _get_db() as conn:
            target_id = _resolve_target_id(conn, host)
            if target_id is None:
                return f"ERROR: Target '{host}' not found."

            cursor = conn.execute(
                "INSERT INTO access "
                "(target_id, access_type, username, privilege, method, "
                "session_ref, discovered_by, notes) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    target_id,
                    access_type,
                    username,
                    privilege,
                    method,
                    session_ref,
                    discovered_by,
                    notes,
                ),
            )
            access_id = cursor.lastrowid
            _emit_event(
                conn, "access", access_id,
                f"{username}@{host} [{privilege}] via {access_type}",
                discovered_by,
            )
            conn.commit()
            return json.dumps(
                {
                    "access_id": access_id,
                    "host": host,
                    "access_type": access_type,
                    "privilege": privilege,
                },
                indent=2,
            )

    @mcp.tool()
    def update_access(
        id: int,
        active: bool | None = None,
        privilege: str = "",
        notes: str = "",
    ) -> str:
        """Update access record (e.g., revoke, update privilege level).

        Args:
            id: Access record ID.
            active: Set to false to mark access as revoked.
            privilege: Updated privilege level.
            notes: Additional notes.
        """
        with _get_db() as conn:
            updates = []
            params: list = []
            if active is not None:
                updates.append("active = ?")
                params.append(1 if active else 0)
            if privilege:
                updates.append("privilege = ?")
                params.append(privilege)
            if notes:
                updates.append("notes = ?")
                params.append(notes)

            if not updates:
                return "No fields to update."

            updates.append(f"updated_at = {_now_sql()}")
            params.append(id)
            conn.execute(
                f"UPDATE access SET {', '.join(updates)} WHERE id = ?",
                params,
            )
            _emit_event(conn, "access_update", id, f"access #{id} updated")
            conn.commit()
            return json.dumps({"access_id": id, "updated": True})

    @mcp.tool()
    def add_vuln(
        title: str,
        host: str,
        vuln_type: str = "",
        status: str = "found",
        severity: str = "medium",
        details: str = "",
        evidence_path: str = "",
        via_access_id: int | None = None,
        discovered_by: str = "",
    ) -> str:
        """Add a confirmed vulnerability.

        Deduplicates on (target_id, title). If a vuln with the same title
        already exists for the same target, returns the existing record
        instead of creating a duplicate.

        Args:
            title: Short vulnerability title (e.g., "SQLi in /search parameter").
            host: Target host (required — must match an existing target).
            vuln_type: Vulnerability class (e.g., "sqli", "xss", "rce").
            status: Status: found, exploited, blocked.
            severity: Severity: info, low, medium, high, critical.
            details: Technical details.
            evidence_path: Path to evidence file in engagement/evidence/.
            via_access_id: Access ID that led to finding this vuln
                          (for kill-chain provenance). None = unauthenticated/recon.
            discovered_by: Skill that found this vulnerability.
        """
        with _get_db() as conn:
            if not host:
                return "ERROR: host is required. Every vuln must be associated with a target."
            target_id = _resolve_target_id(conn, host)
            if target_id is None:
                return f"ERROR: Target '{host}' not found. Add the target first."

            # Dedup: check for existing vuln with same title on same target
            existing = conn.execute(
                "SELECT id, status, severity FROM vulns "
                "WHERE target_id = ? AND title = ?",
                (target_id, title),
            ).fetchone()

            if existing:
                return json.dumps(
                    {
                        "vuln_id": existing["id"],
                        "status": "duplicate_skipped",
                        "existing_status": existing["status"],
                        "existing_severity": existing["severity"],
                        "title": title,
                    },
                    indent=2,
                )

            cursor = conn.execute(
                "INSERT INTO vulns "
                "(target_id, title, vuln_type, status, severity, "
                "details, evidence_path, via_access_id, discovered_by) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    target_id,
                    title,
                    vuln_type,
                    status,
                    severity,
                    details,
                    evidence_path,
                    via_access_id,
                    discovered_by,
                ),
            )
            vuln_id = cursor.lastrowid
            summary = f"{title} [{severity}]"
            if host:
                summary += f" on {host}"
            _emit_event(conn, "vuln", vuln_id, summary, discovered_by)
            conn.commit()
            return json.dumps(
                {
                    "vuln_id": vuln_id,
                    "title": title,
                    "severity": severity,
                    "status": status,
                },
                indent=2,
            )

    @mcp.tool()
    def update_vuln(
        id: int,
        status: str = "",
        severity: str = "",
        details: str = "",
    ) -> str:
        """Update vulnerability (e.g., change status after exploitation).

        Args:
            id: Vulnerability ID.
            status: Updated status (found/exploited/blocked).
            severity: Updated severity.
            details: Updated details.
        """
        with _get_db() as conn:
            updates = []
            params: list = []
            if status:
                updates.append("status = ?")
                params.append(status)
            if severity:
                updates.append("severity = ?")
                params.append(severity)
            if details:
                updates.append("details = ?")
                params.append(details)

            if not updates:
                return "No fields to update."

            updates.append(f"updated_at = {_now_sql()}")
            params.append(id)
            conn.execute(
                f"UPDATE vulns SET {', '.join(updates)} WHERE id = ?",
                params,
            )
            summary = f"vuln #{id}"
            if status:
                summary += f" -> {status}"
            _emit_event(conn, "vuln_update", id, summary)
            conn.commit()
            return json.dumps({"vuln_id": id, "updated": True})

    @mcp.tool()
    def add_pivot(
        source: str,
        destination: str,
        method: str = "",
        status: str = "identified",
        discovered_by: str = "",
        notes: str = "",
    ) -> str:
        """Add a pivot path (what leads where).

        Args:
            source: Source (e.g., "SQLi on 10.10.10.5:/search").
            destination: Destination (e.g., "DB creds for 10.10.10.1:mssql").
            method: How the pivot works.
            status: Status: identified, exploited, blocked.
            discovered_by: Skill that identified this path.
            notes: Additional notes.
        """
        with _get_db() as conn:
            cursor = conn.execute(
                "INSERT INTO pivot_map "
                "(source, destination, method, status, discovered_by, notes) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (source, destination, method, status, discovered_by, notes),
            )
            pivot_id = cursor.lastrowid
            _emit_event(
                conn,
                "pivot",
                pivot_id,
                f"{source} -> {destination}",
                discovered_by,
            )
            conn.commit()
            return json.dumps(
                {
                    "pivot_id": pivot_id,
                    "source": source,
                    "destination": destination,
                    "status": status,
                },
                indent=2,
            )

    @mcp.tool()
    def update_pivot(
        id: int,
        status: str = "",
        notes: str = "",
    ) -> str:
        """Update a pivot path status.

        Args:
            id: Pivot ID.
            status: Updated status (identified/exploited/blocked).
            notes: Updated notes.
        """
        with _get_db() as conn:
            updates = []
            params: list = []
            if status:
                updates.append("status = ?")
                params.append(status)
            if notes:
                updates.append("notes = ?")
                params.append(notes)

            if not updates:
                return "No fields to update."

            params.append(id)
            conn.execute(
                f"UPDATE pivot_map SET {', '.join(updates)} WHERE id = ?",
                params,
            )
            _emit_event(conn, "pivot_update", id, f"pivot #{id} -> {status}")
            conn.commit()
            return json.dumps({"pivot_id": id, "updated": True})

    @mcp.tool()
    def add_blocked(
        technique: str,
        reason: str,
        host: str = "",
        retry: str = "no",
        notes: str = "",
        blocked_by: str = "",
    ) -> str:
        """Record a blocked/failed technique attempt.

        Args:
            technique: Technique that was attempted (e.g., "kerberoasting").
            reason: Why it failed.
            host: Target host (empty = not host-specific).
            retry: Retry assessment: no, later, with_context.
            notes: Additional notes.
            blocked_by: Skill that was blocked.
        """
        with _get_db() as conn:
            target_id = None
            if host:
                target_id = _resolve_target_id(conn, host)
                if target_id is None:
                    return f"ERROR: Target '{host}' not found. Add the target first."

            cursor = conn.execute(
                "INSERT INTO blocked "
                "(target_id, technique, reason, retry, notes, blocked_by) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (target_id, technique, reason, retry, notes, blocked_by),
            )
            blocked_id = cursor.lastrowid
            summary = technique
            if host:
                summary += f" on {host}"
            summary += f" | {reason} [{retry}]"
            _emit_event(conn, "blocked", blocked_id, summary, blocked_by)
            conn.commit()
            return json.dumps(
                {
                    "blocked_id": blocked_id,
                    "technique": technique,
                    "retry": retry,
                },
                indent=2,
            )

    @mcp.tool()
    def add_tunnel(
        tunnel_type: str = "other",
        pivot_host: str = "",
        target_subnet: str = "",
        local_endpoint: str = "",
        remote_endpoint: str = "",
        requires_proxychains: bool = False,
        notes: str = "",
        created_by: str = "",
    ) -> str:
        """Record an established tunnel.

        Args:
            tunnel_type: Tunnel type: ssh_local, ssh_dynamic, ssh_remote,
                        ssh_tun, sshuttle, ligolo, chisel, socat, other.
            pivot_host: Host being pivoted through.
            target_subnet: Target subnet reachable via tunnel (e.g., "172.16.0.0/24").
            local_endpoint: Local endpoint (e.g., "socks5://127.0.0.1:1080",
                           "ligolo0 TUN", "127.0.0.1:8080").
            remote_endpoint: Remote endpoint on/through the pivot.
            requires_proxychains: True if tools need proxychains (SOCKS-based),
                                 false for transparent tunnels (sshuttle, ligolo, ssh_tun).
            notes: Additional notes.
            created_by: Skill/agent that created this tunnel.
        """
        with _get_db() as conn:
            cursor = conn.execute(
                "INSERT INTO tunnels "
                "(tunnel_type, pivot_host, target_subnet, local_endpoint, "
                "remote_endpoint, requires_proxychains, notes, created_by) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    tunnel_type,
                    pivot_host,
                    target_subnet,
                    local_endpoint,
                    remote_endpoint,
                    1 if requires_proxychains else 0,
                    notes,
                    created_by,
                ),
            )
            tunnel_id = cursor.lastrowid
            proxy_note = "proxychains" if requires_proxychains else "transparent"
            summary = f"{tunnel_type} via {pivot_host} → {target_subnet} ({proxy_note})"
            _emit_event(conn, "tunnel", tunnel_id, summary, created_by)
            conn.commit()
            return json.dumps(
                {
                    "tunnel_id": tunnel_id,
                    "tunnel_type": tunnel_type,
                    "pivot_host": pivot_host,
                    "target_subnet": target_subnet,
                    "requires_proxychains": requires_proxychains,
                },
                indent=2,
            )

    @mcp.tool()
    def update_tunnel(
        id: int,
        status: str = "",
        notes: str = "",
    ) -> str:
        """Update a tunnel (e.g., mark as down or closed).

        Args:
            id: Tunnel ID.
            status: Updated status (active/down/closed).
            notes: Updated notes.
        """
        with _get_db() as conn:
            updates = []
            params: list = []
            if status:
                updates.append("status = ?")
                params.append(status)
            if notes:
                updates.append("notes = ?")
                params.append(notes)

            if not updates:
                return "No fields to update."

            updates.append(f"updated_at = {_now_sql()}")
            params.append(id)
            conn.execute(
                f"UPDATE tunnels SET {', '.join(updates)} WHERE id = ?",
                params,
            )
            _emit_event(conn, "tunnel_update", id, f"tunnel #{id} -> {status}")
            conn.commit()
            return json.dumps({"tunnel_id": id, "updated": True})

    return mcp


def main() -> None:
    server = create_server()
    server.run()


if __name__ == "__main__":
    main()
