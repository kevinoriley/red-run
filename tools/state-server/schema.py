"""SQLite schema for engagement state management.

Creates and migrates the state.db database used by the state-server MCP.
Version tracking via PRAGMA user_version enables future migrations.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

SCHEMA_VERSION = 19

SCHEMA_SQL = """\
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS engagement (
    id          INTEGER PRIMARY KEY CHECK (id = 1),
    name        TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    closed_at   TEXT,
    status      TEXT NOT NULL DEFAULT 'active'
                CHECK (status IN ('active', 'closed')),
    mode        TEXT NOT NULL DEFAULT 'ctf'
                CHECK (mode IN ('ctf', 'pentest'))
);

CREATE TABLE IF NOT EXISTS targets (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    ip            TEXT NOT NULL UNIQUE,
    hostname      TEXT NOT NULL DEFAULT '',
    os            TEXT NOT NULL DEFAULT '',
    role          TEXT NOT NULL DEFAULT '',
    notes         TEXT NOT NULL DEFAULT '',
    discovered_by TEXT NOT NULL DEFAULT '',
    created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    updated_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

CREATE TABLE IF NOT EXISTS ports (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id   INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    port        INTEGER NOT NULL,
    protocol    TEXT NOT NULL DEFAULT 'tcp',
    state       TEXT NOT NULL DEFAULT 'open',
    service     TEXT NOT NULL DEFAULT '',
    banner      TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    UNIQUE(target_id, port, protocol)
);

CREATE TABLE IF NOT EXISTS credentials (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT NOT NULL DEFAULT '',
    secret        TEXT NOT NULL DEFAULT '',
    secret_type   TEXT NOT NULL DEFAULT 'password'
                  CHECK (secret_type IN ('password', 'ntlm_hash', 'net_ntlm',
                         'aes_key', 'kerberos_tgt', 'kerberos_tgs', 'dcc2',
                         'ssh_key', 'token', 'certificate', 'webapp_hash',
                         'dpapi', 'other')),
    domain        TEXT NOT NULL DEFAULT '',
    source        TEXT NOT NULL DEFAULT '',
    cracked       INTEGER NOT NULL DEFAULT 0,
    via_access_id INTEGER REFERENCES access(id) ON DELETE SET NULL,
    via_vuln_id   INTEGER REFERENCES vulns(id) ON DELETE SET NULL,
    in_graph     INTEGER NOT NULL DEFAULT 1,
    chain_order   INTEGER NOT NULL DEFAULT 0,
    notes         TEXT NOT NULL DEFAULT '',
    discovered_by TEXT NOT NULL DEFAULT '',
    created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    updated_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

CREATE TABLE IF NOT EXISTS credential_access (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    credential_id INTEGER NOT NULL REFERENCES credentials(id) ON DELETE CASCADE,
    target_id     INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    service       TEXT NOT NULL DEFAULT '',
    works         INTEGER NOT NULL,
    tested_at     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    tested_by     TEXT NOT NULL DEFAULT '',
    UNIQUE(credential_id, target_id, service)
);

CREATE TABLE IF NOT EXISTS access (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id     INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    access_type   TEXT NOT NULL DEFAULT 'shell'
                  CHECK (access_type IN ('shell', 'ssh', 'winrm', 'rdp',
                         'web_shell', 'smb', 'db', 'token', 'vpn',
                         'c2', 'other')),
    username      TEXT NOT NULL DEFAULT '',
    privilege     TEXT NOT NULL DEFAULT 'user'
                  CHECK (privilege IN ('user', 'admin', 'root', 'system',
                         'service', 'domain_admin', 'other')),
    method        TEXT NOT NULL DEFAULT '',
    session_ref   TEXT NOT NULL DEFAULT '',
    via_credential_id INTEGER REFERENCES credentials(id) ON DELETE SET NULL,
    via_access_id INTEGER REFERENCES access(id) ON DELETE SET NULL,
    via_vuln_id   INTEGER REFERENCES vulns(id) ON DELETE SET NULL,
    technique_id  TEXT NOT NULL DEFAULT '',
    in_graph     INTEGER NOT NULL DEFAULT 1,
    chain_order   INTEGER NOT NULL DEFAULT 0,
    active        INTEGER NOT NULL DEFAULT 1,
    notes         TEXT NOT NULL DEFAULT '',
    discovered_by TEXT NOT NULL DEFAULT '',
    created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    updated_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

CREATE TABLE IF NOT EXISTS vulns (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id     INTEGER REFERENCES targets(id) ON DELETE SET NULL,
    title         TEXT NOT NULL,
    vuln_type     TEXT NOT NULL DEFAULT '',
    status        TEXT NOT NULL DEFAULT 'found'
                  CHECK (status IN ('found', 'exploited', 'blocked')),
    severity      TEXT NOT NULL DEFAULT 'medium'
                  CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical')),
    details       TEXT NOT NULL DEFAULT '',
    evidence_path TEXT NOT NULL DEFAULT '',
    via_access_id    INTEGER REFERENCES access(id) ON DELETE SET NULL,
    via_credential_id INTEGER REFERENCES credentials(id) ON DELETE SET NULL,
    technique_id  TEXT NOT NULL DEFAULT '',
    in_graph     INTEGER NOT NULL DEFAULT 1,
    chain_order   INTEGER NOT NULL DEFAULT 0,
    discovered_by TEXT NOT NULL DEFAULT '',
    created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    updated_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

CREATE TABLE IF NOT EXISTS pivot_map (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    source        TEXT NOT NULL,
    destination   TEXT NOT NULL,
    method        TEXT NOT NULL DEFAULT '',
    status        TEXT NOT NULL DEFAULT 'identified'
                  CHECK (status IN ('identified', 'exploited', 'blocked')),
    notes         TEXT NOT NULL DEFAULT '',
    discovered_by TEXT NOT NULL DEFAULT '',
    created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

CREATE TABLE IF NOT EXISTS blocked (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id     INTEGER REFERENCES targets(id) ON DELETE SET NULL,
    technique     TEXT NOT NULL,
    reason        TEXT NOT NULL,
    retry         TEXT NOT NULL DEFAULT 'no'
                  CHECK (retry IN ('no', 'later', 'with_context')),
    notes         TEXT NOT NULL DEFAULT '',
    blocked_by    TEXT NOT NULL DEFAULT '',
    created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

CREATE TABLE IF NOT EXISTS state_events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type  TEXT NOT NULL,
    record_id   INTEGER NOT NULL,
    summary     TEXT NOT NULL,
    agent       TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

CREATE TABLE IF NOT EXISTS tunnels (
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    tunnel_type          TEXT NOT NULL DEFAULT 'other',
    pivot_host           TEXT NOT NULL DEFAULT '',
    target_subnet        TEXT NOT NULL DEFAULT '',
    local_endpoint       TEXT NOT NULL DEFAULT '',
    remote_endpoint      TEXT NOT NULL DEFAULT '',
    requires_proxychains INTEGER NOT NULL DEFAULT 0,
    status               TEXT NOT NULL DEFAULT 'active'
                         CHECK (status IN ('active', 'down', 'closed')),
    notes                TEXT NOT NULL DEFAULT '',
    created_by           TEXT NOT NULL DEFAULT '',
    created_at           TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    updated_at           TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);
"""


def _migrate_v2_to_v3(conn: sqlite3.Connection) -> None:
    """Migrate schema from v2 to v3: add tunnels table, relax state_events CHECK.

    Non-destructive — uses CREATE TABLE IF NOT EXISTS for tunnels.
    Recreates state_events without the CHECK constraint on event_type so that
    new event types (like 'tunnel') work without DDL changes.
    """
    # Add tunnels table
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS tunnels (
            id                   INTEGER PRIMARY KEY AUTOINCREMENT,
            tunnel_type          TEXT NOT NULL DEFAULT 'other',
            pivot_host           TEXT NOT NULL DEFAULT '',
            target_subnet        TEXT NOT NULL DEFAULT '',
            local_endpoint       TEXT NOT NULL DEFAULT '',
            remote_endpoint      TEXT NOT NULL DEFAULT '',
            requires_proxychains INTEGER NOT NULL DEFAULT 0,
            status               TEXT NOT NULL DEFAULT 'active'
                                 CHECK (status IN ('active', 'down', 'closed')),
            notes                TEXT NOT NULL DEFAULT '',
            created_by           TEXT NOT NULL DEFAULT '',
            created_at           TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
            updated_at           TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
        );
    """)

    # Recreate state_events without the CHECK constraint on event_type.
    # SQLite doesn't support ALTER TABLE DROP CONSTRAINT, so we rename → copy → drop.
    has_check = conn.execute(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name='state_events'"
    ).fetchone()
    if has_check and "CHECK" in (has_check[0] or ""):
        conn.executescript("""
            ALTER TABLE state_events RENAME TO _state_events_old;

            CREATE TABLE state_events (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type  TEXT NOT NULL,
                record_id   INTEGER NOT NULL,
                summary     TEXT NOT NULL,
                agent       TEXT NOT NULL DEFAULT '',
                created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
            );

            INSERT INTO state_events (id, event_type, record_id, summary, agent, created_at)
                SELECT id, event_type, record_id, summary, agent, created_at
                FROM _state_events_old;

            DROP TABLE _state_events_old;
        """)


def _migrate_v7_to_v8(conn: sqlite3.Connection) -> None:
    """Migrate schema from v7 to v8: drop endpoint column from vulns."""
    cols = [r[1] for r in conn.execute("PRAGMA table_info(vulns)").fetchall()]
    if "endpoint" not in cols:
        return
    conn.executescript("""
        ALTER TABLE vulns RENAME TO _vulns_old;

        CREATE TABLE vulns (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            target_id     INTEGER REFERENCES targets(id) ON DELETE SET NULL,
            title         TEXT NOT NULL,
            vuln_type     TEXT NOT NULL DEFAULT '',
            status        TEXT NOT NULL DEFAULT 'found'
                          CHECK (status IN ('found', 'exploited', 'blocked')),
            severity      TEXT NOT NULL DEFAULT 'medium'
                          CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical')),
            details       TEXT NOT NULL DEFAULT '',
            evidence_path TEXT NOT NULL DEFAULT '',
            via_access_id INTEGER REFERENCES access(id) ON DELETE SET NULL,
            discovered_by TEXT NOT NULL DEFAULT '',
            created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
            updated_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
        );

        INSERT INTO vulns (id, target_id, title, vuln_type, status, severity,
                          details, evidence_path, via_access_id,
                          discovered_by, created_at, updated_at)
            SELECT id, target_id, title, vuln_type, status, severity,
                   details, evidence_path, via_access_id,
                   discovered_by, created_at, updated_at
            FROM _vulns_old;

        DROP TABLE _vulns_old;
    """)
    conn.commit()


def _migrate_v6_to_v7(conn: sqlite3.Connection) -> None:
    """Migrate schema from v6 to v7: expand credential secret_type.

    Adds net_ntlm, dcc2, webapp_hash, dpapi to the CHECK constraint.
    Recreates credentials table (SQLite can't ALTER CHECK).
    """
    conn.executescript("""
        ALTER TABLE credentials RENAME TO _credentials_old;

        CREATE TABLE credentials (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            username      TEXT NOT NULL DEFAULT '',
            secret        TEXT NOT NULL DEFAULT '',
            secret_type   TEXT NOT NULL DEFAULT 'password'
                          CHECK (secret_type IN ('password', 'ntlm_hash', 'net_ntlm',
                                 'aes_key', 'kerberos_tgt', 'kerberos_tgs', 'dcc2',
                                 'ssh_key', 'token', 'certificate', 'webapp_hash',
                                 'dpapi', 'other')),
            domain        TEXT NOT NULL DEFAULT '',
            source        TEXT NOT NULL DEFAULT '',
            cracked       INTEGER NOT NULL DEFAULT 0,
            via_access_id INTEGER REFERENCES access(id) ON DELETE SET NULL,
            notes         TEXT NOT NULL DEFAULT '',
            discovered_by TEXT NOT NULL DEFAULT '',
            created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
            updated_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
        );

        INSERT INTO credentials (id, username, secret, secret_type, domain, source,
                                cracked, via_access_id, notes, discovered_by,
                                created_at, updated_at)
            SELECT id, username, secret, secret_type, domain, source,
                   cracked, via_access_id, notes, discovered_by,
                   created_at, updated_at
            FROM _credentials_old;

        DROP TABLE _credentials_old;
    """)
    conn.commit()


def _migrate_v5_to_v6(conn: sqlite3.Connection) -> None:
    """Migrate schema from v5 to v6: change vuln status lifecycle.

    Old statuses: found, active, done
    New statuses: found, exploited, blocked

    Mapping: active -> exploited, done -> exploited, found stays.
    Recreates vulns table with new CHECK constraint (SQLite can't ALTER CHECK).
    """
    conn.executescript("""
        ALTER TABLE vulns RENAME TO _vulns_old;

        CREATE TABLE vulns (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            target_id     INTEGER REFERENCES targets(id) ON DELETE SET NULL,
            title         TEXT NOT NULL,
            vuln_type     TEXT NOT NULL DEFAULT '',
            status        TEXT NOT NULL DEFAULT 'found'
                          CHECK (status IN ('found', 'exploited', 'blocked')),
            severity      TEXT NOT NULL DEFAULT 'medium'
                          CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical')),
            endpoint      TEXT NOT NULL DEFAULT '',
            details       TEXT NOT NULL DEFAULT '',
            evidence_path TEXT NOT NULL DEFAULT '',
            via_access_id INTEGER REFERENCES access(id) ON DELETE SET NULL,
            discovered_by TEXT NOT NULL DEFAULT '',
            created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
            updated_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
        );

        INSERT INTO vulns (id, target_id, title, vuln_type, status, severity,
                          endpoint, details, evidence_path, via_access_id,
                          discovered_by, created_at, updated_at)
            SELECT id, target_id, title, vuln_type,
                   CASE status
                       WHEN 'active' THEN 'exploited'
                       WHEN 'done' THEN 'exploited'
                       ELSE status
                   END,
                   severity, endpoint, details, evidence_path, via_access_id,
                   discovered_by, created_at, updated_at
            FROM _vulns_old;

        DROP TABLE _vulns_old;
    """)
    conn.commit()


def _migrate_v4_to_v5(conn: sqlite3.Connection) -> None:
    """Migrate schema from v4 to v5: add mode column to engagement."""
    cols = [r[1] for r in conn.execute("PRAGMA table_info(engagement)").fetchall()]
    if "mode" not in cols:
        conn.execute(
            "ALTER TABLE engagement ADD COLUMN mode TEXT NOT NULL DEFAULT 'ctf'"
        )
    conn.commit()


def _migrate_v3_to_v4(conn: sqlite3.Connection) -> None:
    """Migrate schema from v3 to v4: add via_access_id to credentials and vulns.

    Adds a nullable FK to access(id) for provenance tracking — which access
    session led to the discovery of this credential or vulnerability.
    """
    for table in ("credentials", "vulns"):
        cols = [r[1] for r in conn.execute(f"PRAGMA table_info({table})").fetchall()]
        if "via_access_id" not in cols:
            conn.execute(
                f"ALTER TABLE {table} ADD COLUMN via_access_id INTEGER REFERENCES access(id) ON DELETE SET NULL"
            )
    conn.commit()


def _migrate_v18_to_v19(conn: sqlite3.Connection) -> None:
    """Migrate schema from v18 to v19: add c2 to access_type CHECK constraint.

    SQLite can't ALTER CHECK, so recreate the access table.
    """
    cols = [r[1] for r in conn.execute("PRAGMA table_info(access)").fetchall()]
    col_list = ", ".join(cols)
    conn.executescript(f"""
        ALTER TABLE access RENAME TO _access_old;

        CREATE TABLE access (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            target_id     INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
            access_type   TEXT NOT NULL DEFAULT 'shell'
                          CHECK (access_type IN ('shell', 'ssh', 'winrm', 'rdp',
                                 'web_shell', 'smb', 'db', 'token', 'vpn',
                                 'c2', 'other')),
            username      TEXT NOT NULL DEFAULT '',
            privilege     TEXT NOT NULL DEFAULT 'user'
                          CHECK (privilege IN ('user', 'admin', 'root', 'system',
                                 'service', 'domain_admin', 'other')),
            method        TEXT NOT NULL DEFAULT '',
            session_ref   TEXT NOT NULL DEFAULT '',
            via_credential_id INTEGER REFERENCES credentials(id) ON DELETE SET NULL,
            via_access_id INTEGER REFERENCES access(id) ON DELETE SET NULL,
            via_vuln_id   INTEGER REFERENCES vulns(id) ON DELETE SET NULL,
            active        INTEGER NOT NULL DEFAULT 1,
            notes         TEXT NOT NULL DEFAULT '',
            technique_id  TEXT NOT NULL DEFAULT '',
            chain_order   INTEGER NOT NULL DEFAULT 0,
            in_graph      INTEGER NOT NULL DEFAULT 1,
            discovered_by TEXT NOT NULL DEFAULT '',
            created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
            updated_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
        );

        INSERT INTO access ({col_list})
            SELECT {col_list} FROM _access_old;
        DROP TABLE _access_old;
    """)
    conn.commit()


def _migrate_v17_to_v18(conn: sqlite3.Connection) -> None:
    """Migrate schema from v17 to v18: add via_vuln_id to access."""
    cols = [r[1] for r in conn.execute("PRAGMA table_info(access)").fetchall()]
    if "via_vuln_id" not in cols:
        conn.execute(
            "ALTER TABLE access ADD COLUMN via_vuln_id INTEGER "
            "REFERENCES vulns(id) ON DELETE SET NULL"
        )
    conn.commit()


def _migrate_v16_to_v17(conn: sqlite3.Connection) -> None:
    """Migrate schema from v16 to v17: add via_credential_id to vulns."""
    cols = [r[1] for r in conn.execute("PRAGMA table_info(vulns)").fetchall()]
    if "via_credential_id" not in cols:
        conn.execute(
            "ALTER TABLE vulns ADD COLUMN via_credential_id INTEGER "
            "REFERENCES credentials(id) ON DELETE SET NULL"
        )
    conn.commit()


def _migrate_v15_to_v16(conn: sqlite3.Connection) -> None:
    """Migrate schema from v15 to v16: add via_vuln_id to credentials."""
    cols = [r[1] for r in conn.execute("PRAGMA table_info(credentials)").fetchall()]
    if "via_vuln_id" not in cols:
        conn.execute(
            "ALTER TABLE credentials ADD COLUMN via_vuln_id INTEGER "
            "REFERENCES vulns(id) ON DELETE SET NULL"
        )
    conn.commit()


def _migrate_v14_to_v15(conn: sqlite3.Connection) -> None:
    """Migrate schema from v14 to v15: rename in_report to in_graph."""
    for table in ("access", "vulns", "credentials"):
        cols = [r[1] for r in conn.execute(f"PRAGMA table_info({table})").fetchall()]
        if "in_report" in cols and "in_graph" not in cols:
            conn.execute(f"ALTER TABLE {table} RENAME COLUMN in_report TO in_graph")
    conn.commit()


def _migrate_v13_to_v14(conn: sqlite3.Connection) -> None:
    """Migrate schema from v13 to v14: add chain_order for flow graph ordering."""
    for table in ("access", "vulns", "credentials"):
        cols = [r[1] for r in conn.execute(f"PRAGMA table_info({table})").fetchall()]
        if "chain_order" not in cols:
            conn.execute(
                f"ALTER TABLE {table} ADD COLUMN chain_order INTEGER NOT NULL DEFAULT 0"
            )
    conn.commit()


def _migrate_v12_to_v13(conn: sqlite3.Connection) -> None:
    """Migrate schema from v12 to v13: add technique_id and in_graph columns."""
    for table in ("access", "vulns"):
        cols = [r[1] for r in conn.execute(f"PRAGMA table_info({table})").fetchall()]
        if "technique_id" not in cols:
            conn.execute(
                f"ALTER TABLE {table} ADD COLUMN technique_id TEXT NOT NULL DEFAULT ''"
            )
        if "in_graph" not in cols:
            conn.execute(
                f"ALTER TABLE {table} ADD COLUMN in_graph INTEGER NOT NULL DEFAULT 1"
            )
    # credentials gets in_graph only (no technique_id — creds are assets, not actions)
    cols = [r[1] for r in conn.execute("PRAGMA table_info(credentials)").fetchall()]
    if "in_graph" not in cols:
        conn.execute(
            "ALTER TABLE credentials ADD COLUMN in_graph INTEGER NOT NULL DEFAULT 1"
        )
    conn.commit()


def _migrate_v11_to_v12(conn: sqlite3.Connection) -> None:
    """Migrate schema from v11 to v12: add smb to access_type CHECK constraint.

    SQLite can't ALTER CHECK, so recreate the access table.
    """
    conn.executescript("""
        ALTER TABLE access RENAME TO _access_old;

        CREATE TABLE access (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            target_id     INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
            access_type   TEXT NOT NULL DEFAULT 'shell'
                          CHECK (access_type IN ('shell', 'ssh', 'winrm', 'rdp',
                                 'web_shell', 'smb', 'db', 'token', 'vpn', 'other')),
            username      TEXT NOT NULL DEFAULT '',
            privilege     TEXT NOT NULL DEFAULT 'user'
                          CHECK (privilege IN ('user', 'admin', 'root', 'system',
                                 'service', 'domain_admin', 'other')),
            method        TEXT NOT NULL DEFAULT '',
            session_ref   TEXT NOT NULL DEFAULT '',
            via_credential_id INTEGER REFERENCES credentials(id) ON DELETE SET NULL,
            via_access_id INTEGER REFERENCES access(id) ON DELETE SET NULL,
            active        INTEGER NOT NULL DEFAULT 1,
            notes         TEXT NOT NULL DEFAULT '',
            discovered_by TEXT NOT NULL DEFAULT '',
            created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
            updated_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
        );

        INSERT INTO access (id, target_id, access_type, username, privilege,
                           method, session_ref, via_credential_id, via_access_id,
                           active, notes, discovered_by, created_at, updated_at)
            SELECT id, target_id, access_type, username, privilege,
                   method, session_ref, via_credential_id, via_access_id,
                   active, notes, discovered_by,
                   COALESCE(created_at, strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
                   COALESCE(updated_at, strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
            FROM _access_old;
        DROP TABLE _access_old;
    """)
    conn.commit()


def _migrate_v10_to_v11(conn: sqlite3.Connection) -> None:
    """Migrate schema from v10 to v11: add via_access_id to access for privesc chains."""
    cols = [r[1] for r in conn.execute("PRAGMA table_info(access)").fetchall()]
    if "via_access_id" not in cols:
        conn.execute(
            "ALTER TABLE access ADD COLUMN via_access_id INTEGER "
            "REFERENCES access(id) ON DELETE SET NULL"
        )
    conn.commit()


def _migrate_v9_to_v10(conn: sqlite3.Connection) -> None:
    """Migrate schema from v9 to v10: add via_credential_id to access."""
    cols = [r[1] for r in conn.execute("PRAGMA table_info(access)").fetchall()]
    if "via_credential_id" not in cols:
        conn.execute(
            "ALTER TABLE access ADD COLUMN via_credential_id INTEGER "
            "REFERENCES credentials(id) ON DELETE SET NULL"
        )
    conn.commit()


def _migrate_v8_to_v9(conn: sqlite3.Connection) -> None:
    """Migrate schema from v8 to v9: add hostname column, rename host to ip."""
    cols = [r[1] for r in conn.execute("PRAGMA table_info(targets)").fetchall()]
    if "hostname" not in cols:
        conn.execute("ALTER TABLE targets ADD COLUMN hostname TEXT NOT NULL DEFAULT ''")
    if "host" in cols:
        conn.execute("ALTER TABLE targets RENAME COLUMN host TO ip")
    conn.commit()


def init_db(db_path: str | Path) -> sqlite3.Connection:
    """Create or open the state database and apply schema.

    Returns a connection with WAL mode and foreign keys enabled.
    """
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row

    # Check current version for migrations
    current_version = conn.execute("PRAGMA user_version").fetchone()[0]

    # Apply base schema (CREATE IF NOT EXISTS — safe for existing DBs)
    conn.executescript(SCHEMA_SQL)

    # Run migrations for existing databases (skip fresh DBs — base schema is current)
    if 0 < current_version < SCHEMA_VERSION:
        if current_version == 2:
            _migrate_v2_to_v3(conn)
        if current_version <= 3:
            _migrate_v3_to_v4(conn)
        if current_version <= 4:
            _migrate_v4_to_v5(conn)
        if current_version <= 5:
            _migrate_v5_to_v6(conn)
        if current_version <= 6:
            _migrate_v6_to_v7(conn)
        if current_version <= 7:
            _migrate_v7_to_v8(conn)
        if current_version <= 8:
            _migrate_v8_to_v9(conn)
        if current_version <= 9:
            _migrate_v9_to_v10(conn)
        if current_version <= 10:
            _migrate_v10_to_v11(conn)
        if current_version <= 11:
            _migrate_v11_to_v12(conn)
        if current_version <= 12:
            _migrate_v12_to_v13(conn)
        if current_version <= 13:
            _migrate_v13_to_v14(conn)
        if current_version <= 14:
            _migrate_v14_to_v15(conn)
        if current_version <= 15:
            _migrate_v15_to_v16(conn)
        if current_version <= 16:
            _migrate_v16_to_v17(conn)
        if current_version <= 17:
            _migrate_v17_to_v18(conn)
        if current_version <= 18:
            _migrate_v18_to_v19(conn)

    conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
    conn.commit()
    return conn
