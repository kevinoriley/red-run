"""SQLite schema for engagement state management.

Creates and migrates the state.db database used by the state-server MCP.
Version tracking via PRAGMA user_version enables future migrations.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

SCHEMA_VERSION = 1

SCHEMA_SQL = """\
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS engagement (
    id          INTEGER PRIMARY KEY CHECK (id = 1),
    name        TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    closed_at   TEXT,
    status      TEXT NOT NULL DEFAULT 'active'
                CHECK (status IN ('active', 'closed'))
);

CREATE TABLE IF NOT EXISTS targets (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    host          TEXT NOT NULL UNIQUE,
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
                  CHECK (secret_type IN ('password', 'ntlm_hash', 'aes_key',
                         'kerberos_tgt', 'kerberos_tgs', 'ssh_key', 'token',
                         'certificate', 'other')),
    domain        TEXT NOT NULL DEFAULT '',
    source        TEXT NOT NULL DEFAULT '',
    cracked       INTEGER NOT NULL DEFAULT 0,
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
                         'web_shell', 'db', 'token', 'vpn', 'other')),
    username      TEXT NOT NULL DEFAULT '',
    privilege     TEXT NOT NULL DEFAULT 'user'
                  CHECK (privilege IN ('user', 'admin', 'root', 'system',
                         'service', 'domain_admin', 'other')),
    method        TEXT NOT NULL DEFAULT '',
    session_ref   TEXT NOT NULL DEFAULT '',
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
                  CHECK (status IN ('found', 'active', 'done')),
    severity      TEXT NOT NULL DEFAULT 'medium'
                  CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical')),
    endpoint      TEXT NOT NULL DEFAULT '',
    details       TEXT NOT NULL DEFAULT '',
    evidence_path TEXT NOT NULL DEFAULT '',
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
"""


def init_db(db_path: str | Path) -> sqlite3.Connection:
    """Create or open the state database and apply schema.

    Returns a connection with WAL mode and foreign keys enabled.
    """
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA_SQL)
    conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
    conn.commit()
    return conn
