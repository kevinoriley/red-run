"""Unit tests for state-server.

Tests schema creation, migrations, CRUD operations, chain BFS, flow graph
pruning, and enum validation. Uses tmp_path for isolated SQLite — no network,
no MCP connection, no engagement directory needed.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

# Add server directory to path so we can import server modules
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import server as server_mod
from schema import SCHEMA_VERSION, init_db
from server import create_server


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def call(srv, tool_name: str, **kwargs) -> str:
    """Call a registered MCP tool function by name."""
    tool = srv._tool_manager._tools[tool_name]
    return tool.fn(**kwargs)


def call_json(srv, tool_name: str, **kwargs) -> dict:
    """Call a tool and parse the JSON result."""
    return json.loads(call(srv, tool_name, **kwargs))


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def db_path(tmp_path: Path) -> Path:
    return tmp_path / "state.db"


@pytest.fixture
def db(db_path: Path):
    conn = init_db(db_path)
    conn.execute("INSERT INTO engagement (id, name) VALUES (1, 'test')")
    conn.commit()
    yield conn
    conn.close()


@pytest.fixture
def srv(db_path: Path, monkeypatch):
    """Create a server with a temp database, engagement initialized."""
    monkeypatch.setattr(server_mod, "DB_PATH", db_path)
    s = create_server()
    call(s, "init_engagement", name="test")
    return s


# ---------------------------------------------------------------------------
# Schema tests
# ---------------------------------------------------------------------------


class TestSchema:
    def test_init_db_creates_tables(self, db_path: Path):
        conn = init_db(db_path)
        tables = {
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
        expected = {
            "engagement", "targets", "ports", "credentials",
            "credential_access", "access", "vulns", "pivot_map",
            "blocked", "state_events", "tunnels",
        }
        assert expected.issubset(tables), f"Missing tables: {expected - tables}"
        conn.close()

    def test_init_db_idempotent(self, db_path: Path):
        conn1 = init_db(db_path)
        conn1.close()
        conn2 = init_db(db_path)
        conn2.close()

    def test_schema_version(self, db_path: Path):
        conn = init_db(db_path)
        version = conn.execute("PRAGMA user_version").fetchone()[0]
        assert version == SCHEMA_VERSION
        conn.close()


class TestMigration:
    def test_v17_to_v18_adds_via_vuln_id(self, tmp_path: Path, monkeypatch):
        """Simulate a v17 database and verify migration adds via_vuln_id."""
        import sqlite3

        db_path = tmp_path / "migrate.db"
        conn = sqlite3.connect(str(db_path))
        # Create minimal v17 schema — just enough for the migration to work
        conn.execute("PRAGMA user_version = 17")
        conn.executescript("""
            CREATE TABLE engagement (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                name TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL DEFAULT 'active',
                mode TEXT NOT NULL DEFAULT 'ctf',
                created_at TEXT NOT NULL DEFAULT '',
                closed_at TEXT
            );
            CREATE TABLE targets (id INTEGER PRIMARY KEY, ip TEXT UNIQUE);
            CREATE TABLE access (
                id INTEGER PRIMARY KEY,
                target_id INTEGER,
                via_credential_id INTEGER,
                via_access_id INTEGER
            );
        """)
        conn.commit()
        conn.close()

        # Run migration via init_db
        conn2 = init_db(db_path)
        cols = [r[1] for r in conn2.execute("PRAGMA table_info(access)").fetchall()]
        assert "via_vuln_id" in cols
        version = conn2.execute("PRAGMA user_version").fetchone()[0]
        assert version == SCHEMA_VERSION
        conn2.close()

    def test_migration_idempotent(self, tmp_path: Path):
        db_path = tmp_path / "idem.db"
        conn1 = init_db(db_path)
        conn1.close()
        conn2 = init_db(db_path)
        cols = [r[1] for r in conn2.execute("PRAGMA table_info(access)").fetchall()]
        assert "via_vuln_id" in cols
        conn2.close()


# ---------------------------------------------------------------------------
# CRUD tests
# ---------------------------------------------------------------------------


class TestTargetCrud:
    def test_add_target(self, srv):
        data = call_json(srv, "add_target", ip="10.10.10.5", os="Linux")
        assert data["ip"] == "10.10.10.5"
        targets = json.loads(call(srv, "get_targets", ip="10.10.10.5"))
        assert len(targets) == 1
        assert targets[0]["os"] == "Linux"

    def test_upsert_target(self, srv):
        call(srv, "add_target", ip="10.10.10.6", os="Linux")
        data = call_json(srv, "add_target", ip="10.10.10.6", os="Ubuntu 22.04")
        assert data["action"] == "updated"
        targets = json.loads(call(srv, "get_targets", ip="10.10.10.6"))
        assert targets[0]["os"] == "Ubuntu 22.04"

    def test_add_port(self, srv):
        call(srv, "add_target", ip="10.10.10.7")
        call(srv, "add_port", ip="10.10.10.7", port=80, service="http")
        targets = json.loads(call(srv, "get_targets", ip="10.10.10.7"))
        ports = targets[0]["ports"]
        assert any(p["port"] == 80 and p["service"] == "http" for p in ports)


class TestCredentialCrud:
    def test_add_credential(self, srv):
        data = call_json(srv, "add_credential",
                         username="admin", secret="Password123", secret_type="password")
        assert data["username"] == "admin"
        assert "credential_id" in data

    def test_credential_dedup(self, srv):
        d1 = call_json(srv, "add_credential",
                        username="admin", secret="pass", secret_type="password")
        d2 = call_json(srv, "add_credential",
                        username="admin", secret="pass", secret_type="password")
        assert d2.get("status") == "duplicate_skipped"
        assert d2["credential_id"] == d1["credential_id"]

    def test_credential_via_provenance(self, srv):
        call(srv, "add_target", ip="10.10.10.8")
        vuln = call_json(srv, "add_vuln", title="LFI", ip="10.10.10.8",
                         severity="high")
        cred = call_json(srv, "add_credential",
                         username="dbuser", secret="dbpass",
                         via_vuln_id=vuln["vuln_id"])
        creds = json.loads(call(srv, "get_credentials"))
        match = [c for c in creds if c["username"] == "dbuser"]
        assert match[0]["via_vuln_id"] == vuln["vuln_id"]


class TestAccessCrud:
    def test_add_access(self, srv):
        call(srv, "add_target", ip="10.10.10.9")
        data = call_json(srv, "add_access", ip="10.10.10.9",
                         username="www-data", privilege="user")
        assert data["access_type"] == "shell"
        access = json.loads(call(srv, "get_access"))
        assert len(access) == 1

    def test_access_via_vuln_id(self, srv):
        call(srv, "add_target", ip="10.10.10.10")
        vuln = call_json(srv, "add_vuln", title="RCE", ip="10.10.10.10",
                         severity="critical", status="exploited")
        access = call_json(srv, "add_access", ip="10.10.10.10",
                           username="www-data", via_vuln_id=vuln["vuln_id"])
        all_access = json.loads(call(srv, "get_access"))
        match = [a for a in all_access if a["id"] == access["access_id"]]
        assert match[0]["via_vuln_id"] == vuln["vuln_id"]

    def test_update_access_username(self, srv):
        call(srv, "add_target", ip="10.10.10.50")
        data = call_json(srv, "add_access", ip="10.10.10.50", privilege="user")
        # Username was blank — patch it
        call(srv, "update_access", id=data["access_id"], username="jboss")
        all_access = json.loads(call(srv, "get_access"))
        match = [a for a in all_access if a["id"] == data["access_id"]]
        assert match[0]["username"] == "jboss"

    def test_revoke_access(self, srv):
        call(srv, "add_target", ip="10.10.10.11")
        data = call_json(srv, "add_access", ip="10.10.10.11", username="user1")
        call(srv, "update_access", id=data["access_id"], active=False)
        active = json.loads(call(srv, "get_access", active_only=True))
        assert len(active) == 0
        all_access = json.loads(call(srv, "get_access", active_only=False))
        assert len(all_access) == 1

    def test_revoke_restores_sibling_vulns(self, srv):
        """When access is revoked, pruned sibling vulns should be restored."""
        call(srv, "add_target", ip="10.10.10.12")
        a = call_json(srv, "add_access", ip="10.10.10.12", username="user1")
        aid = a["access_id"]
        # Add two vulns from same access
        v1 = call_json(srv, "add_vuln", title="SQLi", ip="10.10.10.12",
                        severity="high", via_access_id=aid)
        v2 = call_json(srv, "add_vuln", title="LFI", ip="10.10.10.12",
                        severity="medium", via_access_id=aid)
        # Exploit one — should prune sibling
        call(srv, "update_vuln", id=v1["vuln_id"], status="exploited")
        # Revoke access — should restore pruned sibling
        call(srv, "update_access", id=aid, active=False)
        vulns = json.loads(call(srv, "get_vulns", target="10.10.10.12"))
        lfi = [v for v in vulns if v["id"] == v2["vuln_id"]][0]
        assert lfi["in_graph"] == 1


class TestVulnCrud:
    def test_add_vuln(self, srv):
        call(srv, "add_target", ip="10.10.10.13")
        data = call_json(srv, "add_vuln", title="XSS", ip="10.10.10.13",
                         severity="medium")
        assert data["title"] == "XSS"
        vulns = json.loads(call(srv, "get_vulns"))
        assert len(vulns) == 1

    def test_vuln_hard_dedup(self, srv):
        call(srv, "add_target", ip="10.10.10.14")
        d1 = call_json(srv, "add_vuln", title="SQLi in /search",
                        ip="10.10.10.14", severity="high")
        d2 = call_json(srv, "add_vuln", title="SQLi in /search",
                        ip="10.10.10.14", severity="high")
        assert d2.get("status") == "duplicate_skipped"
        assert d2["vuln_id"] == d1["vuln_id"]

    def test_exploit_prunes_siblings(self, srv):
        call(srv, "add_target", ip="10.10.10.15")
        a = call_json(srv, "add_access", ip="10.10.10.15", username="user1")
        aid = a["access_id"]
        v1 = call_json(srv, "add_vuln", title="SQLi", ip="10.10.10.15",
                        severity="high", via_access_id=aid)
        v2 = call_json(srv, "add_vuln", title="LFI", ip="10.10.10.15",
                        severity="medium", via_access_id=aid)
        result = call_json(srv, "update_vuln", id=v1["vuln_id"], status="exploited")
        assert result.get("siblings_pruned", 0) >= 1
        vulns = json.loads(call(srv, "get_vulns", target="10.10.10.15"))
        lfi = [v for v in vulns if v["id"] == v2["vuln_id"]][0]
        assert lfi["in_graph"] == 0

    def test_block_restores_siblings(self, srv):
        call(srv, "add_target", ip="10.10.10.16")
        a = call_json(srv, "add_access", ip="10.10.10.16", username="user1")
        aid = a["access_id"]
        v1 = call_json(srv, "add_vuln", title="SQLi", ip="10.10.10.16",
                        severity="high", via_access_id=aid)
        v2 = call_json(srv, "add_vuln", title="LFI", ip="10.10.10.16",
                        severity="medium", via_access_id=aid)
        # Exploit then block
        call(srv, "update_vuln", id=v1["vuln_id"], status="exploited")
        call(srv, "update_vuln", id=v1["vuln_id"], status="blocked")
        vulns = json.loads(call(srv, "get_vulns", target="10.10.10.16"))
        lfi = [v for v in vulns if v["id"] == v2["vuln_id"]][0]
        assert lfi["in_graph"] == 1


# ---------------------------------------------------------------------------
# Chain BFS tests
# ---------------------------------------------------------------------------


class TestChainBfs:
    def test_empty_chain(self, srv):
        chain = json.loads(call(srv, "get_chain"))
        assert chain["chain"] == []
        assert chain["orphans"] == []

    def test_linear_chain(self, srv):
        """cred → access → vuln should produce a connected chain."""
        call(srv, "add_target", ip="10.10.10.20")
        cred = call_json(srv, "add_credential",
                         username="admin", secret="pass")
        access = call_json(srv, "add_access", ip="10.10.10.20",
                           username="admin",
                           via_credential_id=cred["credential_id"])
        call(srv, "add_vuln", title="Privesc", ip="10.10.10.20",
             severity="high", via_access_id=access["access_id"])
        chain = json.loads(call(srv, "get_chain"))
        assert len(chain["chain"]) == 3
        assert chain["orphans"] == []

    def test_vuln_to_access_edge(self, srv):
        """access.via_vuln_id should create a vuln→access edge in BFS."""
        call(srv, "add_target", ip="10.10.10.21")
        vuln = call_json(srv, "add_vuln", title="RCE", ip="10.10.10.21",
                         severity="critical", status="exploited")
        call(srv, "add_access", ip="10.10.10.21", username="www-data",
             via_vuln_id=vuln["vuln_id"])
        chain = json.loads(call(srv, "get_chain"))
        types = [s["type"] for s in chain["chain"]]
        assert "vuln" in types
        assert "access" in types
        # Access should be via the vuln
        access_step = [s for s in chain["chain"] if s["type"] == "access"][0]
        assert access_step["via"]["type"] == "vuln"
        assert access_step["via"]["id"] == vuln["vuln_id"]
        assert chain["orphans"] == []


# ---------------------------------------------------------------------------
# Enum validation tests
# ---------------------------------------------------------------------------


class TestEnumValidation:
    def test_invalid_access_type(self, srv):
        call(srv, "add_target", ip="10.10.10.30")
        result = call(srv, "add_access", ip="10.10.10.30",
                      access_type="invalid_type")
        assert "ERROR" in result

    def test_invalid_severity(self, srv):
        call(srv, "add_target", ip="10.10.10.31")
        result = call(srv, "add_vuln", title="Test", ip="10.10.10.31",
                      severity="extreme")
        assert "ERROR" in result

    def test_invalid_secret_type(self, srv):
        result = call(srv, "add_credential",
                      username="x", secret="y", secret_type="magic")
        assert "ERROR" in result


# ---------------------------------------------------------------------------
# State summary tests
# ---------------------------------------------------------------------------


class TestStateSummary:
    def test_empty_summary(self, srv):
        summary = call(srv, "get_state_summary")
        assert "Engagement State" in summary
        assert "_(none)_" in summary

    def test_populated_summary(self, srv):
        call(srv, "add_target", ip="10.10.10.40", os="Linux")
        call(srv, "add_vuln", title="Test vuln", ip="10.10.10.40",
             severity="high")
        summary = call(srv, "get_state_summary")
        assert "10.10.10.40" in summary
        assert "Test vuln" in summary


# ---------------------------------------------------------------------------
# Engagement lifecycle tests
# ---------------------------------------------------------------------------


class TestEngagement:
    def test_init_engagement(self, srv):
        # Already initialized by fixture — verify state
        summary = call(srv, "get_state_summary")
        assert "active" in summary

    def test_close_engagement(self, srv):
        result = call_json(srv, "close_engagement")
        assert result["status"] == "closed"
