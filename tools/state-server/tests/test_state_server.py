"""Unit tests for state-server.

Tests schema creation, CRUD operations, server creation, and mode separation.
Uses tmp_path for in-memory SQLite — no network, no engagement directory needed.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

# Add server directory to path so we can import server modules
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from schema import SCHEMA_VERSION, init_db
from server import create_server

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def db_path(tmp_path: Path) -> Path:
    """Create a temporary database path."""
    return tmp_path / "state.db"


@pytest.fixture
def db(db_path: Path):
    """Initialize a temporary database and return the connection."""
    conn = init_db(db_path)
    # Insert the singleton engagement row
    conn.execute("INSERT INTO engagement (id, name) VALUES (1, 'test')")
    conn.commit()
    yield conn
    conn.close()


@pytest.fixture
def patched_db(db_path: Path, db):
    """Patch DB_PATH so server functions use the temp database."""
    with patch("server.DB_PATH", db_path):
        yield db


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
            "engagement",
            "targets",
            "ports",
            "credentials",
            "credential_access",
            "access",
            "vulns",
            "pivot_map",
            "blocked",
        }
        assert expected.issubset(tables), f"Missing tables: {expected - tables}"
        conn.close()

    def test_init_db_idempotent(self, db_path: Path):
        conn1 = init_db(db_path)
        conn1.close()
        # Calling again should not error
        conn2 = init_db(db_path)
        conn2.close()

    def test_schema_version(self, db_path: Path):
        conn = init_db(db_path)
        version = conn.execute("PRAGMA user_version").fetchone()[0]
        assert version == SCHEMA_VERSION
        conn.close()


# ---------------------------------------------------------------------------
# Server creation / mode tests
# ---------------------------------------------------------------------------


class TestServerCreation:
    def test_read_mode_has_read_tools(self):
        server = create_server("read")
        tool_names = {t.name for t in server._tool_manager.list_tools()}
        read_tools = {
            "get_state_summary",
            "get_targets",
            "get_credentials",
            "get_access",
            "get_vulns",
            "get_pivot_map",
            "get_blocked",
        }
        assert read_tools.issubset(tool_names), (
            f"Missing read tools: {read_tools - tool_names}"
        )

    def test_write_mode_has_write_tools(self):
        server = create_server("write")
        tool_names = {t.name for t in server._tool_manager.list_tools()}
        write_tools = {
            "init_engagement",
            "add_target",
            "add_credential",
            "add_access",
            "add_vuln",
            "add_pivot",
            "add_blocked",
        }
        assert write_tools.issubset(tool_names), (
            f"Missing write tools: {write_tools - tool_names}"
        )

    def test_read_mode_no_write_tools(self):
        server = create_server("read")
        tool_names = {t.name for t in server._tool_manager.list_tools()}
        write_only = {"add_target", "add_credential", "add_access", "add_vuln"}
        overlap = tool_names & write_only
        assert not overlap, f"Read mode should not have write tools: {overlap}"


# ---------------------------------------------------------------------------
# CRUD lifecycle tests
# ---------------------------------------------------------------------------


class TestCrudLifecycle:
    def _call_tool(self, server, name: str, kwargs: dict) -> str:
        """Call a registered tool function by name."""
        # Access the tool function directly from the server's registry
        tool = server._tool_manager._tools[name]
        return tool.fn(**kwargs)

    @pytest.fixture
    def write_server(self, db_path: Path, patched_db):
        """Create a write-mode server with patched DB."""
        with patch("server.DB_PATH", db_path):
            server = create_server("write")
            yield server

    def test_add_and_get_target(self, write_server):
        result = self._call_tool(
            write_server, "add_target", {"host": "10.10.10.5", "os": "Linux"}
        )
        data = json.loads(result)
        assert data["host"] == "10.10.10.5"
        assert data["action"] == "created"

        targets = json.loads(
            self._call_tool(write_server, "get_targets", {"host": "10.10.10.5"})
        )
        assert len(targets) == 1
        assert targets[0]["host"] == "10.10.10.5"
        assert targets[0]["os"] == "Linux"

    def test_add_target_with_ports(self, write_server):
        ports_json = json.dumps([
            {"port": 80, "service": "http"},
            {"port": 443, "service": "https"},
        ])
        self._call_tool(
            write_server,
            "add_target",
            {"host": "10.10.10.6", "ports": ports_json},
        )
        targets = json.loads(
            self._call_tool(write_server, "get_targets", {"host": "10.10.10.6"})
        )
        assert len(targets) == 1
        ports = targets[0]["ports"]
        assert len(ports) == 2
        port_numbers = {p["port"] for p in ports}
        assert port_numbers == {80, 443}

    def test_add_target_upsert(self, write_server):
        self._call_tool(
            write_server, "add_target", {"host": "10.10.10.7", "os": "Linux"}
        )
        result = self._call_tool(
            write_server,
            "add_target",
            {"host": "10.10.10.7", "os": "Ubuntu 22.04"},
        )
        data = json.loads(result)
        assert data["action"] == "updated"

        targets = json.loads(
            self._call_tool(write_server, "get_targets", {"host": "10.10.10.7"})
        )
        assert len(targets) == 1
        assert targets[0]["os"] == "Ubuntu 22.04"

    def test_add_and_get_credential(self, write_server):
        result = self._call_tool(
            write_server,
            "add_credential",
            {
                "username": "admin",
                "secret": "Password123",
                "secret_type": "password",
            },
        )
        data = json.loads(result)
        assert data["username"] == "admin"
        assert "credential_id" in data

        creds = json.loads(
            self._call_tool(write_server, "get_credentials", {})
        )
        assert len(creds) == 1
        assert creds[0]["username"] == "admin"

    def test_test_credential(self, write_server):
        # Create target and credential first
        self._call_tool(
            write_server, "add_target", {"host": "10.10.10.8"}
        )
        cred_result = json.loads(
            self._call_tool(
                write_server,
                "add_credential",
                {"username": "user1", "secret": "pass1"},
            )
        )
        cred_id = cred_result["credential_id"]

        result = self._call_tool(
            write_server,
            "test_credential",
            {
                "credential_id": cred_id,
                "host": "10.10.10.8",
                "service": "ssh",
                "works": True,
            },
        )
        data = json.loads(result)
        assert data["works"] is True

        creds = json.loads(
            self._call_tool(write_server, "get_credentials", {})
        )
        assert len(creds[0]["tested_against"]) == 1
        assert creds[0]["tested_against"][0]["works"] == 1

    def test_add_and_get_access(self, write_server):
        self._call_tool(
            write_server, "add_target", {"host": "10.10.10.9"}
        )
        result = self._call_tool(
            write_server,
            "add_access",
            {
                "host": "10.10.10.9",
                "access_type": "shell",
                "username": "www-data",
                "privilege": "user",
            },
        )
        data = json.loads(result)
        assert data["access_type"] == "shell"

        access = json.loads(
            self._call_tool(write_server, "get_access", {})
        )
        assert len(access) == 1
        assert access[0]["username"] == "www-data"

    def test_update_access_revoke(self, write_server):
        self._call_tool(
            write_server, "add_target", {"host": "10.10.10.10"}
        )
        result = json.loads(
            self._call_tool(
                write_server,
                "add_access",
                {"host": "10.10.10.10", "username": "user1"},
            )
        )
        access_id = result["access_id"]

        self._call_tool(
            write_server,
            "update_access",
            {"id": access_id, "active": False},
        )

        # active_only=True should exclude revoked access
        active = json.loads(
            self._call_tool(
                write_server, "get_access", {"active_only": True}
            )
        )
        assert len(active) == 0

        # active_only=False should include it
        all_access = json.loads(
            self._call_tool(
                write_server, "get_access", {"active_only": False}
            )
        )
        assert len(all_access) == 1

    def test_add_and_get_vuln(self, write_server):
        result = self._call_tool(
            write_server,
            "add_vuln",
            {
                "title": "SQLi in /search",
                "vuln_type": "sqli",
                "severity": "high",
            },
        )
        data = json.loads(result)
        assert data["title"] == "SQLi in /search"

        vulns = json.loads(
            self._call_tool(write_server, "get_vulns", {})
        )
        assert len(vulns) == 1
        assert vulns[0]["severity"] == "high"

    def test_add_and_get_pivot(self, write_server):
        result = self._call_tool(
            write_server,
            "add_pivot",
            {
                "source": "SQLi on 10.10.10.5",
                "destination": "DB creds for 10.10.10.1",
                "method": "data exfil",
            },
        )
        data = json.loads(result)
        assert data["source"] == "SQLi on 10.10.10.5"

        pivots = json.loads(
            self._call_tool(write_server, "get_pivot_map", {})
        )
        assert len(pivots) == 1

    def test_add_and_get_blocked(self, write_server):
        result = self._call_tool(
            write_server,
            "add_blocked",
            {
                "technique": "kerberoasting",
                "reason": "No SPNs found",
            },
        )
        data = json.loads(result)
        assert data["technique"] == "kerberoasting"

        blocked = json.loads(
            self._call_tool(write_server, "get_blocked", {})
        )
        assert len(blocked) == 1
        assert blocked[0]["reason"] == "No SPNs found"

    def test_state_summary_populated(self, write_server):
        # Add some data
        self._call_tool(
            write_server,
            "add_target",
            {"host": "10.10.10.20", "os": "Linux"},
        )
        self._call_tool(
            write_server,
            "add_vuln",
            {"title": "Test vuln", "severity": "high"},
        )

        summary = self._call_tool(
            write_server, "get_state_summary", {}
        )
        assert "Engagement State" in summary
        assert "10.10.10.20" in summary
        assert "Test vuln" in summary

    def test_state_summary_empty(self, write_server):
        summary = self._call_tool(
            write_server, "get_state_summary", {}
        )
        assert "Engagement State" in summary
        assert "_(none)_" in summary
