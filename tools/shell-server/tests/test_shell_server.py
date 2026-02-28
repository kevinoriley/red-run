"""Unit tests for shell-server.

Tests Session dataclass, transcript logic, and server creation.
No sockets, no TCP — pure unit tests.
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock

# Add server directory to path so we can import server module
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from server import Session, create_server


class TestSession:
    def _make_session(self) -> Session:
        return Session(
            session_id="test-001",
            conn=MagicMock(),
            remote_addr=("127.0.0.1", 4444),
            port=4444,
            label="test-session",
        )

    def test_log_appends_entry(self):
        session = self._make_session()
        assert len(session.transcript) == 0
        session.log("send", "id\n")
        assert len(session.transcript) == 1
        ts, direction, data = session.transcript[0]
        assert direction == "send"
        assert data == "id\n"
        # Timestamp should be ISO format
        assert "T" in ts

    def test_transcript_format(self):
        session = self._make_session()
        session.log("send", "whoami\n")
        session.log("recv", "root\n")
        assert len(session.transcript) == 2
        for entry in session.transcript:
            assert len(entry) == 3
            ts, direction, data = entry
            assert isinstance(ts, str)
            assert direction in ("send", "recv")
            assert isinstance(data, str)


class TestServerCreation:
    def test_creates_server(self):
        server = create_server()
        assert server is not None

    def test_server_name(self):
        server = create_server()
        assert server.name == "red-run-shell-server"
