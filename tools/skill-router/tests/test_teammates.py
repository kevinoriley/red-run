"""Lint tests for teammate spawn templates.

Validates required sections, state-mgr message protocol, via_vuln_id coverage,
and scope boundaries. No network or MCP server required — reads teammate
files directly.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

# --- Paths ---

REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
TEAMMATES_DIR = REPO_ROOT / "teammates"

# state-mgr is the protocol receiver, not sender — skip protocol sender checks
STATE_MGR = "state-mgr"

# On-demand teammates have specialized roles — not all protocol actions apply
ON_DEMAND = {"pivot", "bypass", "spray", "recover", "research"}

# Enum + ops teammates are the core senders of all protocol actions
CORE_TEAMMATES = None  # computed at test time: everything except STATE_MGR and ON_DEMAND


# --- Helpers ---


def _get_teammate_files() -> list[Path]:
    """Return all .md files in teammates/ except README.md."""
    if not TEAMMATES_DIR.exists():
        return []
    return sorted(
        p for p in TEAMMATES_DIR.glob("*.md") if p.name != "README.md"
    )


def _teammate_id(path: Path) -> str:
    return path.stem


# --- Fixtures ---


@pytest.fixture(params=_get_teammate_files(), ids=lambda p: _teammate_id(p))
def teammate_file(request: pytest.FixtureRequest) -> Path:
    return request.param


@pytest.fixture
def teammate_text(teammate_file: Path) -> str:
    return teammate_file.read_text()


# --- Required sections ---


class TestRequiredSections:
    def test_has_how_tasks_work(self, teammate_file: Path, teammate_text: str):
        # state-mgr uses "## How Messages Work" (different role)
        has_section = (
            "## How Tasks Work" in teammate_text
            or "## How Messages Work" in teammate_text
        )
        assert has_section, (
            f"{teammate_file.stem}: missing '## How Tasks Work' or '## How Messages Work' section"
        )

    def test_has_communication(self, teammate_file: Path, teammate_text: str):
        assert "## Communication" in teammate_text, (
            f"{teammate_file.stem}: missing '## Communication' section"
        )

    def test_has_scope_boundaries(self, teammate_file: Path, teammate_text: str):
        assert "## Scope Boundaries" in teammate_text, (
            f"{teammate_file.stem}: missing '## Scope Boundaries' section"
        )

    def test_has_operational_notes(self, teammate_file: Path, teammate_text: str):
        # state-mgr uses "## Operational Notes"
        assert "## Operational Notes" in teammate_text, (
            f"{teammate_file.stem}: missing '## Operational Notes' section"
        )


# --- State message protocol ---


class TestStateProtocol:
    """Core teammates (enum + ops) must include [add-vuln], [add-cred], [add-access] examples.

    On-demand teammates (pivot, bypass, spray, recover, research) have specialized
    roles and may not need all protocol actions.
    """

    def _skip_non_core(self, teammate_file: Path):
        if teammate_file.stem == STATE_MGR:
            pytest.skip("state-mgr defines the protocol, not sends it")
        if teammate_file.stem in ON_DEMAND:
            pytest.skip(f"{teammate_file.stem} is on-demand — protocol subset expected")

    def test_has_add_vuln_protocol(self, teammate_file: Path, teammate_text: str):
        self._skip_non_core(teammate_file)
        assert "[add-vuln]" in teammate_text, (
            f"{teammate_file.stem}: missing '[add-vuln]' protocol example"
        )

    def test_has_add_cred_protocol(self, teammate_file: Path, teammate_text: str):
        self._skip_non_core(teammate_file)
        assert "[add-cred]" in teammate_text, (
            f"{teammate_file.stem}: missing '[add-cred]' protocol example"
        )

    def test_has_add_access_protocol(self, teammate_file: Path, teammate_text: str):
        self._skip_non_core(teammate_file)
        assert "[add-access]" in teammate_text, (
            f"{teammate_file.stem}: missing '[add-access]' protocol example"
        )


# --- via_vuln_id coverage ---


class TestViaVulnId:
    """[add-access] protocol examples must include via_vuln_id."""

    def test_add_access_has_via_vuln_id(self, teammate_file: Path, teammate_text: str):
        if teammate_file.stem == STATE_MGR:
            pytest.skip("state-mgr defines the protocol, not sends it")
        # Find all [add-access] lines and check at least one has via_vuln_id
        access_lines = [
            line for line in teammate_text.splitlines()
            if "[add-access]" in line and "ip=" in line
        ]
        if not access_lines:
            pytest.skip(f"{teammate_file.stem}: no [add-access] protocol line found")
        has_via_vuln = any("via_vuln_id" in line for line in access_lines)
        assert has_via_vuln, (
            f"{teammate_file.stem}: [add-access] protocol missing via_vuln_id"
        )


# --- Skill discovery restrictions ---


class TestNoSkillDiscovery:
    """Templates should not call search_skills() or list_skills() except in negative context."""

    def test_no_search_skills_call(self, teammate_file: Path, teammate_text: str):
        lines = teammate_text.splitlines()
        for i, line in enumerate(lines, 1):
            if "search_skills" in line and "search_skills()" not in line:
                continue  # Just a mention, not a call
            if "search_skills()" in line:
                lower = line.lower()
                neg = ("do not", "don't", "never", "not call", "only")
                if not any(n in lower for n in neg):
                    pytest.fail(
                        f"{teammate_file.stem}:{i}: references search_skills() "
                        f"outside negative/restrictive context"
                    )

    def test_no_list_skills_call(self, teammate_file: Path, teammate_text: str):
        lines = teammate_text.splitlines()
        for i, line in enumerate(lines, 1):
            if "list_skills" in line and "list_skills()" not in line:
                continue
            if "list_skills()" in line:
                lower = line.lower()
                neg = ("do not", "don't", "never", "not call", "only")
                if not any(n in lower for n in neg):
                    pytest.fail(
                        f"{teammate_file.stem}:{i}: references list_skills() "
                        f"outside negative/restrictive context"
                    )


# --- state-mgr isolation ---


class TestStateMgrIsolation:
    """state-mgr must not reference target-interaction tools."""

    @pytest.fixture
    def state_mgr_text(self) -> str:
        path = TEAMMATES_DIR / "state-mgr.md"
        if not path.exists():
            pytest.skip("state-mgr.md not found")
        return path.read_text()

    def test_no_shell_server_tool_calls(self, state_mgr_text: str):
        """state-mgr should not contain tool call patterns for target interaction."""
        # These are actual tool invocation patterns, not negative scope mentions
        tool_calls = [
            "send_command(",
            "start_listener(",
            "start_process(",
            "nmap_scan(",
        ]
        for pattern in tool_calls:
            assert pattern not in state_mgr_text, (
                f"state-mgr.md contains tool call '{pattern}' — "
                f"state-mgr must not interact with targets"
            )
