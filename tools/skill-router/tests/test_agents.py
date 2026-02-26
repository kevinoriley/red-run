"""Lint tests for custom subagent definitions.

Validates agent frontmatter: required fields, mcpServers references,
tool lists. No network or MCP server required — reads agent files directly.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

# --- Paths ---

REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
AGENTS_DIR = REPO_ROOT / "agents"
MCP_CONFIG = REPO_ROOT / ".mcp.json"

REQUIRED_FIELDS = {"name", "description", "tools", "mcpServers"}
VALID_TOOLS = {
    "Read",
    "Write",
    "Edit",
    "Bash",
    "Grep",
    "Glob",
    "WebFetch",
    "WebSearch",
    "Task",
    "NotebookEdit",
}


def _get_agent_files() -> list[Path]:
    """Return all .md files in agents/."""
    if not AGENTS_DIR.exists():
        return []
    return sorted(AGENTS_DIR.glob("*.md"))


def _parse_agent_frontmatter(path: Path) -> dict:
    """Parse YAML frontmatter from an agent .md file."""
    content = path.read_text()
    if not content.startswith("---"):
        pytest.fail(f"{path.name}: missing YAML frontmatter (must start with ---)")

    end = content.index("---", 3)
    frontmatter = content[3:end].strip()
    return yaml.safe_load(frontmatter)


def _get_mcp_server_names() -> set[str]:
    """Return MCP server names from .mcp.json."""
    if not MCP_CONFIG.exists():
        return set()
    config = json.loads(MCP_CONFIG.read_text())
    return set(config.get("mcpServers", {}).keys())


# --- Tests ---


@pytest.fixture(params=_get_agent_files(), ids=lambda p: p.stem)
def agent_file(request: pytest.FixtureRequest) -> Path:
    return request.param


@pytest.fixture
def agent_frontmatter(agent_file: Path) -> dict:
    return _parse_agent_frontmatter(agent_file)


class TestAgentFrontmatter:
    def test_has_required_fields(self, agent_file: Path, agent_frontmatter: dict):
        missing = REQUIRED_FIELDS - set(agent_frontmatter.keys())
        assert not missing, f"{agent_file.name}: missing fields: {missing}"

    def test_name_matches_filename(self, agent_file: Path, agent_frontmatter: dict):
        expected = agent_file.stem
        assert agent_frontmatter["name"] == expected, (
            f"{agent_file.name}: frontmatter name '{agent_frontmatter['name']}' "
            f"doesn't match filename '{expected}'"
        )

    def test_description_not_empty(self, agent_file: Path, agent_frontmatter: dict):
        desc = agent_frontmatter.get("description", "")
        assert desc and len(desc.strip()) > 20, (
            f"{agent_file.name}: description too short or empty"
        )

    def test_tools_are_valid(self, agent_file: Path, agent_frontmatter: dict):
        tools = agent_frontmatter.get("tools", [])
        assert isinstance(tools, list), f"{agent_file.name}: tools must be a list"
        invalid = set(tools) - VALID_TOOLS
        assert not invalid, f"{agent_file.name}: invalid tools: {invalid}"

    def test_mcp_servers_exist_in_config(
        self, agent_file: Path, agent_frontmatter: dict
    ):
        servers = agent_frontmatter.get("mcpServers", [])
        assert isinstance(servers, list), (
            f"{agent_file.name}: mcpServers must be a list"
        )
        known_servers = _get_mcp_server_names()
        if not known_servers:
            pytest.skip(".mcp.json not found")
        unknown = set(servers) - known_servers
        assert not unknown, (
            f"{agent_file.name}: mcpServers reference unknown servers: {unknown}. "
            f"Known: {known_servers}"
        )

    def test_has_skill_router(self, agent_file: Path, agent_frontmatter: dict):
        servers = agent_frontmatter.get("mcpServers", [])
        assert "skill-router" in servers, (
            f"{agent_file.name}: must include skill-router in mcpServers"
        )


class TestAgentBody:
    def test_has_role_section(self, agent_file: Path):
        content = agent_file.read_text()
        assert "## Your Role" in content, (
            f"{agent_file.name}: missing '## Your Role' section"
        )

    def test_has_scope_boundaries(self, agent_file: Path):
        content = agent_file.read_text()
        assert "## Scope Boundaries" in content, (
            f"{agent_file.name}: missing '## Scope Boundaries' section"
        )

    def test_has_return_format(self, agent_file: Path):
        content = agent_file.read_text()
        assert "## Return Format" in content, (
            f"{agent_file.name}: missing '## Return Format' section"
        )

    def test_has_engagement_files(self, agent_file: Path):
        content = agent_file.read_text()
        assert "## Engagement Files" in content, (
            f"{agent_file.name}: missing '## Engagement Files' section"
        )

    def test_no_search_skills_call(self, agent_file: Path):
        content = agent_file.read_text()
        # Agents should NOT call search_skills — only the orchestrator does
        # Exception: if it's in a "do not" instruction
        lines = content.split("\n")
        for i, line in enumerate(lines, 1):
            if (
                "search_skills()" in line
                and "never call" not in line.lower()
                and "do not" not in line.lower()
            ):
                pytest.fail(
                    f"{agent_file.name}:{i}: references search_skills() — "
                    f"agents should only load the skill the orchestrator specifies"
                )

    def test_no_list_skills_call(self, agent_file: Path):
        content = agent_file.read_text()
        lines = content.split("\n")
        for i, line in enumerate(lines, 1):
            if (
                "list_skills()" in line
                and "never call" not in line.lower()
                and "do not" not in line.lower()
            ):
                pytest.fail(
                    f"{agent_file.name}:{i}: references list_skills() — "
                    f"agents should only load the skill the orchestrator specifies"
                )
