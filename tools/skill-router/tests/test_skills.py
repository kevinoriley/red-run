"""Lint tests for SKILL.md files.

Validates skill frontmatter (required fields, name consistency, opsec values)
and required body sections. No network, no MCP server, no ChromaDB — reads
skill files directly. Only requires pyyaml + pytest.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

# --- Paths ---

REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
SKILLS_DIR = REPO_ROOT / "skills"

# Skills excluded from indexing (same rules as indexer.py)
SKIP_DIRS = {"_template"}
NATIVE_SKILLS = {"orchestrator"}

# Sections required for all indexed skills (except retrospective)
REQUIRED_SECTIONS = {
    "## Mode",
    "## Engagement Logging",
    "## State Management",
    "## Prerequisites",
    "## Troubleshooting",
}

# Retrospective is a post-mortem skill — no target interaction, different structure
RETROSPECTIVE_REQUIRED_SECTIONS = {
    "## Prerequisites",
    "## Troubleshooting",
    "## Engagement Logging",
}

REQUIRED_FRONTMATTER_FIELDS = {"name", "description", "keywords", "tools", "opsec"}
VALID_OPSEC_VALUES = {"low", "medium", "high"}

# Template placeholders that should not appear in real skills
TEMPLATE_PLACEHOLDERS = {
    "<skill-name>",
    "<technique description>",
    "<scope>",
}


# --- Helpers ---


def _get_skill_files() -> list[Path]:
    """Return all indexable SKILL.md paths (excludes _template and orchestrator)."""
    if not SKILLS_DIR.exists():
        return []
    files = []
    for path in sorted(SKILLS_DIR.rglob("SKILL.md")):
        relative = path.relative_to(SKILLS_DIR)
        if any(part in SKIP_DIRS for part in relative.parts):
            continue
        if path.parent.name in NATIVE_SKILLS:
            continue
        files.append(path)
    return files


def _parse_skill_frontmatter(path: Path) -> dict:
    """Parse YAML frontmatter from a SKILL.md file."""
    content = path.read_text()
    if not content.startswith("---"):
        pytest.fail(f"{path}: missing YAML frontmatter (must start with ---)")

    match = re.match(r"^---\s*\n(.*?)\n---", content, re.DOTALL)
    if not match:
        pytest.fail(f"{path}: malformed YAML frontmatter (no closing ---)")

    try:
        return yaml.safe_load(match.group(1)) or {}
    except yaml.YAMLError as e:
        pytest.fail(f"{path}: invalid YAML frontmatter: {e}")


def _get_all_skill_names() -> set[str]:
    """Return set of directory names for all indexable skills."""
    return {p.parent.name for p in _get_skill_files()}


def _get_all_skill_md_paths() -> list[Path]:
    """Return all SKILL.md paths including orchestrator (for routing ref checks)."""
    if not SKILLS_DIR.exists():
        return []
    files = []
    for path in sorted(SKILLS_DIR.rglob("SKILL.md")):
        relative = path.relative_to(SKILLS_DIR)
        if any(part in SKIP_DIRS for part in relative.parts):
            continue
        files.append(path)
    return files


def _skill_id(path: Path) -> str:
    """Return a readable test ID from a skill path (e.g., 'web/sql-injection-union')."""
    relative = path.relative_to(SKILLS_DIR)
    return str(relative.parent)


# --- Fixtures ---


@pytest.fixture(params=_get_skill_files(), ids=lambda p: _skill_id(p))
def skill_file(request: pytest.FixtureRequest) -> Path:
    return request.param


@pytest.fixture
def skill_frontmatter(skill_file: Path) -> dict:
    return _parse_skill_frontmatter(skill_file)


# --- Frontmatter Tests ---


class TestSkillFrontmatter:
    def test_has_required_fields(self, skill_file: Path, skill_frontmatter: dict):
        missing = REQUIRED_FRONTMATTER_FIELDS - set(skill_frontmatter.keys())
        assert not missing, f"{_skill_id(skill_file)}: missing fields: {missing}"

    def test_name_matches_directory(self, skill_file: Path, skill_frontmatter: dict):
        expected = skill_file.parent.name
        actual = skill_frontmatter.get("name", "")
        assert actual == expected, (
            f"{_skill_id(skill_file)}: frontmatter name '{actual}' "
            f"doesn't match directory name '{expected}'"
        )

    def test_keywords_nonempty(self, skill_file: Path, skill_frontmatter: dict):
        keywords = skill_frontmatter.get("keywords", [])
        assert isinstance(keywords, list) and len(keywords) >= 1, (
            f"{_skill_id(skill_file)}: keywords must be a non-empty list"
        )

    def test_opsec_valid(self, skill_file: Path, skill_frontmatter: dict):
        opsec = str(skill_frontmatter.get("opsec", "")).strip()
        assert opsec in VALID_OPSEC_VALUES, (
            f"{_skill_id(skill_file)}: opsec '{opsec}' not in {VALID_OPSEC_VALUES}"
        )

    def test_description_not_empty(self, skill_file: Path, skill_frontmatter: dict):
        desc = skill_frontmatter.get("description", "")
        assert isinstance(desc, str) and len(desc.strip()) > 20, (
            f"{_skill_id(skill_file)}: description must be >20 chars, "
            f"got {len(str(desc).strip())} chars"
        )


# --- Section Tests ---


class TestSkillSections:
    def test_has_required_sections(self, skill_file: Path):
        content = skill_file.read_text()
        skill_name = skill_file.parent.name

        if skill_name == "retrospective":
            required = RETROSPECTIVE_REQUIRED_SECTIONS
        else:
            required = REQUIRED_SECTIONS

        missing = []
        for section in required:
            if section not in content:
                missing.append(section)

        assert not missing, (
            f"{_skill_id(skill_file)}: missing required sections: {missing}"
        )


# --- Routing Reference Tests ---


class TestSkillRouting:
    def test_no_old_routing_refs(self):
        """No skills should use the old 'Invoke **X** via the Skill tool' pattern."""
        old_pattern = re.compile(r"Invoke \*\*.*?\*\* via the Skill tool")
        violations = []

        for path in _get_all_skill_md_paths():
            content = path.read_text()
            for i, line in enumerate(content.splitlines(), 1):
                if old_pattern.search(line):
                    violations.append(f"{_skill_id(path)}:{i}: {line.strip()}")

        assert not violations, (
            f"Found old routing pattern in {len(violations)} location(s):\n"
            + "\n".join(violations)
        )

    def test_get_skill_refs_valid(self):
        """Every get_skill('X') reference must point to an existing skill."""
        known = _get_all_skill_names()
        # Documentation examples use placeholder names — skip them
        placeholder_refs = {"skill-name"}
        ref_pattern = re.compile(r'get_skill\(["\']([^"\']+)["\']\)')
        invalid = []

        for path in _get_all_skill_md_paths():
            content = path.read_text()
            for match in ref_pattern.finditer(content):
                ref_name = match.group(1)
                if ref_name in placeholder_refs:
                    continue
                if ref_name not in known:
                    invalid.append(f"{_skill_id(path)}: get_skill(\"{ref_name}\")")

        assert not invalid, (
            f"Found {len(invalid)} get_skill() ref(s) to non-existent skills:\n"
            + "\n".join(invalid)
        )

    def test_no_template_placeholders(self):
        """Indexed skills must not contain template placeholder literals."""
        # Retrospective uses <skill-name> as output format instructions, not as
        # an unfilled template placeholder
        excluded = {"retrospective"}
        violations = []

        for path in _get_skill_files():
            if path.parent.name in excluded:
                continue
            content = path.read_text()
            for placeholder in TEMPLATE_PLACEHOLDERS:
                if placeholder in content:
                    violations.append(f"{_skill_id(path)}: contains '{placeholder}'")

        assert not violations, (
            f"Found template placeholders in {len(violations)} location(s):\n"
            + "\n".join(violations)
        )
