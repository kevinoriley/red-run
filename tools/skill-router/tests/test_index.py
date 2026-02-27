"""Index tests for ChromaDB skill collection.

Validates that all indexable skills are present in the collection, no stale
entries exist, and semantic search returns expected results. Requires ChromaDB
built via install.sh — skips if .chromadb/ doesn't exist.
"""

from __future__ import annotations

from pathlib import Path

import pytest

# --- Paths ---

REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
SKILLS_DIR = REPO_ROOT / "skills"
DB_DIR = Path(__file__).resolve().parent.parent / ".chromadb"

# Same exclusion rules as indexer.py
SKIP_DIRS = {"_template"}
NATIVE_SKILLS = {"orchestrator"}


def _get_indexable_skill_names() -> set[str]:
    """Return set of skill directory names that should be indexed."""
    names = set()
    for path in SKILLS_DIR.rglob("SKILL.md"):
        relative = path.relative_to(SKILLS_DIR)
        if any(part in SKIP_DIRS for part in relative.parts):
            continue
        if path.parent.name in NATIVE_SKILLS:
            continue
        names.add(path.parent.name)
    return names


# --- Skip if ChromaDB not built ---

if not DB_DIR.exists():
    pytest.skip("ChromaDB not built — run install.sh first", allow_module_level=True)

# Import ChromaDB only after confirming it exists (avoids import errors in lint-only CI)
from server import _get_collection  # noqa: E402


# --- Fixtures ---


@pytest.fixture(scope="module")
def collection():
    """Return the ChromaDB collection."""
    return _get_collection(DB_DIR)


@pytest.fixture(scope="module")
def indexed_ids(collection) -> set[str]:
    """Return all IDs currently in the collection."""
    results = collection.get()
    return set(results["ids"])


@pytest.fixture(scope="module")
def skill_names() -> set[str]:
    """Return all indexable skill directory names."""
    return _get_indexable_skill_names()


# --- Index Completeness Tests ---


class TestIndexCompleteness:
    def test_all_skills_indexed(self, indexed_ids: set[str], skill_names: set[str]):
        """Every indexable skill should be present in the collection."""
        missing = skill_names - indexed_ids
        assert not missing, (
            f"{len(missing)} skill(s) not indexed: {sorted(missing)}. "
            f"Re-run: uv run python indexer.py"
        )

    def test_no_stale_entries(self, indexed_ids: set[str], skill_names: set[str]):
        """Every ID in the collection should correspond to an existing skill."""
        stale = indexed_ids - skill_names
        assert not stale, (
            f"{len(stale)} stale entry/entries in index: {sorted(stale)}. "
            f"Re-run: uv run python indexer.py"
        )


# --- Round-Trip Tests ---


class TestGetSkillRoundTrip:
    @pytest.fixture(
        params=sorted(_get_indexable_skill_names()),
        ids=lambda n: n,
    )
    def skill_name(self, request: pytest.FixtureRequest) -> str:
        return request.param

    def test_get_skill_returns_content(self, collection, skill_name: str):
        """collection.get(ids=[name]) returns a result with a valid path."""
        results = collection.get(ids=[skill_name], include=["metadatas"])
        assert results["ids"], f"Skill '{skill_name}' not found in collection"

        metadata = results["metadatas"][0]
        assert "path" in metadata, f"Skill '{skill_name}' metadata missing 'path'"
        path = Path(metadata["path"])
        assert path.exists(), (
            f"Skill '{skill_name}' indexed path does not exist: {path}"
        )


# --- Search Quality Tests ---


class TestSearchQuality:
    """Smoke tests: canonical queries must return the expected skill as top-1."""

    QUERIES = [
        ("SQL injection with UNION SELECT", "sql-injection-union"),
        ("Kerberos roasting attack", "kerberos-roasting"),
        ("Linux kernel exploit DirtyPipe PwnKit CVE", "linux-kernel-exploits"),
        ("SSRF server-side request forgery internal service", "ssrf"),
        ("Tomcat WAR deployment", "tomcat-manager-deploy"),
        ("lxd group privilege escalation", "linux-file-path-abuse"),
        ("Active Directory certificate abuse", "adcs-template-abuse"),
        ("Blind XPath/NoSQL injection", "nosql-injection"),
    ]

    @pytest.fixture(params=QUERIES, ids=lambda q: q[1])
    def query_and_expected(self, request: pytest.FixtureRequest) -> tuple[str, str]:
        return request.param

    def test_top1_result(self, collection, query_and_expected: tuple[str, str]):
        query, expected = query_and_expected
        results = collection.query(
            query_texts=[query],
            n_results=1,
            include=["distances"],
        )
        assert results["ids"][0], f"No results for query: {query}"
        top1 = results["ids"][0][0]
        assert top1 == expected, (
            f"Query '{query}': expected top-1 '{expected}', got '{top1}'"
        )
