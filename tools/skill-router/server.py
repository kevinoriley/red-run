"""MCP server for semantic skill discovery and retrieval in red-run.

Provides three tools:
- search_skills: Semantic search across all indexed skills
- get_skill: Load a skill's full SKILL.md content by name
- list_skills: Browse skill inventory by category

Usage:
    uv run python server.py [--skills-dir PATH] [--db-dir PATH]
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import chromadb
from chromadb.utils.embedding_functions import SentenceTransformerEmbeddingFunction
from mcp.server.fastmcp import FastMCP

EMBEDDING_MODEL = "all-MiniLM-L6-v2"
COLLECTION_NAME = "red-run-skills"

# Resolve defaults relative to this script
_SCRIPT_DIR = Path(__file__).resolve().parent
_DEFAULT_SKILLS_DIR = _SCRIPT_DIR.parent.parent / "skills"
_DEFAULT_DB_DIR = _SCRIPT_DIR / ".chromadb"


def _get_collection(db_dir: Path) -> chromadb.Collection:
    """Get the ChromaDB collection with pinned embedding function."""
    embedding_fn = SentenceTransformerEmbeddingFunction(model_name=EMBEDDING_MODEL)
    client = chromadb.PersistentClient(path=str(db_dir))
    return client.get_collection(
        name=COLLECTION_NAME,
        embedding_function=embedding_fn,
    )


def create_server(skills_dir: Path, db_dir: Path) -> FastMCP:
    """Create and configure the MCP server with skill routing tools."""
    mcp = FastMCP(
        "red-run-skill-router",
        instructions=(
            "Provides pentesting skill discovery and retrieval for red-run. "
            "Use search_skills to find relevant skills by describing a scenario. "
            "Use get_skill to load a skill's full methodology. "
            "Use list_skills to browse the inventory."
        ),
    )
    collection = _get_collection(db_dir)

    @mcp.tool()
    def search_skills(
        query: str,
        n: int = 5,
        category: str | None = None,
        min_similarity: float = 0.4,
    ) -> str:
        """Search for pentesting skills by describing a scenario or technique.

        Args:
            query: Natural language description of what you need
                   (e.g., "blind SQL injection in a login form",
                   "escalate privileges on Linux with SUID binaries",
                   "Kerberos ticket forging for domain persistence").
            n: Maximum number of results to return (default 5).
            category: Optional filter by category (web, ad, privesc, network).
            min_similarity: Minimum cosine similarity threshold (0.0-1.0).
                           Results below this are excluded. Default 0.4.
        """
        where = {"category": category} if category else None
        results = collection.query(
            query_texts=[query],
            n_results=min(n, 20),
            where=where,
            include=["metadatas", "distances"],
        )

        if not results["ids"][0]:
            return "No matching skills found."

        lines = []
        for id_, metadata, distance in zip(
            results["ids"][0],
            results["metadatas"][0],
            results["distances"][0],
        ):
            similarity = 1 - distance  # cosine distance → similarity
            if similarity < min_similarity:
                continue
            opsec = metadata.get("opsec", "unknown")
            lines.append(
                f"**{id_}** ({metadata['category']}, opsec: {opsec}) "
                f"[similarity: {similarity:.2f}]\n"
                f"  {metadata['description'][:200]}"
            )

        if not lines:
            return f"No skills found above similarity threshold ({min_similarity})."
        return "\n\n".join(lines)

    @mcp.tool()
    def get_skill(name: str) -> str:
        """Load a pentesting skill's full SKILL.md content by name.

        The returned content contains complete methodology, payloads, and
        instructions. Read it and follow the instructions for the engagement.

        Args:
            name: Skill name (e.g., "sql-injection-union", "kerberos-roasting",
                  "linux-sudo-suid-capabilities"). Use search_skills to discover
                  available names.
        """
        # Look up the skill path from ChromaDB metadata
        results = collection.get(ids=[name], include=["metadatas"])
        if not results["ids"]:
            # Fuzzy fallback: search by name
            search = collection.query(
                query_texts=[name], n_results=3, include=["metadatas"]
            )
            if search["ids"][0]:
                suggestions = ", ".join(search["ids"][0])
                return (
                    f"Skill '{name}' not found. Did you mean: {suggestions}?\n"
                    f'Use search_skills("{name}") for semantic search.'
                )
            return (
                f"Skill '{name}' not found. Use list_skills() to see available skills."
            )

        metadata = results["metadatas"][0]
        skill_path = Path(metadata["path"])

        if not skill_path.exists():
            # Path from index is stale — try to find it by convention
            skill_path = skills_dir / metadata["category"] / name / "SKILL.md"
            if not skill_path.exists():
                return (
                    f"Skill '{name}' is indexed but SKILL.md not found at "
                    f"{skill_path}. Re-run the indexer."
                )

        content = skill_path.read_text()
        header = (
            f"# SKILL: {name}\n"
            f"**Category**: {metadata['category']}\n"
            f"**Source**: {skill_path}\n\n"
            f"---\n\n"
        )
        return header + content

    @mcp.tool()
    def list_skills(category: str | None = None) -> str:
        """List all available pentesting skills, optionally filtered by category.

        Args:
            category: Filter by category (web, ad, privesc, network).
                      Omit to list all skills.
        """
        where = {"category": category} if category else None
        results = collection.get(where=where, include=["metadatas"])

        if not results["ids"]:
            if category:
                return f"No skills found in category '{category}'."
            return "No skills indexed. Run the indexer first."

        # Group by category
        by_category: dict[str, list[dict]] = {}
        for id_, metadata in zip(results["ids"], results["metadatas"]):
            cat = metadata["category"]
            by_category.setdefault(cat, []).append(
                {"name": id_, "description": metadata["description"][:150]}
            )

        lines = []
        for cat in sorted(by_category):
            lines.append(f"## {cat} ({len(by_category[cat])} skills)")
            for skill in sorted(by_category[cat], key=lambda s: s["name"]):
                lines.append(f"- **{skill['name']}**: {skill['description']}")
            lines.append("")

        total = sum(len(v) for v in by_category.values())
        lines.insert(0, f"**{total} skills available**\n")
        return "\n".join(lines)

    return mcp


def main() -> None:
    parser = argparse.ArgumentParser(description="red-run skill router MCP server")
    parser.add_argument(
        "--skills-dir",
        type=Path,
        default=_DEFAULT_SKILLS_DIR,
        help="Path to skills/ directory",
    )
    parser.add_argument(
        "--db-dir",
        type=Path,
        default=_DEFAULT_DB_DIR,
        help="Path to ChromaDB data directory",
    )
    args = parser.parse_args()

    if not args.db_dir.exists():
        print(
            f"Error: ChromaDB directory not found: {args.db_dir}\n"
            f"Run the indexer first: uv run python indexer.py",
            file=sys.stderr,
        )
        sys.exit(1)

    server = create_server(args.skills_dir, args.db_dir)
    server.run()


if __name__ == "__main__":
    main()
