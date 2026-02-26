"""Index red-run SKILL.md files into ChromaDB for semantic search.

Reads structured frontmatter (name, description, keywords, tools, opsec) and
section headers from each SKILL.md, builds a compact embedding document per
skill, and upserts into a ChromaDB collection.

Usage:
    uv run python indexer.py [--skills-dir PATH] [--db-dir PATH]
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

import chromadb
import yaml
from chromadb.utils.embedding_functions import SentenceTransformerEmbeddingFunction

EMBEDDING_MODEL = "all-MiniLM-L6-v2"
COLLECTION_NAME = "red-run-skills"

# Skills that stay native (not served via MCP)
NATIVE_SKILLS = {"orchestrator"}

# Directories to skip during indexing
SKIP_DIRS = {"_template"}


def parse_frontmatter(content: str) -> dict[str, str]:
    """Extract YAML frontmatter from SKILL.md content."""
    match = re.match(r"^---\s*\n(.*?)\n---", content, re.DOTALL)
    if not match:
        return {}
    try:
        return yaml.safe_load(match.group(1)) or {}
    except yaml.YAMLError:
        return {}


def extract_headers(content: str) -> list[str]:
    """Extract ## and ### section headers, filtering boilerplate."""
    boilerplate = {
        "Mode",
        "Engagement Logging",
        "Skill Routing Is Mandatory",
        "State Management",
        "Exploit and Tool Transfer",
        "Prerequisites",
        "Troubleshooting",
        "OPSEC Notes",
        "Invocation Log",
        "Scope Boundary",
    }
    headers = []
    in_code_block = False
    for line in content.splitlines():
        if line.startswith("```"):
            in_code_block = not in_code_block
        if not in_code_block and re.match(r"^#{2,3}\s+", line):
            header = re.sub(r"^#+\s+", "", line).strip()
            if header not in boilerplate:
                headers.append(header)
    return headers


def derive_category(skill_path: Path, skills_dir: Path) -> str:
    """Derive category from directory structure (e.g., 'web', 'ad', 'privesc')."""
    relative = skill_path.relative_to(skills_dir)
    parts = relative.parts
    # Structure: <category>/<skill-name>/SKILL.md or <skill-name>/SKILL.md
    if len(parts) >= 3:
        return parts[0]
    return "uncategorized"


MAX_HEADERS = 15  # Cap headers to stay within embedding model's 256-token limit


def build_document(
    name: str,
    description: str,
    category: str,
    keywords: list[str],
    tools: list[str],
    headers: list[str],
) -> str:
    """Build the text document to embed for a single skill.

    Uses structured frontmatter fields (description, keywords, tools) to build
    a compact, keyword-rich document within the model's 256-token limit. Each
    field is purpose-built: description provides semantic context, keywords
    provide exact search terms, tools enable tool-name lookups, and headers
    add technique-specific section names as bonus context.
    """
    parts = [f"name: {name}", f"category: {category}", f"description: {description}"]
    if keywords:
        parts.append(f"keywords: {', '.join(keywords)}")
    if tools:
        parts.append(f"tools: {', '.join(tools)}")
    if headers:
        parts.append(f"sections: {', '.join(headers[:MAX_HEADERS])}")
    return "\n".join(parts)


def index_skills(skills_dir: Path, db_dir: Path) -> int:
    """Index all SKILL.md files into ChromaDB. Returns count of indexed skills."""
    embedding_fn = SentenceTransformerEmbeddingFunction(model_name=EMBEDDING_MODEL)
    client = chromadb.PersistentClient(path=str(db_dir))
    collection = client.get_or_create_collection(
        name=COLLECTION_NAME,
        embedding_function=embedding_fn,
        metadata={"hnsw:space": "cosine"},
    )

    skill_files = sorted(skills_dir.rglob("SKILL.md"))
    indexed = []
    skipped = []

    for skill_path in skill_files:
        # Skip _template and native skills
        relative = skill_path.relative_to(skills_dir)
        if any(part in SKIP_DIRS for part in relative.parts):
            skipped.append(f"{relative} (template)")
            continue
        skill_dir_name = skill_path.parent.name
        if skill_dir_name in NATIVE_SKILLS:
            skipped.append(f"{relative} (native)")
            continue

        content = skill_path.read_text()
        frontmatter = parse_frontmatter(content)
        name = frontmatter.get("name", skill_dir_name)
        description = frontmatter.get("description", "").strip()

        if not description:
            skipped.append(f"{relative} (no description)")
            continue

        keywords = frontmatter.get("keywords", []) or []
        tools = frontmatter.get("tools", []) or []
        opsec = frontmatter.get("opsec", "medium")

        category = derive_category(skill_path, skills_dir)
        headers = extract_headers(content)
        document = build_document(name, description, category, keywords, tools, headers)

        indexed.append(
            {
                "id": name,
                "document": document,
                "metadata": {
                    "name": name,
                    "category": category,
                    "path": str(skill_path),
                    "description": description,
                    "opsec": str(opsec),
                },
            }
        )

    if indexed:
        collection.upsert(
            ids=[s["id"] for s in indexed],
            documents=[s["document"] for s in indexed],
            metadatas=[s["metadata"] for s in indexed],
        )

    # Clean up stale entries (skills that were removed)
    indexed_ids = {s["id"] for s in indexed}
    existing = collection.get()
    stale_ids = [id_ for id_ in existing["ids"] if id_ not in indexed_ids]
    if stale_ids:
        collection.delete(ids=stale_ids)
        print(f"Removed {len(stale_ids)} stale entries: {', '.join(stale_ids)}")

    print(f"Indexed {len(indexed)} skills into {db_dir}")
    for s in indexed:
        print(f"  + {s['metadata']['category']}/{s['id']}")
    if skipped:
        print(f"Skipped {len(skipped)}:")
        for s in skipped:
            print(f"  - {s}")

    return len(indexed)


def main() -> None:
    parser = argparse.ArgumentParser(description="Index red-run skills into ChromaDB")
    parser.add_argument(
        "--skills-dir",
        type=Path,
        default=Path(__file__).resolve().parent.parent.parent / "skills",
        help="Path to skills/ directory (default: ../../skills relative to this script)",
    )
    parser.add_argument(
        "--db-dir",
        type=Path,
        default=Path(__file__).resolve().parent / ".chromadb",
        help="Path to ChromaDB data directory (default: .chromadb/ next to this script)",
    )
    args = parser.parse_args()

    if not args.skills_dir.is_dir():
        print(f"Error: skills directory not found: {args.skills_dir}", file=sys.stderr)
        sys.exit(1)

    count = index_skills(args.skills_dir, args.db_dir)
    if count == 0:
        print("Warning: no skills were indexed", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
