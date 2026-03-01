# skill-router MCP Server

MCP server providing semantic skill discovery and retrieval for red-run
agents. Skills are indexed from structured YAML frontmatter into ChromaDB
with sentence-transformer embeddings, enabling natural language search across
the entire skill library.

## Prerequisites

### Install Python dependencies

```bash
uv sync --directory tools/skill-router
```

This pulls in ChromaDB, sentence-transformers (`all-MiniLM-L6-v2`), and the
MCP SDK. First run will download the embedding model (~80MB).

## Usage

### Index skills

Before the server can serve queries, skills must be indexed:

```bash
uv run --directory tools/skill-router python indexer.py
```

The indexer reads every `skills/<category>/<skill-name>/SKILL.md`, extracts
YAML frontmatter (name, description, keywords, tools, opsec), and upserts into
a ChromaDB collection at `tools/skill-router/.chromadb/`. Stale entries (deleted
skills) are automatically cleaned up.

Re-run the indexer after adding, removing, or modifying skills.

### Start the server

The server runs as an MCP server, started automatically by Claude Code via
`.mcp.json`. To test manually:

```bash
uv run --directory tools/skill-router python server.py
```

## Tools

| Tool | Parameters | Description |
|------|-----------|-------------|
| `search_skills` | `query` (required), `n` (default 5), `category` (optional), `min_similarity` (default 0.4) | Semantic search across all indexed skills |
| `get_skill` | `name` (required) | Load a skill's full SKILL.md content by name |
| `list_skills` | `category` (optional) | List all available skills, optionally filtered by category |

## How indexing works

The indexer builds one embedding document per skill from structured frontmatter
fields:

- **description**: Provides semantic context for natural language queries
- **keywords**: Exact search terms (technique names, CVE IDs, tool names)
- **tools**: Enables tool-name lookups (e.g., "sqlmap" finds SQL injection skills)
- **opsec**: Included in search results so agents can assess detection risk
- **section headers**: Technique-specific headers added as bonus context

Documents are embedded with `all-MiniLM-L6-v2` (256-token limit). The indexer
caps headers at 15 to stay within the limit.

## Configuration

| CLI Flag | Default | Description |
|----------|---------|-------------|
| `--skills-dir` | `../../skills` (relative to script) | Path to skills directory |
| `--db-dir` | `.chromadb/` (next to script) | Path to ChromaDB data directory |

## Data

ChromaDB data lives at `tools/skill-router/.chromadb/` (gitignored). Delete it
and re-run the indexer to rebuild from scratch.
