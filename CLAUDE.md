# red-run

Claude Code skill library for penetration testing and CTF work.

## Engagement Workflow

The orchestrator is invoked via `/red-run-ctf` slash command only — not by
natural language triggers. It contains all routing logic, approval gates,
and state management rules. **If you are an agent teams teammate** (you were
spawned by a team lead and received a task assignment), **do NOT invoke the
orchestrator skill.** Load technique skills via
`mcp__skill-router__get_skill()` instead — never via the Skill tool.

## Token Budget

Every token costs money and latency. Consider token impact when making ANY
change to red-run — agent templates, skill text, MCP responses, orchestrator
prompts. Prefer designs that minimize per-invocation token usage without
sacrificing needed functionality. Examples: put hints in tool responses (loaded
only when called) rather than agent templates (loaded every invocation); keep
agent templates focused; avoid verbose boilerplate. This is a judgment call —
never cut needed context, but always ask "does this need to be in every
invocation?"

**No inline file templates.** Never embed file contents (YAML, shell scripts,
JSON, config files) directly in skill files, agent templates, or orchestrator
prompts. These burn context tokens on every invocation even when the file isn't
being written. Instead, store templates in `operator/templates/` and reference
them by path. The orchestrator reads and populates templates at runtime — the
template content is only loaded when actually needed.

## Orchestrator Variants

Multiple orchestrators coexist in the same repo, sharing state.db, MCP servers,
and technique skills. Each variant uses a different execution model.

| Variant | Invoke | Status | Execution Model |
|---------|--------|--------|-----------------|
| `/red-run-ctf` | Slash command only | **Active** (default) | Agent teams (persistent teammates, peer messaging) |
| `/red-run-legacy` | Slash command only | **Legacy** | Subagents (ephemeral, one skill per invocation) |
| `/red-run-notouch` | Slash command only | **Planned** | DLP-safe — operator runs commands, reports sanitized output |
| `/red-run-train` | Slash command only | **Planned** | Training mode — guided walkthrough with explanations |

**`/red-run-ctf`** uses Claude Code agent teams. Requires
`CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS=1` in env or `.claude/settings.json`.
The orchestrator calls `TeamCreate(team_name="red-run")` at engagement start,
then spawns teammates via `Agent` with `team_name="red-run"`. Most teammates
spawn as Sonnet 200k by default. Teammate spawn templates live in
`teammates/` — see `teammates/README.md`.

**`/red-run-legacy`** is the original subagent-based orchestrator. Agent
definitions live in `agents/`. Invoke with `/red-run-legacy` if needed.

Both orchestrators use the same state.db schema, MCP servers, and technique
skills. An engagement started with one can be resumed with the other.

## Architecture

The default **orchestrator** (`/red-run-ctf`) uses Claude Code agent teams.
The lead session runs the orchestrator skill, creates a team via `TeamCreate`,
spawns persistent domain teammates via `Agent` with `team_name`, assigns tasks
via `TaskCreate`/`TaskUpdate`, and chains vulnerabilities. Teammates communicate
via peer-to-peer messaging (`SendMessage`) and write to state.db for durability.
All technique skills (67 discovery + technique skills) are served on-demand via
the **MCP skill-router**.

The legacy orchestrator (`/red-run-legacy`) uses ephemeral subagents — each
handles one skill per invocation and returns. See `agents/` for definitions.

### Subagent Model

The orchestrator spawns domain-specific subagents for each skill invocation:

| Agent | Domain | MCP Servers | Skills |
|-------|--------|-------------|--------|
| `network-recon-agent` | Network | skill-router, nmap-server, shell-server, rdp-server, state | network-recon, smb-enumeration, database-enumeration, remote-access-enumeration, infrastructure-enumeration, smb-exploitation (haiku) |
| `pivoting-agent` | Pivoting | skill-router, shell-server, rdp-server, state | pivoting-tunneling (sonnet) |
| `web-discovery-agent` | Web discovery | skill-router, shell-server, browser-server, rdp-server, state | web-discovery |
| `web-exploit-agent` | Web operations | skill-router, shell-server, browser-server, rdp-server, state | All web technique skills |
| `ad-discovery-agent` | AD discovery | skill-router, shell-server, rdp-server, state | ad-discovery |
| `ad-exploit-agent` | AD operations | skill-router, shell-server, rdp-server, state | All AD technique skills |
| `password-spray-agent` | Credential spraying | skill-router, shell-server, rdp-server, state | password-spraying (haiku) |
| `linux-privesc-agent` | Linux privesc | skill-router, shell-server, state | Linux discovery + privesc + container escapes |
| `windows-privesc-agent` | Windows privesc | skill-router, shell-server, rdp-server, state | Windows discovery + privesc |
| `evasion-agent` | AV/EDR bypass | skill-router, shell-server, rdp-server, state | av-edr-evasion |
| `credential-cracking-agent` | Credential recovery | skill-router, state | credential-cracking (haiku, local-only) |
| `research-agent` | Deep analysis | skill-router, shell-server, state | unknown-vector-analysis (opus) |

Each invocation: agent loads one skill via `get_skill()`, executes methodology, saves evidence, and returns findings. The orchestrator parses the return summary and makes the next routing decision. All agents and the orchestrator share the same state MCP server with full read/write access. Deduplication is handled at the database level.

**Inline fallback**: If subagents aren't installed, the orchestrator **DOES NOT** load skills inline via `get_skill()` in the main thread. STOP and have the operator fix the issue. Skills are only loaded inline when explicitly requested by the operator.

Agent source files live in `agents/` (version controlled), installed to `~/.claude/agents/` by install.sh.

### MCP Servers

| Server | Location | Purpose |
|--------|----------|---------|
| skill-router | `tools/skill-router/` | Semantic skill discovery and loading (ChromaDB + embeddings) |
| nmap-server | `tools/nmap-server/` | Dockerized nmap scanning with input validation |
| shell-server | `tools/shell-server/` | TCP listener, reverse shell, local interactive process manager, privileged Docker execution |
| state | `tools/state-server/` | Full read/write engagement state (all agents + orchestrator) |
| browser-server | `tools/browser-server/` | Headless browser automation (web agents) |
| rdp-server | `tools/rdp-server/` | Headless RDP automation via aardwolf (windows-privesc-agent) |
| sliver-server | `tools/sliver-server/` | Sliver C2 gRPC wrapper — implants, sessions, pivots (optional) |
| state-viewer | `operator/state-viewer/` | Read-only web dashboard for state.db (operator use, not MCP) |

The state server runs as a single instance. In the agent teams orchestrator
(`/red-run-ctf`), all state writes are centralized through the **state-mgr
teammate** — the sole writer to state.db. All shell lifecycle operations
(listeners, processes, upgrades) are centralized through the **shell-mgr
teammate** — teammates message shell-mgr for setup, then interact with the
MCP directly after session handoff. shell-mgr's backend is configurable:
`shell-server` (default), `sliver`, or `custom` (operator-provided C2).
See each server's `README.md` for tool details.

### Skill Types
- **Orchestrator** (`skills/orchestrator/`): Takes a target, runs recon, routes to discovery skills
- **Recon** (`skills/network/network-recon/`): Host discovery, port scanning, OS fingerprinting — produces a port/service map
- **Enumeration** (`skills/network/*-enumeration/`): Per-service deep enumeration (SMB, databases, remote access, infrastructure)
- **Discovery** (`skills/<category>/*-discovery/`): Identifies vulnerabilities, reports findings generically (orchestrator routes to technique skills via `search_skills()`)
- **Technique** (`skills/<category>/<technique>/`): Exercises a specific vulnerability class

### Inter-Skill Routing

The orchestrator makes every routing decision. Skills report findings generically — they do not name specific next skills. The orchestrator uses `search_skills()` to find the right technique skill based on finding descriptions, then derives the correct agent from the skill's category using the **domain→agent map**. Context (injection point, target technology, working payloads) is passed in the Task prompt.

**Mandatory skill loading**: Never execute a technique without loading the matching skill via `get_skill()`. Skills contain methodology, edge cases, payloads, and troubleshooting that general knowledge does not.

**Skill discovery**: Call `search_skills(query)` with a description of the situation to find the right skill. Validate the result before loading — check that the skill's description matches what you need.

**Custom subagents vs built-in sub-agents**: Custom domain subagents (`agents/*.md`) have MCP access and are the correct delegation model. Built-in Task sub-agents (Explore, Plan, general-purpose) do NOT have MCP access — use them only for local processing (hash cracking, output parsing, research), never for target-level work.

### Engagement Logging

Skills support optional engagement logging. No engagement directory = no logging — skills degrade gracefully.

**Directory structure** (created by orchestrator):

```
engagement/
├── config.yaml       # Operator preferences (scan type, proxy, spray, cracking, callback)
├── scope.md          # Target scope, credentials, rules of engagement
├── state.db          # SQLite engagement state (managed via MCP state-server)
├── dump-state.sh     # Export state.db as markdown (from operator/templates/)
├── web-proxy.json    # Machine-readable web proxy config (derived from config.yaml)
├── web-proxy.sh      # Shell env vars for web proxy (sourced by agents)
└── evidence/         # Saved output, responses, dumps (subagents write)
    └── logs/         # Subagent JSONL transcripts (captured by SubagentStop hook)
```

**Orchestrator responsibility:** Creates engagement directory, initializes state.db, manages state via state MCP, parses subagent returns, chains vulns toward impact.

**Subagent responsibility:** Read state via `get_state_summary()`, save evidence to `engagement/evidence/`, report all findings in return summary. All agents write directly to state via the state MCP server. Deduplication is handled at the database level.

### State Management

Engagement state lives in `engagement/state.db` (SQLite, managed by state-server MCP). Tables: targets, ports, credentials, credential_access, access, vulns, pivot_map, blocked, tunnels, state_events.

**Rules:**
- `get_state_summary()` produces a compact markdown summary (~200 lines) for subagent/teammate consumption
- Teammates call `get_state_summary()` on activation; state reads are direct (any teammate, any time)
- **Agent teams (`/red-run-ctf`):** All state writes are centralized through the `state-mgr` teammate. Teammates and the lead send structured `[action]` messages to state-mgr instead of calling write tools directly. state-mgr applies LLM-level dedup, enforces graph coherence, and confirms writes with IDs. DB-level dedup remains as a safety net.
- **Legacy (`/red-run-legacy`):** All agents write directly to state; each write emits a `state_events` row. Deduplication is at the DB level.
- Orchestrator polls `poll_events()` for real-time visibility and uses state summary + pivot map to chain vulns toward impact

## Documentation Rules

Each part of the repo has exactly one documentation file. Keep them in sync
when making changes.

| Component | Documentation | Rule |
|-----------|--------------|------|
| Repo root | `README.md` | Update when architecture, installation, or user-facing behavior changes |
| Docs site | `docs/*.md` | Human-facing reference. Update when features, architecture, or workflows change. `docs/dependencies.md` tracks all external tool dependencies referenced by skills. |
| MCP servers (`tools/*/`) | `README.md` per server | **Required.** Update when tools, parameters, behavior, or prerequisites change |
| Skills (`skills/*/`) | `SKILL.md` | Self-contained — no separate README |
| Agents (`agents/`) | `<agent-name>.md` | Self-contained — no separate README |
| Hooks (`tools/hooks/`) | `README.md` | Update when hook scripts change |
| Operator tools (`operator/*/`) | `README.md` per tool | Update when behavior, usage, or prerequisites change |

**When modifying a tool server:** If you change tools, parameters, behavior, or
dependencies in a `tools/*/` server, update its `README.md` in the same commit.

**Changelog is mandatory.** Every release branch must update `CHANGELOG.md`
before merging. Add entries under the new version heading following
[Keep a Changelog](https://keepachangelog.com/) format.

## Versioning

red-run has no compiled releases — it's installed via `install.sh` which
symlinks (or copies) skills, agents, and MCP servers into `~/.claude/`. Git
tags mark release points.

**Semver:** `MAJOR.MINOR.PATCH`
- **MAJOR** — breaking changes (schema migrations, renamed slash commands,
  removed features, changed teammate/agent APIs that require re-install)
- **MINOR** — new features (new skills, new MCP tools, new teammate templates,
  dashboard features) that are backwards-compatible
- **PATCH** — bug fixes, doc updates, prompt improvements, config changes

**Release branches:** `patch/X.Y.Z-<description>` for patch releases,
`release/X.Y.0-<description>` for minor/major. Tag on merge to main.

## Directory Layout

```
red-run/
  README.md               # User-facing project documentation
  CLAUDE.md               # Development instructions (this file)
  install.sh              # Installs orchestrator, agents, MCP servers
  uninstall.sh            # Removes installed skills, agents, MCP data
  agents/                 # Custom subagent definitions for /red-run-legacy
    network-recon-agent.md
    web-discovery-agent.md
    web-exploit-agent.md
    ad-discovery-agent.md
    ad-exploit-agent.md
    password-spray-agent.md
    linux-privesc-agent.md
    windows-privesc-agent.md
    evasion-agent.md
    credential-cracking-agent.md
    pivoting-agent.md
  teammates/              # Spawn prompt templates for /red-run-ctf (agent teams)
    README.md              # Template format and usage docs
    state-mgr.md           # Centralized state writer, dedup, graph coherence (sonnet)
    shell-mgr.md           # Shell lifecycle manager base template (sonnet)
    shell-mgr-shell-server.md  # Shell-server backend appendix for shell-mgr
    shell-mgr-sliver.md        # Sliver C2 backend appendix for shell-mgr
    net-enum.md            # Network recon + service enumeration (sonnet)
    web-enum.md            # Web app discovery (sonnet)
    web-ops.md             # Web technique execution (sonnet)
    ad-enum.md             # AD discovery (sonnet)
    ad-ops.md              # AD technique execution (sonnet)
    lin-enum.md            # Linux host discovery (sonnet)
    lin-ops.md             # Linux privesc techniques (sonnet)
    win-enum.md            # Windows host discovery (sonnet)
    win-ops.md             # Windows privesc techniques (sonnet)
    pivot.md               # Tunneling (sonnet, on-demand)
    bypass.md              # AV/EDR bypass (sonnet, on-demand)
    spray.md               # Password spraying (haiku, on-demand)
    recover.md             # Offline hash recovery (haiku, on-demand)
    research.md            # Deep analysis (opus, on-demand)
  skills/
    _template/SKILL.md    # Canonical template
    ctf/SKILL.md          # /red-run-ctf (agent teams, default)
    legacy/SKILL.md       # /red-run-legacy (subagent-based, manual invoke only)
    web/                  # Web application techniques
    ad/                   # Active Directory
    credential/           # Credential techniques (password spraying)
    privesc/              # Privilege escalation
    network/              # Recon, protocols, pivoting
    evasion/              # AV/EDR bypass
  tools/
    skill-router/         # MCP server (ChromaDB + embeddings)
      README.md            # Server documentation
      server.py           # FastMCP server — search_skills, get_skill, list_skills
      indexer.py           # Indexes SKILL.md frontmatter into ChromaDB
      pyproject.toml       # Python dependencies (chromadb, sentence-transformers)
    nmap-server/          # MCP server (Dockerized nmap)
      README.md            # Server documentation
      server.py           # FastMCP server — nmap_scan, get_scan, list_scans
      validate.py          # Input validation (flag blocklist, target sanitization)
      Dockerfile           # Alpine + nmap image (built by install.sh)
      pyproject.toml       # Python dependencies (mcp, python-libnmap)
    shell-server/         # MCP server (TCP listener + shell manager)
      README.md            # Server documentation
      server.py           # FastMCP server — start_listener, send_command, stabilize_shell, etc.
      Dockerfile           # Python + Responder + impacket + mitm6 image (built by install.sh)
      pyproject.toml       # Python dependencies (mcp)
    sliver-server/        # MCP server (Sliver C2 gRPC wrapper, optional)
      README.md            # Server documentation
      server.py           # FastMCP server — implants, sessions, pivots
      start.sh            # Idempotent SSE startup
      pyproject.toml       # Python dependencies (mcp, sliver-py, grpcio)
    browser-server/       # MCP server (headless Chromium)
      README.md            # Server documentation
      server.py           # FastMCP server — browser_open, browser_fill, browser_click, etc.
      pyproject.toml       # Python dependencies (mcp, playwright, markdownify)
    state-server/         # MCP server (SQLite engagement state)
      README.md            # Server documentation
      server.py           # FastMCP server — full read/write engagement state
      schema.py           # SQLite schema creation and migration
      pyproject.toml       # Python dependencies (mcp)
    hooks/                # Claude Code hooks
      save-agent-log.sh   # SubagentStop hook — copies JSONL transcripts to engagement/evidence/logs/
      event-watcher.sh    # Background event poller — spawned by orchestrator to watch state_events
  operator/               # Operator-facing tools (run manually, not MCP)
    config.sh             # Pre-engagement config wizard (scan, proxy, spray, cracking, C2)
    state-viewer/      # Read-only web dashboard for state.db
      README.md            # Tool documentation
      server.py           # Stdlib HTTP server — inline HTML dashboard, SSE live updates
      start.sh            # Wrapper script
      generate-token.sh   # Auth token generator for remote access
```

## Skill File Format

Every skill lives at `skills/<category>/<skill-name>/SKILL.md`.

### Frontmatter (required)

```yaml
---
name: skill-name
description: >
  What it does. When to trigger (be pushy — Claude undertriggers by default).
  Explicit trigger phrases. Negative conditions (when NOT to use).
keywords:
  - technique-specific search terms
  - tool names, CVE IDs, protocol names
tools:
  - tool1
  - tool2
opsec: low|medium|high
---
```

The MCP indexer builds embedding documents from these structured fields. `description` provides semantic context, `keywords` provide exact search terms, `tools` enable tool-name lookups, and `opsec` is included in search results.

### Body structure

1. **Preamble**: "You are helping a penetration tester with..."
2. **Engagement Logging**: Check for engagement dir, log evidence to `engagement/evidence/`
3. **State Management**: Read via `get_state_summary()` on activation, report findings in return summary (orchestrator writes state)
4. **Exploit and Tool Transfer**: Attackbox-first workflow for external tools/exploits
5. **Web Interaction**: Browser tools vs curl guidance (web skills)
6. **Prerequisites**: Access, tools, conditions
7. **Steps**: Assess → Confirm → Exploit → Escalate/Pivot
8. **Troubleshooting**: Common failures and fixes

### Conventions
- Skill names use kebab-case: `sql-injection-union`, `kerberoasting`, `docker-socket-escape`
- One technique per skill — split broad topics into focused skills
- Embed critical payloads directly (top 2-3 per DB/variant for 80% coverage)
- OPSEC rating in description: `low` = passive/read-only, `medium` = creates artifacts, `high` = noisy/detected by EDR
- **New technique skill checklist**: When creating a new technique skill, ensure it has descriptive frontmatter (name, description, keywords) so `search_skills()` can discover it. No routing table updates needed — the orchestrator finds skills via semantic search.
- **AD OPSEC: Kerberos-first authentication**: All AD skills default to Kerberos authentication via ccache to avoid NTLM-specific detections (Event 4776, CrowdStrike Identity Module PTH signatures). Each AD skill's Prerequisites section includes the `getTGT.py` → `KRB5CCNAME` → `-k -no-pass` workflow. All embedded tool commands use Kerberos auth flags: Impacket (`-k -no-pass`), NetExec (`--use-kcache`), Certipy (`-k`), bloodyAD (`-k`). Skills where Kerberos auth doesn't apply (relay, coercion, password spraying) explicitly state why and note the NTLM detection surface.
- **Attackbox-first transfer**: Never download exploits, scripts, or tools directly to the target from the internet. Targets may lack outbound access, and operators must review files before execution on target. Workflow: (1) download/clone on attackbox, (2) review, (3) serve via `python3 -m http.server` or transfer with `scp`/`nc`/base64, (4) pull from target. Inline source code in heredocs is fine — the operator can read it in the skill.

## Permission Mode

Agent teams works in standard permission mode. Teammate permission requests
surface to the operator for approval. The orchestrator's approval gates
(operator confirms every routing decision before task assignment) provide
human-in-the-loop control. MCP server tools are pre-allowed in
`.claude/settings.json` to reduce prompt noise for state/skill-router/
shell-server/nmap/browser/rdp operations.

## Installation

```bash
# Install (symlinks — edits in repo reflect immediately)
./install.sh

# Install (copies — for machines without the repo)
./install.sh --copy

# Uninstall
./uninstall.sh
```

The installer puts orchestrators in `~/.claude/skills/red-run-ctf/` and `~/.claude/skills/red-run-legacy/`, subagents in `~/.claude/agents/`, and sets up MCP servers (skill-router, nmap-server, shell-server, browser-server, state-server). Requires [uv](https://docs.astral.sh/uv/), Docker for nmap, and Playwright for browser automation (Chromium installed automatically).

