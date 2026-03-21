# red-run

Claude Code skill library for penetration testing and CTF work.

## Engagement Workflow

**MANDATORY:** When the user mentions targets, attacking, scanning, pentesting,
or references an existing engagement (resuming, continuing, next steps, status),
invoke the `red-run-orchestrator` skill via the Skill tool IMMEDIATELY — before
reading state, running tools, or generating any analysis. The orchestrator skill
contains all routing logic, approval gates, and state management rules. Never
manually call state-server MCP tools, run attack commands, or present engagement
analysis from the main thread without the orchestrator skill loaded.

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
| `/red-run-orchestrator` | Keywords ("attack X") + slash command | **Active** (default) | Subagents (ephemeral, one skill per invocation) |
| `/red-run-ctf` | Slash command only | **Experimental** | Agent teams (persistent teammates, peer messaging) |

**`/red-run-ctf`** requires Claude Code agent teams (experimental). Enable with
`CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS=1` in env or settings.json. It uses
teammate spawn templates from `teammates/` instead of agent definitions from
`agents/`. See `teammates/README.md` for the template format.

Both orchestrators use the same state.db schema, MCP servers, and technique
skills. An engagement started with one can be resumed with the other.

## Architecture

The default **orchestrator** (`/red-run-orchestrator`) is a native Claude Code skill that runs in the main conversation thread. It routes skill execution to **custom domain subagents** — each subagent has MCP access and executes one skill per invocation. All other skills (63 discovery + technique skills) are served on-demand via the **MCP skill-router**.

### Subagent Model

The orchestrator spawns domain-specific subagents for each skill invocation:

| Agent | Domain | MCP Servers | Skills |
|-------|--------|-------------|--------|
| `network-recon-agent` | Network | skill-router, nmap-server, shell-server, rdp-server, state-interim | network-recon, smb-enumeration, database-enumeration, remote-access-enumeration, infrastructure-enumeration, smb-exploitation (haiku) |
| `pivoting-agent` | Pivoting | skill-router, shell-server, rdp-server, state-interim | pivoting-tunneling (sonnet) |
| `web-discovery-agent` | Web discovery | skill-router, shell-server, browser-server, rdp-server, state-interim | web-discovery |
| `web-exploit-agent` | Web exploitation | skill-router, shell-server, browser-server, rdp-server, state-interim | All web technique skills |
| `ad-discovery-agent` | AD discovery | skill-router, shell-server, rdp-server, state-interim | ad-discovery |
| `ad-exploit-agent` | AD exploitation | skill-router, shell-server, rdp-server, state-interim | All AD technique skills |
| `password-spray-agent` | Credential spraying | skill-router, shell-server, rdp-server, state-interim | password-spraying (haiku) |
| `linux-privesc-agent` | Linux privesc | skill-router, shell-server, state-interim | Linux discovery + privesc + container escapes |
| `windows-privesc-agent` | Windows privesc | skill-router, shell-server, rdp-server, state-interim | Windows discovery + privesc |
| `evasion-agent` | AV/EDR evasion | skill-router, shell-server, rdp-server, state-interim | av-edr-evasion |
| `credential-cracking-agent` | Credential cracking | skill-router, state-interim | credential-cracking (haiku, local-only) |
| `research-agent` | Deep analysis | skill-router, shell-server, state-interim | unknown-vector-analysis (opus) |

Each invocation: agent loads one skill via `get_skill()`, executes methodology, saves evidence, and returns findings. The orchestrator parses the return summary, records state changes via the state-writer MCP, and makes the next routing decision. All agents use state-interim for mid-run writes of critical discoveries (credentials, vulns, pivots, blocked). The orchestrator deduplicates interim writes against return summaries.

**Inline fallback**: If subagents aren't installed, the orchestrator **DOES NOT** load skills inline via `get_skill()` in the main thread. STOP and have the operator fix the issue. Skills are only loaded inline when explicitly requested by the operator.

Agent source files live in `agents/` (version controlled), installed to `~/.claude/agents/` by install.sh.

### MCP Servers

| Server | Location | Purpose |
|--------|----------|---------|
| skill-router | `tools/skill-router/` | Semantic skill discovery and loading (ChromaDB + embeddings) |
| nmap-server | `tools/nmap-server/` | Dockerized nmap scanning with input validation |
| shell-server | `tools/shell-server/` | TCP listener, reverse shell, local interactive process manager, privileged Docker execution |
| state-reader | `tools/state-server/` | Read-only engagement state queries (retained for fallback) |
| state-interim | `tools/state-server/` | Read + 5 add-only writes (all agents) |
| state-writer | `tools/state-server/` | Full engagement state management (orchestrator only) |
| browser-server | `tools/browser-server/` | Headless browser automation (web agents) |
| rdp-server | `tools/rdp-server/` | Headless RDP automation via aardwolf (windows-privesc-agent) |
| state-dashboard | `operator/state-dashboard/` | Read-only web dashboard for state.db (operator use, not MCP) |

The state-reader, state-interim, and state-writer are three instances of the same server running in different modes. All agents use state-interim to write critical discoveries (credentials, vulns, pivots, blocked) mid-run. The orchestrator uses state-writer for full read/write access. See each server's `README.md` for tool details.

### Skill Types
- **Orchestrator** (`skills/orchestrator/`): Takes a target, runs recon, routes to discovery skills
- **Recon** (`skills/network/network-recon/`): Host discovery, port scanning, OS fingerprinting — produces a port/service map
- **Enumeration** (`skills/network/*-enumeration/`): Per-service deep enumeration (SMB, databases, remote access, infrastructure)
- **Discovery** (`skills/<category>/*-discovery/`): Identifies vulnerabilities, reports findings generically (orchestrator routes to technique skills via `search_skills()`)
- **Technique** (`skills/<category>/<technique>/`): Exploits a specific vulnerability class

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

**Orchestrator responsibility:** Creates engagement directory, initializes state.db, manages state via state-writer MCP, parses subagent returns, chains vulns toward impact.

**Subagent responsibility:** Read state via `get_state_summary()`, save evidence to `engagement/evidence/`, report all findings in return summary. All agents write critical discoveries mid-run via state-interim (credentials, vulns, pivots, blocked). The orchestrator deduplicates interim writes against return summaries.

### State Management

Engagement state lives in `engagement/state.db` (SQLite, managed by state-server MCP). Tables: targets, ports, credentials, credential_access, access, vulns, pivot_map, blocked, tunnels, state_events.

**Rules:**
- `get_state_summary()` produces a compact markdown summary (~200 lines) for subagent consumption
- Subagents call `get_state_summary()` on activation, report findings in their return summary
- All agents write critical discoveries mid-run via state-interim; each write emits a `state_events` row
- Orchestrator polls `poll_events()` for real-time visibility, parses returns, deduplicates interim writes
- Orchestrator uses state summary + pivot map to chain vulns toward impact

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

## Directory Layout

```
red-run/
  README.md               # User-facing project documentation
  CLAUDE.md               # Development instructions (this file)
  install.sh              # Installs orchestrator, agents, MCP servers
  uninstall.sh            # Removes installed skills, agents, MCP data
  agents/                 # Custom subagent definitions for /red-run-orchestrator
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
    recon.md               # Network recon + enumeration (haiku)
    web.md                 # Web discovery + exploitation (sonnet)
    ad.md                  # AD discovery + exploitation (sonnet)
    linux.md               # Linux discovery + privesc (sonnet)
    windows.md             # Windows discovery + privesc (sonnet)
    pivoting.md            # Tunneling (sonnet, on-demand)
    evasion.md             # AV/EDR bypass (sonnet, on-demand)
    spray.md               # Password spraying (haiku, on-demand)
    cracking.md            # Offline hash cracking (haiku, on-demand)
    research.md            # Deep analysis (opus, on-demand)
  skills/
    _template/SKILL.md    # Canonical template
    orchestrator/SKILL.md # /red-run-orchestrator (subagent-based, default)
    ctf/SKILL.md          # /red-run-ctf (agent teams, experimental)
    web/                  # Web application attacks
    ad/                   # Active Directory
    credential/           # Credential attacks (password spraying)
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
    browser-server/       # MCP server (headless Chromium)
      README.md            # Server documentation
      server.py           # FastMCP server — browser_open, browser_fill, browser_click, etc.
      pyproject.toml       # Python dependencies (mcp, playwright, markdownify)
    state-server/         # MCP server (SQLite engagement state)
      README.md            # Server documentation
      server.py           # FastMCP server — runs as state-reader (read) or state-writer (read+write)
      schema.py           # SQLite schema creation and migration
      pyproject.toml       # Python dependencies (mcp)
    hooks/                # Claude Code hooks
      save-agent-log.sh   # SubagentStop hook — copies JSONL transcripts to engagement/evidence/logs/
      event-watcher.sh    # Background event poller — spawned by orchestrator to watch state_events
  operator/               # Operator-facing tools (run manually, not MCP)
    agent-dashboard/      # Live multi-pane agent monitoring
      README.md            # Tool documentation
      tail-agent.py       # JSONL transcript parser + curses dashboard
      dashboard.sh        # Wrapper script
    state-dashboard/      # Read-only web dashboard for state.db
      README.md            # Tool documentation
      server.py           # Stdlib HTTP server — inline HTML dashboard, SSE live updates
      start.sh            # Wrapper script
      generate-token.sh   # Auth token generator for remote access
    firewall/             # Engagement network firewall (nftables)
      README.md            # Tool documentation
      firewall.sh         # Activate firewall with scope targets
      teardown.sh         # Remove firewall rules
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

All skills delegate to autonomous agents with `mode: "bypassPermissions"`. Run
`claude --dangerously-skip-permissions` for full autonomous operation. The
orchestrator's approval gates (operator confirms every routing decision before
agent spawn) provide human-in-the-loop control.

## Engagement Firewall (Optional)

An nftables firewall is available in `operator/engagement-firewall/` for
operators who want OS-level network isolation restricting outbound traffic to
Anthropic API + scope targets. See `operator/engagement-firewall/README.md`.

## Installation

```bash
# Install (symlinks — edits in repo reflect immediately)
./install.sh

# Install (copies — for machines without the repo)
./install.sh --copy

# Uninstall
./uninstall.sh
```

The installer puts the orchestrator in `~/.claude/skills/red-run-orchestrator/`, subagents in `~/.claude/agents/`, and sets up MCP servers (skill-router, nmap-server, shell-server, browser-server, state-server). Requires [uv](https://docs.astral.sh/uv/), Docker for nmap, and Playwright for browser automation (Chromium installed automatically).

