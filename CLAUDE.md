# red-run

Claude Code skill library for penetration testing and CTF work.

## Architecture

The **orchestrator** is a native Claude Code skill that runs in the main conversation thread. It routes skill execution to **custom domain subagents** — each subagent has MCP access and executes one skill per invocation. All other skills (63 discovery + technique skills) are served on-demand via the **MCP skill-router**.

### Subagent Model

The orchestrator spawns domain-specific subagents for each skill invocation:

| Agent | Domain | MCP Servers | Skills |
|-------|--------|-------------|--------|
| `network-recon-agent` | Network | skill-router, nmap-server, shell-server, state-reader | network-recon, smb-exploitation, pivoting-tunneling |
| `web-discovery-agent` | Web discovery | skill-router, shell-server, state-reader | web-discovery |
| `web-exploit-agent` | Web exploitation | skill-router, shell-server, state-reader | All web technique skills |
| `ad-discovery-agent` | AD discovery | skill-router, shell-server, state-reader | ad-discovery |
| `ad-exploit-agent` | AD exploitation | skill-router, shell-server, state-reader | All AD technique skills |
| `linux-privesc-agent` | Linux privesc | skill-router, shell-server, state-reader | Linux discovery + privesc + container escapes |
| `windows-privesc-agent` | Windows privesc | skill-router, shell-server, state-reader | Windows discovery + privesc |

Each invocation: agent loads one skill via `get_skill()`, executes methodology, saves evidence, and returns findings. The orchestrator parses the return summary, records state changes via the state-writer MCP, and makes the next routing decision. Subagents are read-only for state — they never write engagement state directly.

**Inline fallback**: If subagents aren't installed, the orchestrator loads skills inline via `get_skill()` in the main thread.

Agent source files live in `agents/` (version controlled), installed to `~/.claude/agents/` by install.sh.

### MCP Servers

| Server | Location | Tools | Purpose |
|--------|----------|-------|---------|
| skill-router | `tools/skill-router/` | `search_skills`, `get_skill`, `list_skills` | Semantic skill discovery and loading |
| nmap-server | `tools/nmap-server/` | `nmap_scan`, `get_scan`, `list_scans` | Dockerized nmap scanning with input validation |
| shell-server | `tools/shell-server/` | `start_listener`, `start_process`, `send_command`, `read_output`, `stabilize_shell`, `list_sessions`, `close_session` | TCP listener, reverse shell, and local interactive process manager |
| state-reader | `tools/state-server/` | `get_state_summary`, `get_targets`, `get_credentials`, `get_access`, `get_vulns`, `get_pivot_map`, `get_blocked` | Read-only engagement state queries (subagents) |
| state-writer | `tools/state-server/` | All read tools + `init_engagement`, `close_engagement`, `add_target`, `add_port`, `add_credential`, `add_access`, `add_vuln`, `add_pivot`, `add_blocked`, and update variants | Full engagement state management (orchestrator only) |

The state-reader and state-writer are two instances of the same server (`tools/state-server/server.py`) running in different modes (`--mode read` vs `--mode write`). Both open the same `engagement/state.db`. SQLite WAL mode handles concurrent readers safely. Since only the orchestrator writes (via state-writer), write conflicts are impossible. Subagents physically cannot see write tools because their MCP instance doesn't register them.

The skill-router is backed by ChromaDB + sentence-transformer embeddings (`all-MiniLM-L6-v2`). Skills are indexed from structured frontmatter fields (description, keywords, tools, opsec).

The nmap-server runs nmap inside a Docker container (`--network=host`, minimal capabilities) and returns parsed JSON. All inputs are validated before reaching subprocess. Requires Docker.

The shell-server manages TCP listeners, reverse shell sessions, and local interactive processes. It solves the persistent shell problem — Claude Code's Bash tool runs each command as a separate process, so interactive shells, privilege escalation tools, and credential-based access tools (evil-winrm, psexec.py, ssh, msfconsole) have no way to maintain state between calls.

### Modes
- **Guided** (default): Interactive. Every command that touches the target
  requires explicit user approval before execution. Present what you want to
  run and why, then wait. Local-only operations (file writes, parsing, hash
  cracking) don't need approval. Present options at decision forks.
- **Autonomous**: No guardrails. Execute recon through exploitation, make
  triage decisions, route to skills automatically. Report at milestones. Only
  pause for destructive or high-OPSEC actions.

Mode is set by the user or the orchestrator and propagated via conversation context.

> **On autonomous mode:** Autonomous mode pairs with `claude --dangerously-skip-permissions` (a.k.a. yolo mode). We do not recommend this. We do not endorse this. We are not responsible for what happens. You will watch Claude chain four skills, pop a shell, and pivot to a subnet you forgot was in scope. It is exhilarating and horrifying in equal measure. Use guided mode or avoid `--dangerously-skip-permissions` for the sake of us all.

### Skill Types
- **Orchestrator** (`skills/orchestrator/`): Takes a target, runs recon, routes to discovery skills
- **Discovery** (`skills/<category>/*-discovery/`): Identifies vulnerabilities, routes to technique skills via decision tree
- **Technique** (`skills/<category>/<technique>/`): Exploits a specific vulnerability class

### Inter-Skill Routing

The orchestrator makes every routing decision. When a skill says "Route to **skill-name**", the orchestrator looks up the correct domain agent in the Skill-to-Agent Routing Table and spawns it with that skill. Context (injection point, target technology, mode, working payloads) is passed in the Task prompt.

**Mandatory skill loading**: When a skill says "Route to **skill-name**", that skill MUST be loaded via `get_skill()` — either by a subagent or inline. Never execute a technique without loading the matching skill. Skills contain methodology, edge cases, payloads, and troubleshooting that general knowledge does not. This applies in both guided and autonomous modes.

**Skill discovery**: If unsure which skill to use, call `search_skills(query)` with a description of the situation. Validate the result before loading — check that the skill's description matches what you need.

**Custom subagents vs built-in sub-agents**: Custom domain subagents (`agents/*.md`) have MCP access and are the correct delegation model. Built-in Task sub-agents (Explore, Plan, general-purpose) do NOT have MCP access — use them only for local processing (hash cracking, output parsing, research), never for target-level work.

### Engagement Logging

Skills support optional engagement logging for structured pentests.

**Directory structure** (created by orchestrator or first skill that needs it):

```
engagement/
├── scope.md          # Target scope, credentials, rules of engagement
├── state.db          # SQLite engagement state (managed via MCP state-server)
├── activity.md       # Chronological action log (append-only, orchestrator writes)
├── findings.md       # Confirmed vulnerabilities (orchestrator writes)
└── evidence/         # Saved output, responses, dumps (subagents write)
    └── logs/         # Subagent JSONL transcripts (captured by SubagentStop hook)
```

**Behavior:**
- Skills check for `./engagement/` at start. Guided mode asks to create it if absent; autonomous mode creates it automatically.
- Activity entries logged at milestones, not every command. Format: `### [HH:MM] skill-name → target` with bullet points.
- Findings numbered sequentially. Light summaries — use `pentest-findings` skill for formal report-quality writeups.
- Evidence saved with descriptive filenames to `engagement/evidence/`.
- No engagement directory = no logging. Skills degrade gracefully.

**Subagent transcript capture:**
- A `SubagentStop` hook (`tools/hooks/save-agent-log.sh`) copies raw JSONL
  transcripts from domain subagents into `engagement/evidence/logs/`.
- Filename format: `{ISO-timestamp}-{agent-type}.jsonl` (e.g.,
  `20260227T143052Z-web-exploit-agent.jsonl`).
- Only triggers for red-run domain agents (network-recon, web-discovery,
  web-exploit, ad-discovery, ad-exploit, linux-privesc, windows-privesc) —
  not built-in subagents (Explore, Plan, general-purpose).
- No engagement directory = hook exits silently. No logging, no errors.
- The retrospective skill parses these logs for post-engagement analysis.

**Orchestrator responsibility:**
- Creates engagement directory, initializes `scope.md`, and calls `init_engagement()` to create `state.db`
- Is the **sole writer** of all engagement state (SQLite), `activity.md`, and `findings.md`
- Parses subagent return summaries and records findings via state-writer MCP tools
- Calls `get_state_summary()` to decide next actions and which skill to invoke
- Analyzes state to chain vulnerabilities toward maximum impact
- Produces engagement summary when complete

**Subagent responsibility:**
- Call `get_state_summary()` from the state-reader MCP to read current state
- Save raw evidence to `engagement/evidence/` (the only directory subagents write to)
- Report all findings clearly in their return summary — the orchestrator records state changes

### State Management

Engagement state lives in `engagement/state.db`, a SQLite database managed by the state-server MCP. The **orchestrator is the sole writer** — subagents are read-only.

**Tables:**

| Table | Contents | Key Queries |
|-------|----------|-------------|
| **targets** + **ports** | Hosts, IPs, OS, ports, services (normalized 1:many) | `get_targets()`, "all targets with port 445" |
| **credentials** + **credential_access** | Username/secret pairs + where each has been tested | `get_credentials(untested_only=True)` |
| **access** | Current footholds: shells, sessions, tokens, DB access | `get_access(active_only=True)` |
| **vulns** | Confirmed vulns with status: `found`, `active`, `done` | `get_vulns(status="found")` |
| **pivot_map** | What leads where — vuln X gives access Y, creds Z work on host W | `get_pivot_map()` |
| **blocked** | What was tried and why it failed — prevents re-testing | `get_blocked()` |

**Rules:**
- `get_state_summary()` produces a compact markdown summary (~200 lines) for subagent consumption
- Subagents call `get_state_summary()` on activation, report findings in their return summary
- The orchestrator parses return summaries and calls structured write tools (`add_target`, `add_credential`, `add_vuln`, etc.)
- Orchestrator uses state summary + pivot map to chain vulns toward impact

## Directory Layout

```
red-run/
  install.sh              # Installs orchestrator, agents, MCP servers
  uninstall.sh            # Removes installed skills, agents, MCP data
  agents/                 # Custom subagent definitions (installed to ~/.claude/agents/)
    network-recon-agent.md
    web-discovery-agent.md
    web-exploit-agent.md
    ad-discovery-agent.md
    ad-exploit-agent.md
    linux-privesc-agent.md
    windows-privesc-agent.md
  skills/
    _template/SKILL.md    # Canonical template
    orchestrator/SKILL.md # Master orchestrator (native skill)
    web/                  # Web application attacks
    ad/                   # Active Directory
    privesc/              # Privilege escalation
    network/              # Recon, protocols, pivoting
  tools/
    skill-router/         # MCP server (ChromaDB + embeddings)
      server.py           # FastMCP server — search_skills, get_skill, list_skills
      indexer.py           # Indexes SKILL.md frontmatter into ChromaDB
      pyproject.toml       # Python dependencies (chromadb, sentence-transformers)
    nmap-server/          # MCP server (Dockerized nmap)
      server.py           # FastMCP server — nmap_scan, get_scan, list_scans
      validate.py          # Input validation (flag blocklist, target sanitization)
      Dockerfile           # Alpine + nmap image (built by install.sh)
      pyproject.toml       # Python dependencies (mcp, python-libnmap)
    shell-server/         # MCP server (TCP listener + shell manager)
      server.py           # FastMCP server — start_listener, send_command, stabilize_shell, etc.
      pyproject.toml       # Python dependencies (mcp)
    state-server/         # MCP server (SQLite engagement state)
      server.py           # FastMCP server — runs as state-reader (read) or state-writer (read+write)
      schema.py           # SQLite schema creation and migration
      pyproject.toml       # Python dependencies (mcp)
    hooks/                # Claude Code hooks
      save-agent-log.sh   # SubagentStop hook — copies JSONL transcripts to engagement/evidence/logs/
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
2. **Mode**: Check for guided vs autonomous
3. **Engagement Logging**: Check for engagement dir, log evidence to `engagement/evidence/`
4. **State Management**: Read via `get_state_summary()` on activation, report findings in return summary (orchestrator writes state)
5. **Exploit and Tool Transfer**: Attackbox-first workflow for external tools/exploits
6. **Prerequisites**: Access, tools, conditions
7. **Steps**: Assess → Confirm → Exploit → Escalate/Pivot
8. **Troubleshooting**: Common failures and fixes

### Conventions
- Skill names use kebab-case: `sql-injection-union`, `kerberoasting`, `docker-socket-escape`
- One technique per skill — split broad topics into focused skills
- Embed critical payloads directly (top 2-3 per DB/variant for 80% coverage)
- OPSEC rating in description: `low` = passive/read-only, `medium` = creates artifacts, `high` = noisy/detected by EDR
- Inter-skill routing: bold skill names in escalation sections
- **Discovery skill maintenance**: When creating a new technique skill, update the corresponding discovery skill's routing table to include it. `web-discovery` must route to every web technique skill.
- **AD OPSEC: Kerberos-first authentication**: All AD skills default to Kerberos authentication via ccache to avoid NTLM-specific detections (Event 4776, CrowdStrike Identity Module PTH signatures). Each AD skill's Prerequisites section includes the `getTGT.py` → `KRB5CCNAME` → `-k -no-pass` workflow. All embedded tool commands use Kerberos auth flags: Impacket (`-k -no-pass`), NetExec (`--use-kcache`), Certipy (`-k`), bloodyAD (`-k`). Skills where Kerberos auth doesn't apply (relay, coercion, password spraying) explicitly state why and note the NTLM detection surface.
- **Attackbox-first transfer**: Never download exploits, scripts, or tools directly to the target from the internet. Targets may lack outbound access, and operators must review files before execution on target. Workflow: (1) download/clone on attackbox, (2) review, (3) serve via `python3 -m http.server` or transfer with `scp`/`nc`/base64, (4) pull from target. Inline source code in heredocs is fine — the operator can read it in the skill.

## Sandbox

The bwrap sandbox blocks network socket creation. Users must configure their global `~/.claude/CLAUDE.md` to disable sandbox for network tools — see README.md "Sandbox and network commands" for the setup.

## Installation

```bash
# Install (symlinks — edits in repo reflect immediately)
./install.sh

# Install (copies — for machines without the repo)
./install.sh --copy

# Uninstall
./uninstall.sh
```

The installer puts the orchestrator in `~/.claude/skills/red-run-orchestrator/`, subagents in `~/.claude/agents/`, and sets up MCP servers (skill-router, nmap-server, shell-server, state-server). Requires [uv](https://docs.astral.sh/uv/) and Docker for nmap.

