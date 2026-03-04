# red-run

Claude Code skill library for penetration testing and CTF work.

## Architecture

The **orchestrator** is a native Claude Code skill that runs in the main conversation thread. It routes skill execution to **custom domain subagents** — each subagent has MCP access and executes one skill per invocation. All other skills (63 discovery + technique skills) are served on-demand via the **MCP skill-router**.

### Subagent Model

The orchestrator spawns domain-specific subagents for each skill invocation:

| Agent | Domain | MCP Servers | Skills |
|-------|--------|-------------|--------|
| `network-recon-agent` | Network | skill-router, nmap-server, shell-server, state-interim | network-recon, smb-exploitation, pivoting-tunneling (haiku) |
| `web-discovery-agent` | Web discovery | skill-router, shell-server, browser-server, state-interim | web-discovery |
| `web-exploit-agent` | Web exploitation | skill-router, shell-server, browser-server, state-reader | All web technique skills |
| `ad-discovery-agent` | AD discovery | skill-router, shell-server, state-interim | ad-discovery |
| `ad-exploit-agent` | AD exploitation | skill-router, shell-server, state-reader | All AD technique skills |
| `password-spray-agent` | Credential spraying | skill-router, shell-server, state-reader | password-spraying (haiku) |
| `linux-privesc-agent` | Linux privesc | skill-router, shell-server, state-interim | Linux discovery + privesc + container escapes |
| `windows-privesc-agent` | Windows privesc | skill-router, shell-server, state-interim | Windows discovery + privesc |
| `evasion-agent` | AV/EDR evasion | skill-router, shell-server, state-reader | av-edr-evasion |
| `credential-cracking-agent` | Credential cracking | skill-router, state-reader | credential-cracking (haiku, local-only) |

Each invocation: agent loads one skill via `get_skill()`, executes methodology, saves evidence, and returns findings. The orchestrator parses the return summary, records state changes via the state-writer MCP, and makes the next routing decision. Subagents are read-only for state — they never write engagement state directly.

**Inline fallback**: If subagents aren't installed, the orchestrator loads skills inline via `get_skill()` in the main thread.

Agent source files live in `agents/` (version controlled), installed to `~/.claude/agents/` by install.sh.

### MCP Servers

| Server | Location | Tools | Purpose |
|--------|----------|-------|---------|
| skill-router | `tools/skill-router/` | `search_skills`, `get_skill`, `list_skills` | Semantic skill discovery and loading |
| nmap-server | `tools/nmap-server/` | `nmap_scan`, `get_scan`, `list_scans` | Dockerized nmap scanning with input validation |
| shell-server | `tools/shell-server/` | `start_listener`, `start_process` (supports `privileged` Docker mode), `send_command`, `read_output`, `stabilize_shell`, `list_sessions`, `close_session` | TCP listener, reverse shell, local interactive process manager, and privileged Docker execution |
| state-reader | `tools/state-server/` | `get_state_summary`, `get_targets`, `get_credentials`, `get_access`, `get_vulns`, `get_pivot_map`, `get_blocked`, `poll_events` | Read-only engagement state queries (technique agents) |
| state-interim | `tools/state-server/` | All read tools + `add_credential`, `add_vuln`, `add_pivot`, `add_blocked` (each emits a `state_events` row) | Read + 4 add-only writes (discovery agents) |
| state-writer | `tools/state-server/` | All read tools + `init_engagement`, `close_engagement`, `add_target`, `add_port`, `add_credential`, `add_access`, `add_vuln`, `add_pivot`, `add_blocked`, and update variants | Full engagement state management (orchestrator only) |
| browser-server | `tools/browser-server/` | `browser_open`, `browser_navigate`, `browser_get_page`, `browser_click`, `browser_fill`, `browser_select`, `browser_screenshot`, `browser_cookies`, `browser_evaluate`, `close_browser`, `list_browser_sessions` | Headless browser automation (web agents) |

The state-reader, state-interim, and state-writer are three instances of the same server (`tools/state-server/server.py`) running in different modes (`--mode read`, `--mode interim`, `--mode write`). All three open the same `engagement/state.db`. SQLite WAL mode + `busy_timeout=5000` handles concurrent readers and writers safely. Discovery agents use state-interim to write actionable findings (credentials, vulns, pivots, blocked) mid-run without waiting for the orchestrator to parse their return summary. Technique agents use state-reader (fully read-only). The orchestrator uses state-writer for full read/write access and deduplicates findings that discovery agents already wrote via interim.

The skill-router is backed by ChromaDB + sentence-transformer embeddings (`all-MiniLM-L6-v2`). Skills are indexed from structured frontmatter fields (description, keywords, tools, opsec).

The nmap-server runs nmap inside a Docker container (`--network=host`, minimal capabilities) and returns parsed JSON. All inputs are validated before reaching subprocess. Requires Docker.

The shell-server manages TCP listeners, reverse shell sessions, and local interactive processes. It solves the persistent shell problem — Claude Code's Bash tool runs each command as a separate process, so interactive shells, privilege escalation tools, and credential-based access tools (evil-winrm, psexec.py, ssh, msfconsole) have no way to maintain state between calls. The `privileged` parameter on `start_process` runs commands inside the `red-run-shell` Docker container, which contains a full pentest toolkit: evil-winrm, impacket, chisel, ligolo-ng, socat, Responder, mitm6, and tcpdump. Use `privileged=True` for Docker-only tools (evil-winrm, chisel, ligolo-ng) and for daemons needing raw sockets (Responder, mitm6). Requires the `red-run-shell` Docker image (built by install.sh).

The browser-server provides headless Chromium automation via Playwright. It solves the web interaction problem — curl can't handle CSRF tokens, session rotation, JavaScript-rendered forms, or multi-step authentication flows. Each session maintains its own cookie jar and localStorage. Web agents use browser tools as the default for navigating sites and curl as fallback for precise payload control.

### Skill Types
- **Orchestrator** (`skills/orchestrator/`): Takes a target, runs recon, routes to discovery skills
- **Discovery** (`skills/<category>/*-discovery/`): Identifies vulnerabilities, routes to technique skills via decision tree
- **Technique** (`skills/<category>/<technique>/`): Exploits a specific vulnerability class

### Inter-Skill Routing

The orchestrator makes every routing decision. When a skill says "Route to **skill-name**", the orchestrator looks up the correct agent in the Skill-to-Agent Routing Table and spawns it with that skill. Context (injection point, target technology, working payloads) is passed in the Task prompt.

**Mandatory skill loading**: When a skill says "Route to **skill-name**", that skill MUST be loaded via `get_skill()` — either by a subagent or inline. Never execute a technique without loading the matching skill. Skills contain methodology, edge cases, payloads, and troubleshooting that general knowledge does not. Always load skills via `get_skill()` — never execute techniques without loading the matching skill.

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
- Skills check for `./engagement/` at start. If absent, ask the operator before creating it.
- Activity entries logged at milestones, not every command. Format: `### [HH:MM] skill-name → target` with bullet points.
- Findings numbered sequentially. Light summaries — use `pentest-findings` skill for formal report-quality writeups.
- Evidence saved with descriptive filenames to `engagement/evidence/`.
- No engagement directory = no logging. Skills degrade gracefully.

**Subagent transcript capture:**
- A `SubagentStop` hook (`tools/hooks/save-agent-log.sh`) copies raw JSONL
  transcripts from domain subagents into `engagement/evidence/logs/`.
- Filename format: `{ISO-timestamp}-{agent-type}.jsonl` (e.g.,
  `20260227T143052Z-web-exploit-agent.jsonl`).
- Only triggers for red-run agents (network-recon, web-discovery,
  web-exploit, ad-discovery, ad-exploit, password-spray, linux-privesc,
  windows-privesc) — not built-in subagents (Explore, Plan, general-purpose).
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
- Call `get_state_summary()` from the state-reader or state-interim MCP to read current state
- **Discovery agents** (state-interim): Write actionable findings immediately via `add_credential()`, `add_vuln()`, `add_pivot()`, `add_blocked()` so concurrent agents can see them mid-run
- **Technique agents** (state-reader): Read-only — report all findings in return summary
- Save raw evidence to `engagement/evidence/` (the only engagement directory subagents write to)
- Report all findings clearly in their return summary — the orchestrator deduplicates and records remaining state changes

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
| **state_events** | Event log emitted by interim writes — real-time polling | `poll_events(since_id=0)` |

**Rules:**
- `get_state_summary()` produces a compact markdown summary (~200 lines) for subagent consumption
- Subagents call `get_state_summary()` on activation, report findings in their return summary
- Discovery agents (state-interim) also write actionable findings mid-run via 4 add-only tools; each write emits a `state_events` row
- The orchestrator polls `poll_events()` at interaction points for real-time visibility into discovery agent findings
- The orchestrator parses return summaries, deduplicates interim writes, and calls structured write tools for remaining state changes
- Orchestrator uses state summary + pivot map to chain vulns toward impact

## Documentation Rules

Each part of the repo has exactly one documentation file. Keep them in sync
when making changes.

| Component | Documentation | Rule |
|-----------|--------------|------|
| Repo root | `README.md` | Update when architecture, installation, or user-facing behavior changes |
| MCP servers (`tools/*/`) | `README.md` per server | **Required.** Update when tools, parameters, behavior, or prerequisites change |
| Skills (`skills/*/`) | `SKILL.md` | Self-contained — no separate README |
| Agents (`agents/`) | `<agent-name>.md` | Self-contained — no separate README |
| Hooks (`tools/hooks/`) | Inline comments | No README needed |

**When modifying a tool server:** If you change tools, parameters, behavior, or
dependencies in a `tools/*/` server, update its `README.md` in the same commit.

## Directory Layout

```
red-run/
  README.md               # User-facing project documentation
  CLAUDE.md               # Development instructions (this file)
  install.sh              # Installs orchestrator, agents, MCP servers
  uninstall.sh            # Removes installed skills, agents, MCP data
  agents/                 # Custom subagent definitions (installed to ~/.claude/agents/)
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
  skills/
    _template/SKILL.md    # Canonical template
    orchestrator/SKILL.md # Master orchestrator (native skill)
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

The installer puts the orchestrator in `~/.claude/skills/red-run-orchestrator/`, subagents in `~/.claude/agents/`, and sets up MCP servers (skill-router, nmap-server, shell-server, browser-server, state-server). Requires [uv](https://docs.astral.sh/uv/), Docker for nmap, and Playwright for browser automation (Chromium installed automatically).

