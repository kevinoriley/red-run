# red-run

Claude Code skill library for penetration testing and CTF work.

## Architecture

The **orchestrator** is a native Claude Code skill that runs in the main conversation thread. It routes skill execution to **custom domain subagents** — each subagent has MCP access and executes one skill per invocation. All other skills (63 discovery + technique skills) are served on-demand via the **MCP skill-router**.

### Subagent Model

The orchestrator spawns domain-specific subagents for each skill invocation:

| Agent | Domain | MCP Servers | Skills |
|-------|--------|-------------|--------|
| `network-recon-agent` | Network | skill-router, nmap-server, shell-server | network-recon, smb-exploitation, pivoting-tunneling |
| `web-agent` | Web | skill-router, shell-server | All web discovery + technique skills |
| `ad-agent` | Active Directory | skill-router, shell-server | All AD discovery + technique skills |
| `privesc-agent` | Privilege Escalation | skill-router, shell-server | Linux/Windows discovery + privesc + container escapes |

Each invocation: agent loads one skill via `get_skill()`, executes methodology, updates engagement files, returns findings. The orchestrator reads state.md after every return and makes the next routing decision. Subagents never load a second skill or route to other skills.

**Inline fallback**: If subagents aren't installed, the orchestrator loads skills inline via `get_skill()` in the main thread.

Agent source files live in `agents/` (version controlled), installed to `~/.claude/agents/` by install.sh.

### MCP Servers

| Server | Location | Tools | Purpose |
|--------|----------|-------|---------|
| skill-router | `tools/skill-router/` | `search_skills`, `get_skill`, `list_skills` | Semantic skill discovery and loading |
| nmap-server | `tools/nmap-server/` | `nmap_scan`, `get_scan`, `list_scans` | Privileged nmap scanning (no sudo handoff) |
| shell-server | `tools/shell-server/` | `start_listener`, `send_command`, `read_output`, `stabilize_shell`, `list_sessions`, `close_session` | TCP listener and reverse shell session manager |

The skill-router is backed by ChromaDB + sentence-transformer embeddings (`all-MiniLM-L6-v2`). Skills are indexed from structured frontmatter fields (description, keywords, tools, opsec).

The nmap-server wraps `sudo nmap` and returns parsed JSON. Requires passwordless sudo for nmap.

The shell-server manages TCP listeners and reverse shell sessions. It solves the persistent shell problem — Claude Code's Bash tool runs each command as a separate process, so interactive shells and privilege escalation tools that spawn new shells have no way to connect back.

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
├── state.md          # Compact machine-readable engagement state (snapshot)
├── activity.md       # Chronological action log (append-only)
├── findings.md       # Confirmed vulnerabilities (working tracker)
└── evidence/         # Saved output, responses, dumps
```

**Behavior:**
- Skills check for `./engagement/` at start. Guided mode asks to create it if absent; autonomous mode creates it automatically.
- Activity entries logged at milestones, not every command. Format: `### [HH:MM] skill-name → target` with bullet points.
- Findings numbered sequentially. Light summaries — use `pentest-findings` skill for formal report-quality writeups.
- Evidence saved with descriptive filenames to `engagement/evidence/`.
- No engagement directory = no logging. Skills degrade gracefully.

**Orchestrator responsibility:**
- Creates engagement directory and initializes `scope.md` and `state.md` from user input
- Maintains `activity.md` across skill transitions
- Reads `state.md` to decide next actions and which skill to invoke
- Analyzes `state.md` to chain vulnerabilities toward maximum impact
- Produces engagement summary when complete

### State Management

`engagement/state.md` is a compact, machine-readable snapshot of current engagement state. It is **not** a log — it's the current truth.

**Sections:**

| Section | Contents | Updated By |
|---------|----------|------------|
| **Targets** | Hosts, IPs, URLs, ports, tech stack (one-liner each) | Discovery skills |
| **Credentials** | Username/password/hash/token pairs, where they work | Any skill that finds creds |
| **Access** | Current footholds: shells, sessions, tokens, DB access | Exploitation skills |
| **Vulns** | One-liner per confirmed vuln with status: `[found]`, `[active]`, `[done]` | Technique skills |
| **Pivot Map** | What leads where — vuln X gives access Y, creds Z work on host W | Any skill |
| **Blocked** | What was tried and why it failed — prevents re-testing | Any skill |

**Rules:**
- Keep state.md under ~200 lines so skills can read it without burning context
- One line per item — compact over complete
- Current state, not history — remove revoked creds, mark exploited vulns `[done]`
- Every skill reads state.md on activation, writes back on completion
- Orchestrator uses state.md + Pivot Map to chain vulns toward impact

## Directory Layout

```
red-run/
  install.sh              # Installs orchestrator, agents, MCP servers
  uninstall.sh            # Removes installed skills, agents, MCP data
  agents/                 # Custom subagent definitions (installed to ~/.claude/agents/)
    network-recon-agent.md
    web-agent.md
    ad-agent.md
    privesc-agent.md
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
    nmap-server/          # MCP server (sudo nmap wrapper)
      server.py           # FastMCP server — nmap_scan, get_scan, list_scans
      pyproject.toml       # Python dependencies (mcp, python-libnmap)
    shell-server/         # MCP server (TCP listener + shell manager)
      server.py           # FastMCP server — start_listener, send_command, stabilize_shell, etc.
      pyproject.toml       # Python dependencies (mcp)
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
3. **Engagement Logging**: Check for engagement dir, log invocation immediately, log activity/findings/evidence at milestones
4. **State Management**: Read state.md on activation, write at checkpoints (vuln confirmed, exploitation, pre-routing)
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

The installer puts the orchestrator in `~/.claude/skills/red-run-orchestrator/`, subagents in `~/.claude/agents/`, and sets up MCP servers (skill-router, nmap-server, shell-server). Requires [uv](https://docs.astral.sh/uv/) and passwordless sudo for nmap.

