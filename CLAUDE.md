# red-run

Claude Code skill library for penetration testing and CTF work.

## Architecture

The **orchestrator** is installed as a native Claude Code skill that auto-triggers based on conversation context. All other skills (62 discovery + technique skills) are served on-demand via the **MCP skill-router** — a FastMCP server backed by ChromaDB and sentence-transformer embeddings (`all-MiniLM-L6-v2`). This keeps the system prompt lean; technique skills load only when needed.

### MCP Skill Router

The MCP server at `tools/skill-router/` provides three tools:
- `search_skills(query)` — semantic search across all indexed skills
- `get_skill(name)` — load a skill's full SKILL.md content by name
- `list_skills([category])` — browse the skill inventory

Skills are indexed by `indexer.py` using structured frontmatter fields (description, keywords, tools, opsec) for high-quality embedding documents.

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
Skills route to each other at escalation points using `get_skill()` from the MCP skill-router. When a skill says "Route to **skill-name**", call `get_skill("skill-name")` to load the full skill methodology, then follow its instructions. When routing, pass: injection point, target technology, current mode, and any payloads that already succeeded.

**Mandatory skill loading**: When a skill says "Route to **skill-name**", you MUST load that skill via `get_skill()`. Never execute a technique inline when a matching skill exists — even if you already know the technique. Skills contain methodology, edge cases, payloads, and troubleshooting that general knowledge does not. This applies in both guided and autonomous modes.

**Skill discovery**: If unsure which skill to use, call `search_skills(query)` with a description of the situation. Validate the result before loading — check that the skill's description matches what you need.

**Task sub-agents cannot use MCP tools.** MCP tools are only available in the main conversation thread. Never delegate target-level work (scanning, exploitation, post-exploitation) to Task sub-agents — they bypass all skill routing, engagement logging, and state management. Use Task sub-agents only for local processing (hash cracking, output parsing, research). See the orchestrator's "Multi-Target Engagements" section for the correct approach to multiple targets.

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
  install.sh              # Installs orchestrator + sets up MCP skill-router
  uninstall.sh            # Removes installed skills + MCP data
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

The installer puts the orchestrator in `~/.claude/skills/red-run-orchestrator/` and sets up the MCP skill-router (Python venv + ChromaDB index). Requires [uv](https://docs.astral.sh/uv/).

