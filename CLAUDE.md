# red-run

Claude Code skill library for penetration testing and CTF work.

## Architecture

Skills are Claude Code native `SKILL.md` files that auto-trigger based on conversation context. No slash commands needed — Claude infers which skill to use from the `description` field in each skill's frontmatter.

### Modes
- **Guided** (default): Interactive. Explain each step, ask before executing, present options at forks.
- **Autonomous**: Execute end-to-end. Make triage decisions. Report at milestones. Only pause for destructive or high-OPSEC actions.

Mode is set by the user or the orchestrator and propagated via conversation context.

### Skill Types
- **Orchestrator** (`skills/orchestrator/`): Takes a target, runs recon, routes to discovery skills
- **Discovery** (`skills/<category>/*-discovery/`): Identifies vulnerabilities, routes to technique skills via decision tree
- **Technique** (`skills/<category>/<technique>/`): Exploits a specific vulnerability class

### Inter-Skill Routing
Skills route to each other using bold skill names in their escalation sections (e.g., "Route to **sql-injection-blind**"). Claude's skill matching picks up the context. When routing, pass: injection point, target technology, current mode, and any payloads that already succeeded.

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
  install.sh              # Symlinks skills to ~/.claude/skills/red-run-*/
  uninstall.sh            # Removes installed skills
  skills/
    _template/SKILL.md    # Canonical template
    orchestrator/SKILL.md # Master orchestrator
    web/                  # Web application attacks
    ad/                   # Active Directory
    privesc/              # Privilege escalation
    cloud/                # AWS, Azure, GCP
    network/              # Recon, protocols, pivoting
    containers/           # Docker, Kubernetes, CI/CD
    c2/                   # Command and control
    redteam/              # Initial access, evasion, persistence, creds
  task_plan.md            # Phased build plan
  progress.md             # Session log
  findings.md             # Source material research notes
```

## Skill File Format

Every skill lives at `skills/<category>/<skill-name>/SKILL.md`.

### Frontmatter (required)

```yaml
---
name: skill-name
description: >
  What it does. When to trigger (be pushy — Claude undertriggers by default).
  Explicit trigger phrases. OPSEC level. Tools needed.
  Negative conditions (when NOT to use, and what to use instead).
---
```

### Body structure

1. **Preamble**: "You are helping a penetration tester with..."
2. **Mode**: Check for guided vs autonomous
3. **Engagement Logging**: Check for engagement dir, log activity/findings/evidence
4. **State Management**: Read state.md on activation, write back on completion
5. **Prerequisites**: Access, tools, conditions
6. **Steps**: Assess → Confirm → Exploit → Escalate/Pivot
7. **Deep Reference**: `~/docs/` paths for WAF bypass, edge cases
8. **Troubleshooting**: Common failures and fixes

### Conventions
- Skill names use kebab-case: `sql-injection-union`, `kerberoasting`, `docker-socket-escape`
- One technique per skill — split broad topics into focused skills
- Embed critical payloads directly (top 2-3 per DB/variant for 80% coverage)
- Reference `~/docs/` for the long tail (WAF bypass, alternative functions, edge cases)
- OPSEC rating in description: `low` = passive/read-only, `medium` = creates artifacts, `high` = noisy/detected by EDR
- Inter-skill routing: bold skill names in escalation sections
- **Discovery skill maintenance**: When creating a new technique skill, update the corresponding discovery skill's routing table to include it. `web-vuln-discovery` must route to every web technique skill.

## Dependencies

### Reference Repositories

Skills reference `~/docs/` for deep payload content. Clone these:

```bash
git clone <removed> ~/docs/public-security-references
git clone <removed> ~/docs/public-security-references
git clone <removed> ~/docs/public-security-references
```

Skills degrade gracefully if these aren't available — embedded payloads still work.

## Installation

```bash
# Install (symlinks — edits in repo reflect immediately)
./install.sh

# Install (copies — for machines without the repo)
./install.sh --copy

# Uninstall
./uninstall.sh
```

Skills install to `~/.claude/skills/red-run-<skill-name>/SKILL.md`.

## Workflow

**Source of truth:** `task_plan.md` and `progress.md` are the persistent memory across sessions. Always read both at the start of a new session to pick up where we left off.

- `task_plan.md` — what to build, current phase, per-skill status
- `progress.md` — what was done, decisions made, observations, next steps
- `findings.md` — source material research notes

**Branching:** Never push directly to main. Create a feature branch per skill batch and PR it for review.

| Branch pattern | Scope |
|----------------|-------|
| `skills/web-sqli` | All SQL injection skills |
| `skills/web-xss` | All XSS skills |
| `skills/ad-core` | AD discovery + technique skills |
| `arch/*` | Architecture changes |

**Before starting work:** Read `task_plan.md` and `progress.md`, check git branch and status.

**Before ending a session:** Update `task_plan.md` (skill statuses) and `progress.md` (what was done, next steps), commit, push.
