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
3. **Prerequisites**: Access, tools, conditions
4. **Steps**: Assess → Confirm → Exploit → Escalate/Pivot
5. **Deep Reference**: `~/docs/` paths for WAF bypass, edge cases
6. **Troubleshooting**: Common failures and fixes

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
