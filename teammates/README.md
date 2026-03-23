# Teammate Spawn Templates

Markdown files the `/red-run-ctf` orchestrator reads at runtime and passes as
spawn prompts when creating agent team teammates. These are NOT Claude Code skills
or agent definitions — they're prompt templates.

## How they work

1. Orchestrator decides to spawn a teammate (e.g., web vuln found → need web-ops)
2. Orchestrator reads `teammates/web-ops.md` via the Read tool
3. Orchestrator creates a teammate using the template content as the spawn prompt
4. Teammate inherits the lead's MCP servers, permissions, and CLAUDE.md

## Teammate types

**Infrastructure** — spawned at engagement start, persists entire engagement:

| File | Name | Domain | Model |
|------|------|--------|-------|
| `state-mgr.md` | state-mgr | Centralized state writer, dedup, graph coherence | sonnet |

**Enumeration** — spawn when domain becomes relevant, persist across tasks:

| File | Name | Domain | Model |
|------|------|--------|-------|
| `net-enum.md` | net-enum | Network recon + service enumeration | sonnet |
| `web-enum.md` | web-enum | Web app discovery | sonnet |
| `ad-enum.md` | ad-enum | AD discovery (BloodHound, LDAP, ADCS) | sonnet |
| `lin-enum.md` | lin-enum | Linux host discovery | sonnet |
| `win-enum.md` | win-enum | Windows host discovery | sonnet |

**Operations** — spawn when technique skill is needed, persist across tasks:

| File | Name | Domain | Model |
|------|------|--------|-------|
| `web-ops.md` | web-ops | Web technique execution | sonnet |
| `ad-ops.md` | ad-ops | AD technique execution | sonnet |
| `lin-ops.md` | lin-ops | Linux privesc techniques | sonnet |
| `win-ops.md` | win-ops | Windows privesc techniques | sonnet |

**On-demand** — spawn for specific tasks, dismiss when done:

| File | Name | Domain | Model |
|------|------|--------|-------|
| `pivot.md` | pivot | Network tunneling | sonnet |
| `bypass.md` | bypass | AV/EDR bypass | sonnet |
| `spray.md` | spray | Password spraying | haiku |
| `recover.md` | recover | Offline hash recovery | haiku |
| `research.md` | research | Deep analysis | opus |

## Template conventions

- No YAML frontmatter — teammates inherit config from the lead
- Model is specified by the orchestrator in the spawn instruction, not in the template
- Enum teammates discover and report — they don't exercise findings
- Ops teammates exercise assigned vulns — they don't discover new ones
- On-demand teammates handle one task and get dismissed
- All state writes go through state-mgr via structured `[action]` messages
- Teammates read state directly (get_state_summary, get_vulns, etc.)
- All teammates message the lead on task completion — never self-claim new tasks

## Relationship to v1 agent definitions

These templates replace `agents/*.md` for the agent-teams orchestrator. The v1
agent definitions remain in `agents/` for the subagent-based orchestrator
(`/red-run-legacy`). Both systems share the same technique skills and
MCP servers.
