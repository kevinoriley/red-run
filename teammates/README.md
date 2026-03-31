# Teammate Spawn Templates

Markdown files the `/red-run-ctf` orchestrator reads at runtime and passes as
spawn prompts when creating agent team teammates. These are NOT Claude Code skills
or agent definitions — they're prompt templates.

## How they work

1. Orchestrator calls `TeamCreate(team_name="red-run")` once per session
2. Orchestrator decides to spawn a teammate (e.g., web vuln found → need web-ops)
3. Orchestrator reads `teammates/web-ops.md` via the Read tool
4. Orchestrator spawns via `Agent(prompt=<template>, name="web-ops", team_name="red-run")`
5. Teammate inherits the lead's MCP servers, permissions, and CLAUDE.md
6. Teammate goes idle after activation — wakes on `SendMessage` from lead or peers

## Teammate types

**Infrastructure** — spawned at engagement start, persists entire engagement:

| File | Name | Domain | Model |
|------|------|--------|-------|
| `state-mgr.md` | state-mgr | Centralized state writer, dedup, graph coherence | sonnet |
| `shell-mgr.md` + `shell-mgr-<backend>.md` | shell-mgr | Shell session lifecycle (listeners, processes, upgrades, handoff) | sonnet |

**Enumeration** — one per target surface, multiple instances from same template:

| File | Naming | Domain | Model |
|------|--------|--------|-------|
| `net-enum.md` | net-enum, net-enum-\<target\> | Network recon + service enumeration | sonnet |
| `web-enum.md` | web-enum-\<site\> | Web app discovery | sonnet |
| `ad-enum.md` | ad-enum | AD discovery (BloodHound, LDAP, ADCS) | sonnet |
| `lin-enum.md` | lin-enum-\<host\> | Linux host discovery | sonnet |
| `win-enum.md` | win-enum-\<host\> | Windows host discovery | sonnet |

**Operations** — one per target surface when parallel paths exist:

| File | Naming | Domain | Model |
|------|--------|--------|-------|
| `web-ops.md` | web-ops, web-ops-\<target\> | Web technique execution | sonnet |
| `ad-ops.md` | ad-ops | AD technique execution | sonnet |
| `lin-ops.md` | lin-ops-\<host\> | Linux privesc techniques | sonnet |
| `win-ops.md` | win-ops-\<host\> | Windows privesc techniques | sonnet |

**On-demand** — spawn for specific tasks, dismiss when done:

| File | Name | Domain | Model |
|------|------|--------|-------|
| `bypass.md` | bypass | AV/EDR bypass | sonnet |
| `spray.md` | spray | Password spraying | haiku |
| `recover.md` | recover | Offline hash recovery | haiku |
| `research.md` | research | Deep analysis | sonnet |

## Template conventions

- No YAML frontmatter — teammates inherit config from the lead
- Model is specified by the orchestrator in the spawn instruction, not in the template
- Sonnet teammates spawn as Sonnet 200k by default; for 1M context, set
  `ANTHROPIC_DEFAULT_SONNET_MODEL=claude-sonnet-4-6[1m]` in `.claude/settings.json` env
- Enum teammates discover and report — they don't action findings
- Ops teammates action assigned vulns — they don't discover new ones
- On-demand teammates handle one task and get dismissed
- All state writes go through state-mgr via structured `[action]` messages
- All shell lifecycle ops go through shell-mgr (listeners, processes, upgrades);
  teammates call send_command directly on the MCP after session handoff
- Teammates read state directly (get_state_summary, get_vulns, etc.)
- All teammates message the lead on task completion — never self-claim new tasks
- Non-infrastructure templates end with an Activation Protocol: load schemas,
  read state, go idle. Teammates only start work on `[TASK]`-prefixed messages.
  The spawn prompt is system context, NOT a task assignment.

## Relationship to v1 agent definitions

These templates replace `agents/*.md` for the agent-teams orchestrator. The v1
agent definitions remain in `agents/` for the subagent-based orchestrator
(`/red-run-legacy`). Both systems share the same technique skills and
MCP servers.
