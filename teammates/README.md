# Teammate Spawn Templates

Markdown files the `/red-run-ctf` orchestrator reads at runtime and passes as
spawn prompts when creating agent team teammates. These are NOT Claude Code skills
or agent definitions — they're prompt templates.

## How they work

1. Orchestrator decides to spawn a teammate (e.g., web services found → need web teammate)
2. Orchestrator reads `teammates/web.md` via the Read tool
3. Orchestrator creates a teammate using the template content as the spawn prompt
4. Teammate inherits the lead's MCP servers, permissions, and CLAUDE.md

## Teammate types

**Persistent** — spawned when their domain becomes relevant, persist across
multiple tasks until dismissed:

| File | Domain | Model |
|------|--------|-------|
| `recon.md` | Network recon + service enumeration | haiku |
| `web.md` | Web discovery + exploitation | sonnet |
| `ad.md` | AD discovery + exploitation | sonnet |
| `linux.md` | Linux discovery + privilege escalation | sonnet |
| `windows.md` | Windows discovery + privilege escalation | sonnet |

**On-demand** — spawned for specific tasks, dismissed when done:

| File | Domain | Model |
|------|--------|-------|
| `pivoting.md` | Network tunneling | sonnet |
| `evasion.md` | AV/EDR bypass payload building | sonnet |
| `spray.md` | Password spraying | haiku |
| `cracking.md` | Offline hash cracking | haiku |
| `research.md` | Deep analysis of custom/unknown vectors | opus |

## Template conventions

- No YAML frontmatter — teammates inherit config from the lead
- Model is specified by the orchestrator in the spawn instruction, not in the template
- Persistent teammates handle multiple skills across tasks
- On-demand teammates handle one task and get dismissed
- All teammates write critical findings to state.db via state-interim MCP
- All teammates message the lead on task completion — never self-claim new tasks

## Relationship to v1 agent definitions

These templates replace `agents/*.md` for the agent-teams orchestrator. The v1
agent definitions remain in `agents/` for the subagent-based orchestrator
(`/red-run-orchestrator`). Both systems share the same technique skills and
MCP servers.
