# Teammate Spawn Templates

Markdown files the `/red-run-ctf` orchestrator reads at runtime and passes as
spawn prompts when creating agent team teammates. These are NOT Claude Code skills
or agent definitions — they're prompt templates.

## How they work

1. Orchestrator decides to spawn a teammate (e.g., web vuln found → need web-attk)
2. Orchestrator reads `teammates/web-attk.md` via the Read tool
3. Orchestrator creates a teammate using the template content as the spawn prompt
4. Teammate inherits the lead's MCP servers, permissions, and CLAUDE.md

## Teammate types

**Enumeration** — spawn when domain becomes relevant, persist across tasks:

| File | Name | Domain | Model |
|------|------|--------|-------|
| `net-enum.md` | net-enum | Network recon + service enumeration | sonnet |
| `web-enum.md` | web-enum | Web app discovery | sonnet |
| `ad-enum.md` | ad-enum | AD discovery (BloodHound, LDAP, ADCS) | sonnet |
| `lin-enum.md` | lin-enum | Linux host discovery | sonnet |
| `win-enum.md` | win-enum | Windows host discovery | sonnet |

**Attack** — spawn when technique skill is needed, persist across tasks:

| File | Name | Domain | Model |
|------|------|--------|-------|
| `web-attk.md` | web-attk | Web exploitation techniques | sonnet |
| `ad-attk.md` | ad-attk | AD exploitation techniques | sonnet |
| `lin-attk.md` | lin-attk | Linux privesc exploitation | sonnet |
| `win-attk.md` | win-attk | Windows privesc exploitation | sonnet |

**On-demand** — spawn for specific tasks, dismiss when done:

| File | Name | Domain | Model |
|------|------|--------|-------|
| `pivot.md` | pivot | Network tunneling | sonnet |
| `evade.md` | evade | AV/EDR bypass | sonnet |
| `spray.md` | spray | Password spraying | haiku |
| `crack.md` | crack | Offline hash cracking | haiku |
| `research.md` | research | Deep analysis | opus |

## Template conventions

- No YAML frontmatter — teammates inherit config from the lead
- Model is specified by the orchestrator in the spawn instruction, not in the template
- Enum teammates discover and report — they don't exploit
- Attk teammates exploit assigned vulns — they don't discover new ones
- On-demand teammates handle one task and get dismissed
- All teammates write critical findings to state.db via state MCP
- All teammates message the lead on task completion — never self-claim new tasks

## Relationship to v1 agent definitions

These templates replace `agents/*.md` for the agent-teams orchestrator. The v1
agent definitions remain in `agents/` for the subagent-based orchestrator
(`/red-run-legacy`). Both systems share the same technique skills and
MCP servers.
