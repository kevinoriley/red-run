# Teammates

red-run delegates skill execution to **persistent domain teammates** via Claude Code agent teams. Each teammate accumulates context across tasks, communicates with the lead and other teammates via messaging, and writes findings to state through the state-mgr teammate.

## Teammate Model

The lead (orchestrator) never executes technique skills directly. Instead, it assigns tasks to domain teammates:

1. **Lead searches** for the right skill via `search_skills()`
2. **Lead resolves** the teammate from the skill's category
3. **Lead assigns** the task with skill name, target, and engagement context
4. **Teammate loads** the skill via `get_skill()` from the skill-router MCP
5. **Teammate reads** current engagement state via `get_state_summary()`
6. **Teammate executes** the skill methodology step by step
7. **Teammate messages state-mgr** with findings as they occur
8. **Teammate messages lead** with a structured summary on completion
9. **Lead runs post-task checkpoint** — audits state, routes next actions

Teammates persist across tasks — they accumulate domain knowledge and don't start fresh each time. The lead passes context (injection points, working payloads, target technology, credential/access IDs for provenance) in each task assignment.

## Teammate Map

Teammates are split into enumeration and operations pairs per domain, plus infrastructure and on-demand specialists.

**Infrastructure** (persists entire engagement):

| Template | Name | Domain | Model | Role |
|----------|------|--------|-------|------|
| `state-mgr.md` | state-mgr | State management | sonnet | Sole writer to state.db. Handles dedup, graph coherence, provenance linking. |

**Enumeration** (one per target surface):

| Template | Naming | Domain | Model |
|----------|--------|--------|-------|
| `net-enum.md` | net-enum, net-enum-\<target\> | Network recon + service enum | sonnet |
| `web-enum.md` | web-enum-\<site\> | Web app discovery | sonnet |
| `ad-enum.md` | ad-enum | AD discovery | sonnet |
| `lin-enum.md` | lin-enum-\<host\> | Linux host discovery | sonnet |
| `win-enum.md` | win-enum-\<host\> | Windows host discovery | sonnet |

**Operations** (one per target surface):

| Template | Naming | Domain | Model |
|----------|--------|--------|-------|
| `web-ops.md` | web-ops, web-ops-\<target\> | Web techniques | sonnet |
| `ad-ops.md` | ad-ops | AD techniques | sonnet |
| `lin-ops.md` | lin-ops-\<host\> | Linux privesc | sonnet |
| `win-ops.md` | win-ops-\<host\> | Windows privesc | sonnet |

**On-demand** (spawn for task, dismiss after):

| Template | Name | Domain | Model |
|----------|------|--------|-------|
| `pivot.md` | pivot | Tunneling | sonnet |
| `bypass.md` | bypass | AV/EDR bypass | sonnet |
| `spray.md` | spray | Password spraying | haiku |
| `recover.md` | recover | Offline recovery | haiku |
| `research.md` | research | Deep analysis | opus |

## Enumeration vs Operations

Teammates are split into two categories with different responsibilities.

### Enumeration teammates

Enumeration teammates **discover attack surface** and identify vulnerabilities. They report findings to the lead and state-mgr — they never execute technique skills themselves.

### Operations teammates

Operations teammates **exercise specific vulnerabilities**. They load technique skills, execute the methodology, and report results. All findings are messaged to state-mgr for state persistence and to the lead for routing decisions.

## State Access Pattern

All state writes are centralized through state-mgr:

```
Lead ──messages──► state-mgr ──writes──► state.db
Teammates ──messages──► state-mgr ──writes──► state.db
Any teammate ──reads──► state.db (direct, any time)
```

State-mgr provides LLM-level deduplication that database constraints can't (e.g., "LFI file read" vs "LFI via absolute path" are the same vuln). It also enforces provenance linking — credentials from active techniques must have a corresponding vuln record.

## Tool Execution: Bash vs Shell-Server

Each teammate must choose between the Bash tool and the shell-server MCP for command execution. The rule is simple: **Bash is the default**, shell-server is for specific use cases.

**Use Bash for:**

- Single non-interactive commands (`nmap`, `curl`, `hashcat`, `certipy`)
- File operations, text processing, tool installation
- Anything that runs and exits

**Use shell-server `start_process()` for:**

- Interactive shells that need persistent state (`evil-winrm`, `ssh`, `msfconsole`)
- Privileged Docker execution (`privileged=True`) for tools in the red-run-shell container
- Daemons needing raw sockets (`Responder`, `mitm6`, `tcpdump`)

**Use shell-server `start_listener()` / `send_command()` for:**

- Catching reverse shells
- Sending commands to established shell sessions
- Interacting with stabilized PTY sessions

## Scope Boundaries

Each teammate operates within strict scope boundaries defined by its loaded skill:

- **Scope boundary**: When a skill says "Route to **skill-name**", the teammate stops and messages the lead with findings and the recommended next skill. Teammates never load or execute another skill.
- **Stay in methodology**: Teammates only use techniques documented in their loaded skill. No improvisation, no custom exploit code, no techniques from other domains.
- **Stall detection**: If a teammate spends 5+ tool-calling rounds on the same failure with no meaningful progress, it stops and messages the lead with what was attempted, what failed, and whether it's permanently blocked or retryable.
- **AV/EDR detection**: If a payload is caught by antivirus, the teammate stops immediately and messages the lead with structured context for the bypass teammate.
- **DNS failures**: If hostname resolution fails, the teammate stops and messages the lead with the failing hostname so the lead can request operator intervention.

Teammate spawn templates live in `teammates/` (version controlled). See `teammates/README.md` for the template format.
