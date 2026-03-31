# Architecture

red-run has two layers: a **platform layer** that provides capabilities, and a **strategy layer** that decides how to use them.

## Platform vs Strategy

### Platform layer (stable)

The platform is the set of reusable components that any engagement can use:

- **[Teammates](teammates.md)** — persistent domain teammates (enum/ops pairs) spawned by the orchestrator
- **[Skills](skills-reference.md)** — 67+ technique-specific methodology files loaded on demand
- **[MCP servers](mcp-servers.md)** — nmap scanning, shell management, browser automation, skill routing, state tracking
- **[Engagement state](engagement-state.md)** — SQLite database tracking targets, credentials, access, vulns, and pivot paths
- **[Dashboard](dashboard-and-monitoring.md)** — Real-time engagement monitoring with access chain graph

These components don't change based on engagement type. A CTF lab and a client engagement use the same teammates, skills, and servers.

### Strategy layer (swappable)

The **orchestrator** is the strategy layer. It reads engagement state, decides which skill to invoke next, assigns it to the right teammate, and records findings. The default orchestrator (`/red-run-ctf`) is a **CTF/lab orchestrator** — it chains aggressively, routes to technique skills, and treats everything in scope as fair game.

A different orchestrator could use the same platform with different decision logic:

- **Client engagement orchestrator** — mandatory operator approval before technique execution, stricter scope gates, OPSEC-first routing
- **Red team orchestrator** — stealth-focused, avoids detection signatures, operates within rules of engagement windows
- **Training orchestrator** — explains each decision, pauses for student input, provides hints

The orchestrator contract is simple: read state, pick a skill, assign it to a teammate, record findings. Everything else is implementation choice.

## Architecture Overview

<p align="center">
  <img src="../architecture.svg" width="700" alt="Architecture diagram: Operator → Orchestrator → Agents → MCP Servers → engagement/">
</p>

## Prompt Architecture

red-run controls behavior through layered prompts, not code. Each layer adds specificity:

| Layer | File | Loaded When | What It Provides |
|-------|------|-------------|-----------------|
| **Project** | `CLAUDE.md` | Every conversation | Architecture rules, conventions, skill routing mandate |
| **Teammate** | `teammates/<name>.md` | Teammate spawns | Role definition, scope constraints, hard stops, state-mgr messaging protocol |
| **Skill** | `skills/<cat>/<name>/SKILL.md` | `get_skill()` call | Technique methodology, payloads, troubleshooting |
| **Dynamic** | Lead's task assignment | Each task | Target info, credential/access IDs, engagement-specific context |

The project layer sets universal rules. The teammate layer constrains to a domain (web-enum only discovers, web-ops only executes techniques). The skill layer provides technique depth. The dynamic prompt carries live context from the lead.

## Teammate → MCP Access

All teammates inherit MCP servers from the lead session. In agent teams, MCP servers are shared — a shell session created by one teammate is visible to all others (shell-server runs as a shared SSE service).

| Teammate | Domain | MCP Servers Used |
|----------|--------|------------------|
| state-mgr | State management | state (sole writer) |
| net-enum | Network recon | skill-router, nmap-server, shell-server, state |
| web-enum | Web discovery | skill-router, shell-server, browser-server, state |
| web-ops | Web techniques | skill-router, shell-server, browser-server, state |
| ad-enum | AD discovery | skill-router, shell-server, state |
| ad-ops | AD techniques | skill-router, shell-server, state |
| lin-enum / lin-ops | Linux host | skill-router, shell-server, state |
| win-enum / win-ops | Windows host | skill-router, shell-server, rdp-server, state |
| pivot, bypass, spray, recover, research | On-demand specialists | varies |

All state writes are centralized through **state-mgr** — the sole writer to state.db. Other teammates message state-mgr with structured `[action]` messages instead of calling write tools directly. State reads are direct (any teammate, any time).

## Task Lifecycle

What happens when the lead assigns a task to a teammate:

1. **Lead assigns** a skill and target to a specific teammate via messaging
2. **Teammate loads** the skill via `get_skill()` from the skill-router MCP
3. **Teammate reads state** via `get_state_summary()` for current context
4. **Teammate executes** the skill methodology, messaging state-mgr with findings as they occur
5. **Teammate messages lead** with a structured summary on completion
6. **Lead runs post-task checkpoint** — audits state, updates vuln statuses, routes next actions
7. **Hard stops fire** when applicable (new access → execution achieved, new creds → credential enum, etc.)

## Engagement Directory

```
engagement/
├── config.yaml       # Operator preferences (scan type, proxy, spray, cracking)
├── scope.md          # Target scope, credentials, rules of engagement
├── state.db          # SQLite engagement state (managed via state-server MCP)
├── dump-state.sh     # Export state.db as markdown
├── web-proxy.json    # Machine-readable web proxy config
├── web-proxy.sh      # Shell env vars for web proxy
└── evidence/         # Saved output, responses, dumps
    └── logs/         # Teammate JSONL transcripts
```

The lead creates this directory during engagement setup. State-mgr is the sole writer to state.db. Teammates write evidence files to `evidence/`. The `TeammateIdle` hook captures teammate transcripts to `evidence/logs/`.

See [Engagement State](engagement-state.md) for the database schema and [Running an Engagement](running-an-engagement.md) for the full workflow.

## Data Flow

State flows through the system via state-mgr:

1. **Teammates discover** findings during skill execution
2. **Teammates message state-mgr** with structured `[action]` messages (not direct DB writes)
3. **State-mgr applies** LLM-level dedup, validates provenance links, writes to state.db
4. **State-mgr notifies lead** of new findings (`[new-vuln]`, `[new-cred]`, `[new-access]`)
5. **Lead runs decision logic** — routes findings to the right teammate
6. **Any teammate** can read state directly via `get_state_summary()` at any time

Centralizing writes through state-mgr provides dedup judgment that DB-level constraints can't (e.g., "LFI file read" vs "LFI via absolute path" are the same vuln with different wording). It also enforces the technique-vuln linkage rule: credentials from active techniques must have a corresponding vuln record.

## Privilege Boundaries

Claude Code never gets sudo. This is a deliberate design decision — an LLM with root access to your machine is an unnecessary risk, and red-run is architected so it's never needed.

The tools that require elevated privileges are isolated behind MCP servers and Docker containers:

| What needs privilege | How red-run handles it | Why not just sudo |
|---------------------|----------------------|-------------------|
| `nmap` SYN scans | nmap-server runs nmap inside a Docker container with `--network=host` and minimal capabilities | SYN scans need raw sockets, but Claude doesn't need root — Docker provides the capability isolation |
| Responder, mitm6, tcpdump | shell-server's `privileged=True` runs commands in the `red-run-shell` Docker container with `NET_RAW`/`NET_ADMIN` capabilities | These daemons need raw sockets for poisoning/sniffing, but the privilege stays inside the container |
| `/etc/hosts` changes | Orchestrator hits a **hard stop** — presents the hostnames and asks the operator to add them manually | DNS resolution changes affect the entire system, not just the engagement |
| Clock skew correction | Orchestrator hits a **hard stop** — shows the required `ntpdate` or `faketime` command for the operator to run | System clock changes affect every process on the machine |
The pattern is consistent: if something needs elevated privilege, either it runs inside a container that has the specific capability, or the orchestrator stops and asks the operator to do it. Claude never runs `sudo` itself.

This also means red-run works without adding Claude Code to sudoers or `NOPASSWD` entries for privilege escalation on the *host*. The attack surface is the target, not your machine.

You can enforce this at the Claude Code level by adding `Bash(sudo *)` to the deny list in `~/.claude/settings.json`. This makes Claude Code refuse any Bash command starting with `sudo`, regardless of what an agent or skill tries to do:

```json
{
  "permissions": {
    "deny": [
      "Bash(sudo *)"
    ]
  }
}
```

This comes from the [Trail of Bits Claude Code hardening guide](https://blog.trailofbits.com/2025/07/10/securing-claude-code/), which has other useful deny rules for destructive commands (`rm -rf`, `git push --force`, `dd`, etc.). See [Installation](installation.md) for the recommended setup.
