# red-run

Offensive security toolkit for Claude Code.

<p align="center">
  <img src="docs/dashboard.jpg" width="700" alt="Agent dashboard showing live multi-pane output from parallel agents">
</p>

red-run combines skills, MCP servers, and [Claude Code agent teams](https://code.claude.com/docs/en/agent-teams) with routing logic that guides Claude and the operator through the phases of an infrastructure-focused attack — recon, initial access, lateral movement, privilege escalation, and post-exploitation. It tracks engagement state in a SQLite database that persists across context compactions, routes to skills via semantic search (RAG), and delegates execution to persistent domain teammates that accumulate context across tasks and communicate with each other directly.

The orchestrator (team lead) presents the attack surface, chain analysis, and available paths — you choose what to hit next. Teammates work in their own tmux panes where you can watch them, press Escape to interrupt, and type directly to redirect. See the [Architecture docs](https://blacklanternsecurity.github.io/red-run/architecture/) for diagrams and data flow.

## Orchestrators

red-run supports multiple orchestrator variants that share the same skills, MCP servers, and engagement state. Each variant targets a different use case. Community contributions welcome.

| Orchestrator | Trigger | Status | Purpose |
|---|---|---|---|
| `/red-run-ctf` | Auto (natural language) + `/red-run-ctf` | **Active** | CTF and lab environments. Agent teams with persistent teammates, full autonomy, aggressive exploitation. |
| `/red-run-legacy` | `/red-run-legacy` only | **Legacy** | Original subagent-based orchestrator. Ephemeral agents, one skill per invocation. |
| `/red-run-notouch` | `/red-run-notouch` only | **Planned** | DLP-safe mode. The operator executes commands in separate tmux panes and reports sanitized output back to the orchestrator. No client data touches Anthropic servers. |
| `/red-run-train` | `/red-run-train` only | **Planned** | Training mode. Guided walkthrough with explanations at each step. Designed for learning offensive methodology with AI assistance. |

All orchestrators write to the same `engagement/state.db` — an engagement started with one variant can be resumed with another.

## Documentation

Full documentation is available at the [docs site](https://blacklanternsecurity.github.io/red-run/):

- [Architecture](https://blacklanternsecurity.github.io/red-run/architecture/) — platform vs strategy layers, prompt architecture, data flow
- [Installation](https://blacklanternsecurity.github.io/red-run/installation/) — prerequisites, setup, sandbox configuration
- [Running an Engagement](https://blacklanternsecurity.github.io/red-run/running-an-engagement/) — end-to-end operator guide
- [MCP Servers](https://blacklanternsecurity.github.io/red-run/mcp-servers/) — nmap, shell, browser, state, skill-router
- [Writing Skills](https://blacklanternsecurity.github.io/red-run/writing-skills/) — contributor guide for new skills

See also: [ARCHITECTURE.md](ARCHITECTURE.md) for Mermaid diagrams, [Skills Inventory](docs/skills-inventory.md) for the full skill inventory.

## Installation

**Prerequisites:** Linux VM with pentesting tools, [Claude Code](https://docs.anthropic.com/en/docs/claude-code), [uv](https://docs.astral.sh/uv/), [Docker](https://docs.docker.com/engine/install/)

```bash
./install.sh          # Symlink-based (edits reflect immediately)
./install.sh --copy   # Copy-based (standalone machines)
./uninstall.sh        # Remove everything
```

The installer sets up the orchestrator, teammate templates, and MCP servers, and indexes `skills/` into ChromaDB for semantic retrieval. The repo must stay in place — skill-router reads from `skills/` at runtime.

After installing, run the preflight check to verify attackbox dependencies (nmap, ffuf, sqlmap, hashcat, impacket, etc.):

```bash
bash preflight.sh
```

See [dependencies](docs/dependencies.md) for the full list of required tools and [Installation docs](https://blacklanternsecurity.github.io/red-run/installation/) for firewall setup and troubleshooting.

## Agent Teams

red-run uses [Claude Code agent teams](https://code.claude.com/docs/en/agent-teams) to coordinate multiple Claude Code sessions working together. The orchestrator runs as the team lead, spawning persistent domain teammates (recon, web, AD, Linux/Windows privesc) that each get their own tmux pane. Benefits over the legacy subagent model:

- **Persistent context** — teammates accumulate knowledge across tasks instead of starting fresh each time
- **Peer-to-peer messaging** — teammates notify each other directly (e.g., web teammate finds domain creds → messages AD teammate)
- **Operator visibility** — watch all teammates working in split tmux panes, press Escape to interrupt any teammate, type directly to redirect
- **Shared task list** — coordinated parallel work with the lead assigning all tasks

Agent teams requires the Claude Code experimental feature flag. The repo's `.claude/settings.json` already includes this:

```json
{
  "env": {
    "CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS": "1"
  }
}
```

No manual setup needed — cloning the repo and running `./install.sh` is sufficient. For split-pane teammate visibility, start Claude Code inside a tmux session. Without tmux, teammates run in-process (cycle with Shift+Down - this is not recommended for optimal control).

**Known limitation:** Agent teams is an experimental feature and currently requires `--dangerously-skip-permissions` mode. In standard mode, teammate permission requests don't always surface to the operator, causing teammates to hang. This is a stability issue with the experimental agent teams feature. The orchestrator's `AskUserQuestion` gates still provide human-in-the-loop control for exploitation decisions. This may improve as agent teams matures.

## State Dashboard

Browser-based read-only dashboard for `engagement/state.db` with a kill-chain attack graph and live SSE updates:

```bash
python3 operator/state-dashboard/server.py [--port 8099] [--db engagement/state.db]
```

Open `http://127.0.0.1:8099` to see targets, credentials, access, vulns, pivots, tunnels, blocked techniques, and an event timeline — all updating in real-time as agents work.

To access from a host machine (when red-run is in a VM), generate an auth token — the server will bind to `0.0.0.0` and require the token to access any page:

```bash
bash operator/state-dashboard/generate-token.sh
```

See `operator/state-dashboard/README.md` for details.

## Running

Agent teams requires `--dangerously-skip-permissions` due to a stability issue with the experimental feature (see [Agent Teams](#agent-teams) above). Run with:

```bash
claude --dangerously-skip-permissions
```

The orchestrator presents routing decisions for operator approval before assigning exploitation tasks. An optional nftables firewall is available in `operator/engagement-firewall/` for operators who want OS-level network isolation.

Run from an isolated VM or dedicated pentesting machine. You are responsible for containing Claude on your systems and for any legal consequences under the CFAA or equivalent legislation.

## Disclaimer

**By using red-run you accept full responsibility for its actions.** This tool runs fully autonomous AI agents that execute offensive security techniques — port scanning, vulnerability exploitation, credential attacks, privilege escalation, and lateral movement — against targets you specify.

- **Authorization required.** Do not use against systems without explicit written permission. Unauthorized access to computer systems is illegal under the CFAA (18 U.S.C. § 1030) and equivalent laws in other jurisdictions.
- **CTF and lab use only.** The current version of the orchestrator is a CTF solver — it runs fully autonomous agents with no OPSEC considerations. Skills are baseline templates built by AI and have not been thoroughly reviewed by human eyes. Expect gaps, false positives, and techniques that need validation before use on real infrastructure. See the [architecture plans](https://blacklanternsecurity.github.io/red-run/architecture/) for the production engagement roadmap.
- **No OPSEC guarantees.** Agents run with no stealth considerations. Assume all activity is logged and detectable. Do not rely on red-run for covert operations.
- **No warranty.** red-run is provided as-is. The authors are not liable for any damage, data loss, legal consequences, or other harm resulting from its use.
