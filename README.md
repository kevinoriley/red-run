# red-run

Offensive security toolkit for Claude Code.

<p align="center">
  <img src="docs/dashboard.jpg" width="700" alt="Agent dashboard showing live multi-pane output from parallel agents">
</p>

red-run combines skills, MCP servers, and agents with routing logic that guides Claude through the phases of an infrastructure-focused attack — recon, initial access, lateral movement, privilege escalation, and post-exploitation. It tracks engagement state in a SQLite database that persists across context compactions, routes to skills via semantic search (RAG), and delegates execution to focused agents that each handle one technique per invocation.

The orchestrator presents the attack surface, chain analysis, and available paths — you choose what to hit next. Once you pick a path, the agent runs end-to-end and reports back. See the [Architecture docs](https://blacklanternsecurity.github.io/red-run/architecture/) for diagrams and data flow.

## Skills

67 skills across 7 categories — see [SKILLS.md](SKILLS.md) for the full inventory.

| Category | Count | Coverage |
|----------|-------|----------|
| Web | 33 | SQLi, XSS, SSTI, deserialization, SSRF, auth bypass, and more |
| Active Directory | 16 | Kerberos, ADCS, ACLs, GPO, trust, persistence, lateral movement |
| Privilege Escalation | 11 | Linux + Windows enumeration and technique skills |
| Infrastructure | 4 | Network recon, pivoting, container escapes, SMB |
| Evasion | 1 | AV/EDR bypass, AMSI bypass, custom payloads |
| Utility | 2 | Orchestrator + retrospective |

Skills are baseline templates researched and built by Claude. Refine them manually or run retrospectives after engagements to improve and hone them to your target landscape and methodology.

## Documentation

Full documentation is available at the [docs site](https://blacklanternsecurity.github.io/red-run/):

- [Architecture](https://blacklanternsecurity.github.io/red-run/architecture/) — platform vs strategy layers, prompt architecture, data flow
- [Installation](https://blacklanternsecurity.github.io/red-run/installation/) — prerequisites, setup, sandbox configuration
- [Running an Engagement](https://blacklanternsecurity.github.io/red-run/running-an-engagement/) — end-to-end operator guide
- [MCP Servers](https://blacklanternsecurity.github.io/red-run/mcp-servers/) — nmap, shell, browser, state, skill-router
- [Writing Skills](https://blacklanternsecurity.github.io/red-run/writing-skills/) — contributor guide for new skills

See also: [ARCHITECTURE.md](ARCHITECTURE.md) for Mermaid diagrams, [SKILLS.md](SKILLS.md) for the full skill inventory.

## Installation

**Prerequisites:** Linux VM with pentesting tools, [Claude Code](https://docs.anthropic.com/en/docs/claude-code), [uv](https://docs.astral.sh/uv/), [Docker](https://docs.docker.com/engine/install/)

```bash
./install.sh          # Symlink-based (edits reflect immediately)
./install.sh --copy   # Copy-based (standalone machines)
./uninstall.sh        # Remove everything
```

The installer sets up the orchestrator, agents, and MCP servers, and indexes `skills/` into ChromaDB for semantic retrieval. The repo must stay in place — skill-router reads from `skills/` at runtime.

Run from a VM or dedicated pentesting machine. See [Installation docs](https://blacklanternsecurity.github.io/red-run/installation/) for firewall setup and troubleshooting.

## State Viewer

Browser-based read-only dashboard for `engagement/state.db` with a kill-chain attack graph and live SSE updates:

```bash
python3 tools/state-viewer/server.py [--port 8099] [--db engagement/state.db]
```

Open `http://127.0.0.1:8099` to see targets, credentials, access, vulns, pivots, tunnels, blocked techniques, and an event timeline — all updating in real-time as agents work.

To access from a host machine (when red-run is in a VM), generate an auth token — the server will bind to `0.0.0.0` and require the token to access any page:

```bash
bash tools/state-viewer/generate-token.sh
```

See `tools/state-viewer/README.md` for details.

## Permission Mode

red-run supports two engagement modes:

- **Pentest mode** (`claude`) — Technique skills run inline with normal permission prompts. Discovery skills delegate to autonomous agents. Engagement firewall required.
- **CTF mode** (`claude --dangerously-skip-permissions`) — All skills delegate to autonomous agents. No firewall required. The orchestrator still presents routing decisions for operator approval.

The orchestrator asks which mode to use when initializing a new engagement.

red-run is a **proof of concept** tested only in CTF environments. Do not use it in production engagements. Run from an isolated VM or dedicated pentesting machine. You are responsible for containing Claude on your systems and for any legal consequences under the CFAA or equivalent legislation.

## Disclaimer

For use in **authorized security testing and educational contexts only**. Do not use against systems without explicit written permission. Skills are baseline templates — expect gaps and techniques that need validation against real targets. While skills include OPSEC notes where relevant, do not trust red-run to maintain OPSEC in production environments without dedicated review and testing.
