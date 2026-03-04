# red-run

Offensive security toolkit for Claude Code.

<p align="center">
  <img src="docs/dashboard.jpg" width="700" alt="Agent dashboard showing live multi-pane output from parallel agents">
</p>

red-run combines skills, MCP servers, and agents with routing logic that guides Claude through the phases of an infrastructure-focused attack — recon, initial access, lateral movement, privilege escalation, and post-exploitation. It tracks engagement state in a SQLite database that persists across context compactions, routes to skills via semantic search (RAG), and delegates execution to focused agents that each handle one technique per invocation.

The orchestrator presents the attack surface, chain analysis, and available paths — you choose what to hit next. Once you pick a path, the agent runs end-to-end and reports back. See the [Architecture docs](https://kevinoriley.github.io/red-run/architecture/) for diagrams and data flow.

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

Full documentation is available at the [docs site](https://kevinoriley.github.io/red-run/):

- [Architecture](https://kevinoriley.github.io/red-run/architecture/) — platform vs strategy layers, prompt architecture, data flow
- [Installation](https://kevinoriley.github.io/red-run/installation/) — prerequisites, setup, sandbox configuration
- [Running an Engagement](https://kevinoriley.github.io/red-run/running-an-engagement/) — end-to-end operator guide
- [MCP Servers](https://kevinoriley.github.io/red-run/mcp-servers/) — nmap, shell, browser, state, skill-router
- [Writing Skills](https://kevinoriley.github.io/red-run/writing-skills/) — contributor guide for new skills

See also: [ARCHITECTURE.md](ARCHITECTURE.md) for Mermaid diagrams, [SKILLS.md](SKILLS.md) for the full skill inventory.

## Installation

**Prerequisites:** Linux VM with pentesting tools, [Claude Code](https://docs.anthropic.com/en/docs/claude-code), [uv](https://docs.astral.sh/uv/), [Docker](https://docs.docker.com/engine/install/)

```bash
./install.sh          # Symlink-based (edits reflect immediately)
./install.sh --copy   # Copy-based (standalone machines)
./uninstall.sh        # Remove everything
```

The installer sets up the orchestrator, agents, and MCP servers, and indexes `skills/` into ChromaDB for semantic retrieval. The repo must stay in place — skill-router reads from `skills/` at runtime.

Run from a VM or dedicated pentesting machine. See [Installation docs](https://kevinoriley.github.io/red-run/installation/) for sandbox configuration and troubleshooting.

## Warning

`claude --dangerously-skip-permissions` (yolo mode) is available but **not recommended**. With it active, Claude will chain skills, pop shells, move laterally, and escalate privileges without pausing for confirmation. Avoid `--dangerously-skip-permissions` for maximum safety. You are responsible for containing Claude on your systems and for any legal consequences under the CFAA or equivalent legislation.

## Disclaimer

For use in **authorized security testing and educational contexts only**. Do not use against systems without explicit written permission. Skills are baseline templates — expect gaps and techniques that need validation against real targets. While skills include OPSEC notes where relevant, do not trust red-run to maintain OPSEC in production environments without dedicated review and testing.
