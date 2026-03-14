# red-run

Offensive security toolkit for Claude Code.

<p align="center">
  <img src="docs/dashboard.jpg" width="700" alt="Agent dashboard showing live multi-pane output from parallel agents">
</p>

red-run combines skills, MCP servers, and agents with routing logic that guides Claude through the phases of an infrastructure-focused attack — recon, initial access, lateral movement, privilege escalation, and post-exploitation. It tracks engagement state in a SQLite database that persists across context compactions, routes to skills via semantic search (RAG), and delegates execution to focused agents that each handle one technique per invocation.

The orchestrator presents the attack surface, chain analysis, and available paths — you choose what to hit next. Once you pick a path, the agent runs end-to-end and reports back. An engagement config wizard captures operator preferences (C2 framework, web proxy, scan type, cracking method) upfront so subsequent resumes skip repeated questions. Optional Sliver C2 integration provides native session management, pivoting, and implant generation as an alternative to raw reverse shells. See the [Architecture docs](https://blacklanternsecurity.github.io/red-run/architecture/) for diagrams and data flow.

## Skills

67 skills across 7 categories — see [Skills Inventory](docs/skills-inventory.md) for the full inventory.

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

See also: [ARCHITECTURE.md](ARCHITECTURE.md) for Mermaid diagrams, [Skills Inventory](docs/skills-inventory.md) for the full skill inventory.

## Installation

**Prerequisites:** Linux VM with pentesting tools, [Claude Code](https://docs.anthropic.com/en/docs/claude-code), [uv](https://docs.astral.sh/uv/), [Docker](https://docs.docker.com/engine/install/)

**Optional:** [Sliver C2](https://github.com/BishopFox/sliver) for C2 integration (session management, pivoting, implant generation). Without Sliver, the orchestrator uses raw reverse shells via shell-server.

```bash
./install.sh          # Symlink-based (edits reflect immediately)
./install.sh --copy   # Copy-based (standalone machines)
./uninstall.sh        # Remove everything

# Optional: Sliver C2 proto compilation (requires Sliver protos)
bash scripts/update-sliver-protos.sh
```

The installer sets up the orchestrator, agents, and MCP servers, and indexes `skills/` into ChromaDB for semantic retrieval. The repo must stay in place — skill-router reads from `skills/` at runtime.

After installing, run the preflight check to verify attackbox dependencies (nmap, ffuf, sqlmap, hashcat, impacket, etc.):

```bash
bash preflight.sh
```

See [dependencies](docs/dependencies.md) for the full list of required tools and [Installation docs](https://blacklanternsecurity.github.io/red-run/installation/) for firewall setup and troubleshooting.

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

All skills delegate to autonomous agents with `bypassPermissions`. Run with:

```bash
claude --dangerously-skip-permissions
```

The orchestrator still presents routing decisions for operator approval before spawning each agent. An optional nftables firewall is available in `operator/engagement-firewall/` for operators who want OS-level network isolation.

Run from an isolated VM or dedicated pentesting machine. You are responsible for containing Claude on your systems and for any legal consequences under the CFAA or equivalent legislation.

## Disclaimer

**By using red-run you accept full responsibility for its actions.** This tool runs fully autonomous AI agents that execute offensive security techniques — port scanning, vulnerability exploitation, credential attacks, privilege escalation, and lateral movement — against targets you specify.

- **Authorization required.** Do not use against systems without explicit written permission. Unauthorized access to computer systems is illegal under the CFAA (18 U.S.C. § 1030) and equivalent laws in other jurisdictions.
- **CTF and lab use only.** The current version of the orchestrator is a CTF solver — it runs fully autonomous agents with no OPSEC considerations. Skills are baseline templates built by AI and have not been thoroughly reviewed by human eyes. Expect gaps, false positives, and techniques that need validation before use on real infrastructure. See the [architecture plans](https://blacklanternsecurity.github.io/red-run/architecture/) for the production engagement roadmap.
- **No OPSEC guarantees.** Agents run with no stealth considerations. Assume all activity is logged and detectable. Do not rely on red-run for covert operations.
- **No warranty.** red-run is provided as-is. The authors are not liable for any damage, data loss, legal consequences, or other harm resulting from its use.
