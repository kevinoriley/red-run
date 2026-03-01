# red-run

A redteam runbook that turns Claude Code into a pentester.

## What is this?

red-run is a redteam partner that knows the techniques, carries the payloads, and can execute when you allow it to.

In **guided mode** (default), the orchestrator pauses at routing decisions — it presents the attack surface, available paths, and lets you choose which skill to invoke next. Once a skill is routed to an agent, the agent runs end-to-end. Individual commands within the agent go through Claude Code's normal permission prompts, so you still approve each command that touches the target.

In **autonomous mode**, the orchestrator routes to skills automatically and makes triage decisions without asking. Combine with `--dangerously-skip-permissions` for fully unattended execution. Better suited for CTFs and lab environments where OPSEC doesn't matter and you can break things.

&nbsp;
<div align="center"><br><b>⚠️⚠️⚠️⚠️ WARNING ⚠️⚠️⚠️⚠️</b></div>

&nbsp;

Autonomous mode pairs with `claude --dangerously-skip-permissions` (a.k.a. yolo mode). **We do not recommend this.** We do not endorse this. We are not responsible for what happens. Claude will chain four skills, pop a shell, and pivot to a subnet no one told you about. It is exhilarating and horrifying in equal measure. <!-- It's incredibly fun to watch. --> Use guided mode or avoid `--dangerously-skip-permissions` entirely. Remember that skills are really just suggestions. YOU are responsible for containing Claude responsibly on your systems. YOU are liable for any legal consequences under the CFAA or equivalent legislation in your jurisdiction.

&nbsp;

<div align="center"><b>⚠️⚠️⚠️⚠️ WARNING ⚠️⚠️⚠️⚠️</b></div>

&nbsp;

## Architecture

The `orchestrator` is a Claude Code skill intended to run with Opus 4.6 in extended thinking mode. It runs in the main conversation thread. It delegates skill execution to **agents** — focused Sonnet agents with MCP access that each handle one skill per invocation. This keeps context isolated (each agent starts fresh) while the `orchestrator` maintains the big picture via a SQLite state database.

**Agents:**

| Agent | Domain | Key capability |
|-------|--------|----------------|
| `network-recon-agent` | Network recon + exploitation | nmap MCP + shell-server |
| `web-discovery-agent` | Web application discovery | Enumeration, tech fingerprinting, vuln identification |
| `web-exploit-agent` | Web application exploitation | shell-server for RCE → reverse shell |
| `ad-discovery-agent` | AD enumeration | BloodHound, LDAP, attack surface mapping |
| `ad-exploit-agent` | AD exploitation | Kerberos-first auth + shell-server |
| `linux-privesc-agent` | Linux privilege escalation | shell-server for catching escalated shells |
| `windows-privesc-agent` | Windows privilege escalation | shell-server for catching escalated shells |
| `evasion-agent` | AV/EDR evasion | Custom payload compilation, AMSI bypass |

Each invocation: agent loads one skill, follows the methodology, saves evidence, and returns findings. The `orchestrator` records state changes and routes to the next skill.

**MCP servers:**
- **skill-router** — semantic search + skill loading via ChromaDB + sentence-transformer embeddings
- **nmap-server** — runs nmap inside a Docker container, returns parsed JSON with input validation
- **shell-server** — TCP listener, reverse shell, and local interactive process manager
- **browser-server** — headless Chromium via Playwright for web interaction (CSRF tokens, JS-rendered forms, session management)
- **state-server** — SQLite engagement state

### Persistent sessions via MCP

Claude Code’s Bash tool runs each command as a separate process — there’s no persistent shell session. This means interactive tools (evil-winrm, ssh, psexec.py) lose state between calls, and reverse shells from RCE have nowhere to connect back.

The **shell-server** MCP solves this with two session types:

- **`start_listener`** — catches inbound reverse shells. Agents open a catcher, send a reverse shell payload through whatever RCE they’ve achieved, then interact via `send_command()`.
- **`start_process`** — spawns local interactive tools in a persistent PTY. When you have credentials and a service port open, agents call `start_process(command="evil-winrm -i TARGET -u admin -p pass")` and drive the session through `send_command()`. Evil-winrm’s built-in `upload`/`download` commands also make it the preferred file transfer method for Windows targets.

Both session types persist across tool calls, support prompt detection, and save transcripts to `engagement/evidence/` on close.

### Inter-skill routing

The `orchestrator` makes every routing decision by spawning the appropriate agent with a skill name and context. When an LFI reads Tomcat credentials, the `orchestrator` spawns `web-exploit-agent` with `tomcat-manager-deploy` to get a shell. When BloodHound reveals an ACL path, it spawns `ad-exploit-agent` with `acl-abuse`. Context (injection point, working payloads, target platform, mode) is passed in the agent's Task prompt.

## Skills

67 skills across 7 categories — see **[SKILLS.md](SKILLS.md)** for the full inventory with technique details and line counts. These are baseline offensive security skill templates researched and created by Claude.

| Category | Skills | Coverage |
|----------|--------|----------|
| Web Application | 33 | SQLi, XSS, SSTI, deserialization, SSRF, auth bypass, and more |
| Active Directory | 16 | Kerberos, ADCS, ACLs, GPO, trust, persistence, lateral movement |
| Privilege Escalation | 11 | Windows + Linux enumeration and technique skills |
| Infrastructure | 4 | Network recon, pivoting, container escapes, SMB exploitation |
| Evasion | 1 | AV/EDR bypass, custom payloads, AMSI bypass |
| Utility | 2 | Orchestrator + retrospective |

## Engagement logging

red-run performs engagement logging for structured pentests and state tracking. The `orchestrator` creates the engagement directory on activation, and skills automatically log activity, findings, and evidence.

```
engagement/
├── scope.md          # Target scope, credentials, rules of engagement
├── state.db          # SQLite engagement state (managed via MCP state-server)
├── activity.md       # Chronological action log (`orchestrator` writes)
├── findings.md       # Confirmed vulnerabilities (`orchestrator` writes)
└── evidence/         # Saved output, responses, dumps (agents write)
    └── logs/         # Agent JSONL transcripts (captured automatically)
```

- Activity logged at milestones (test confirmed, data extracted, finding discovered)
- Findings numbered with severity, target, technique, impact, and reproduction steps
- Agent JSONL transcripts automatically captured via a `SubagentStop` hook — every tool call, decision, and error from each agent is preserved for retrospective analysis

### State management

Large engagements generate more state than fits in a single conversation context. The **state-server MCP** solves this — a SQLite database that persists across sessions and context compactions, with structured queries for targets, credentials, access, vulnerabilities, pivot paths, and blocked items.

The `orchestrator` is the sole writer of engagement state. Agents call `get_state_summary()` (read-only) on activation and report findings in their return summary. The `orchestrator` parses these summaries and calls structured write tools (`add_target`, `add_credential`, `add_vuln`, etc.) to update state. This enforces that all routing decisions flow through the `orchestrator`.

| Table | Contents |
|-------|----------|
| targets + ports | Hosts, IPs, OS, ports, services (normalized) |
| credentials | Username/password/hash/token pairs, where tested |
| access | Current footholds — shells, sessions, tokens, DB access |
| vulns | Confirmed vulns with status: `found`, `active`, `done` |
| pivot_map | What leads where — vuln X gives access Y, creds Z work on host W |
| blocked | What was tried and why it failed |

## The retrospective loop

The skills in this repo are a starting point. The `retrospective` skill is what makes them yours.

After an engagement, run a retrospective. Claude reads the engagement directory — `activity.md`, `state.db`, `findings.md`, and the agent JSONL transcripts in `evidence/logs/` — and analyzes what happened. It reviews every skill routing decision, identifies gaps in payloads and methodology, flags techniques that were done by hand instead of through a skill, and produces a prioritized list of improvements: skill updates, new skills to build, routing fixes.

The actionable items are specific. Not "improve the SQL injection skill" but "`sql-injection-blind` only carried MySQL `SLEEP()` payloads — add MSSQL `WAITFOR DELAY` and PostgreSQL `pg_sleep()` for time-based detection." You discuss the findings with Claude, decide what to change, and update the skills right there in the same session.

This is where red-run starts to work differently for you than for anyone else. After a few engagements:

- Your web skills carry the payloads that actually worked against the stacks you see most often
- Your AD skills reflect the tools and authentication workflows you prefer
- Your privesc skills cover the edge cases you've personally hit
- Your discovery skills route to techniques in the order that matches your methodology

The cycle is: **engage → retrospective → improve skills → engage again**. Each pass through the loop makes the library more effective for the specific types of targets, environments, and toolchains you work with. The skills become a living record of your methodology — refined by real engagements, not hypothetical coverage.

## Installation

### Prerequisites

- Linux VM with your pentesting tools installed
- [uv](https://docs.astral.sh/uv/) — Python package manager (for MCP servers)
- [Docker](https://docs.docker.com/engine/install/) — the nmap MCP server runs scans inside a container (the install script builds the image)
- [Playwright](https://playwright.dev/) system dependencies — the browser MCP server uses headless Chromium (the install script runs `playwright install chromium` automatically)

### Install

```bash
# Symlink-based (edits in repo reflect immediately)
./install.sh

# Copy-based (for machines without the repo)
./install.sh --copy

# Uninstall
./uninstall.sh
```

The installer:
1. Installs `orchestrator` as a native Claude Code skill (`~/.claude/skills/`)
2. Installs **agents** to `~/.claude/agents/`
3. Sets up **MCP servers** — `skill-router` (ChromaDB + embeddings), `nmap-server`, `shell-server`, `browser-server` (Chromium), `state-server`
4. Verifies project config (`.mcp.json`, settings, Docker for nmap)

The repo must stay in place — the MCP server reads skills from `skills/` at runtime.

## Running Claude Code for pentesting

### Run inside a VM

Always run red-run from a VM or dedicated pentesting machine. Skills execute commands, transfer tools, and interact with targets — you want network isolation and a disposable environment. A purpose-built Linux VM with your pentesting tools and Claude Code installed is the intended setup.

### Sandbox and network commands

Claude Code's bwrap sandbox blocks network socket creation. Since pentesting skills are almost entirely network commands, every tool (`nmap`, `netexec`, `sqlmap`, etc.) will fail on first attempt, then retry with sandbox disabled — doubling execution time.

**Fix:** Add a network tools exception to your global `~/.claude/CLAUDE.md` that tells Claude to proactively use `dangerouslyDisableSandbox: true` for network-touching commands. Local-only commands (file I/O, hash cracking, parsing) should keep sandbox enabled. Example:

```markdown
## Sandbox

Always use `dangerouslyDisableSandbox: true` for commands that make network
connections: nmap, ping, netexec, curl, wget, sqlmap, impacket-*, certipy,
bloodyAD, ffuf, nuclei, httpx, responder, tcpdump, ssh, smbclient, ldapsearch,
crackmapexec, gobuster, hydra, chisel, ligolo, socat, nc, bbot, nikto, wfuzz,
feroxbuster, enum4linux-ng, rpcclient, scp, rsync, proxychains,
python3 -m http.server.

For everything else (file reads, writes, local processing, hash cracking),
keep sandbox enabled.
```

### Recommended configuration

- **Claude Code** installed in the VM — skills execute commands directly, so Claude needs to be where the tools are
- **[Trail of Bits Claude Code configuration](https://github.com/trailofbits/claude-code-config)** — sandbox, hooks, and guardrails this project was built around

### Baseline skills — customize for your workflow

These skills are a **baseline** built from researching publicly available offensive security methodologies. They cover the most common techniques with the top 2-3 payloads per variant. Nearly all skill content was generated by Claude and has not been thoroughly human-reviewed — treat it as a starting point, not a verified reference. Expect errors, gaps, and techniques that need validation against real targets.

## Running tests

```bash
# Skill + agent lint tests
cd tools/skill-router && uv run --only-group lint pytest tests/test_skills.py tests/test_agents.py -v

# MCP server tests (run from each server directory)
cd tools/nmap-server && uv run pytest tests/ -v
cd tools/shell-server && uv run pytest tests/ -v
cd tools/browser-server && uv run pytest tests/ -v
cd tools/state-server && uv run pytest tests/ -v
```

CI runs these automatically on pull requests — see `.github/workflows/ci.yml`.

## Disclaimer

These skills are for use in **authorized security testing, CTF competitions, and educational contexts only**. Do not use them against systems you do not have explicit written permission to test.
