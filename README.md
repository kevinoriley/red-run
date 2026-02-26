# red-run

A redteam runbook that turns Claude Code into a pentester.

## What is this?

red-run is a redteam partner that knows the techniques, carries the payloads, and can execute when you allow it to.

In **guided mode** (default), Claude walks you through each attack step, shows you the command it would run, explains what to look for in the output, and asks before executing. You stay in the driver's seat (most of the time...) and can course-correct when Claude drifts.

In **autonomous mode**, Claude runs commands directly, makes triage decisions at forks, and rarely pauses for your input. Autonomous mode is better suited for CTFs and lab environments where OPSEC doesn't matter and you can break things.

## How it works

### Skill types

- **Orchestrator** — routes to discovery skills, chains vulnerabilities via state management
- **Discovery skills** — identify vulnerabilities and route to the correct technique skill
- **Technique skills** — exploit a specific vulnerability class with embedded payloads and bypass techniques

### Modes

- **Guided** (default) — explain each step, ask before executing, present options at decision forks
- **Autonomous** — execute end-to-end, make triage decisions, report at milestones

Say "switch to autonomous" or "guide me through this" at any point.

&nbsp;
<div align="center"><br><b>⚠️⚠️⚠️⚠️ WARNING ⚠️⚠️⚠️⚠️</b></div>

&nbsp;

Autonomous mode pairs with `claude --dangerously-skip-permissions` (a.k.a. yolo mode). **We do not recommend this.** We do not endorse this. We are not responsible for what happens. You will watch Claude chain four skills, pop a shell, and pivot to a subnet you forgot was in scope. It is exhilarating and horrifying in equal measure. Use guided mode or avoid `--dangerously-skip-permissions` entirely. Remember that skills are really just suggestions. YOU are responsible for containing Claude responsibly on your systems. YOU are liable for any legal consequences under the CFAA or equivalent legislation in your jurisdiction.

&nbsp;

<div align="center"><b>⚠️⚠️⚠️⚠️ WARNING ⚠️⚠️⚠️⚠️</b></div>

&nbsp;

### Architecture

The **orchestrator** is a native Claude Code skill that runs in the main conversation thread. It delegates skill execution to **custom domain subagents** — focused agents with MCP access that each handle one skill per invocation. This keeps context isolated (each agent starts fresh) and eliminates the sudo nmap handoff bottleneck.

**Subagents:**

| Agent | Domain | Key capability |
|-------|--------|----------------|
| `network-recon-agent` | Network recon + exploitation | nmap MCP + shell-server |
| `web-agent` | Web application security | shell-server for RCE → reverse shell |
| `ad-agent` | Active Directory attacks | Kerberos-first auth + shell-server |
| `privesc-agent` | Privilege escalation | shell-server for catching escalated shells |

Each invocation: agent loads one skill, follows the methodology, updates engagement files, returns findings. The orchestrator reads state and routes to the next skill. If subagents aren't installed, the orchestrator falls back to inline skill execution.

**MCP servers:**
- **skill-router** — semantic search + skill loading via ChromaDB + sentence-transformer embeddings
- **nmap-server** — wraps `sudo nmap`, returns parsed JSON (no manual handoff)
- **shell-server** — TCP listener + reverse shell session manager (solves the persistent shell problem)

### Reverse shells via MCP

Claude Code's Bash tool runs each command as a separate process — there's no persistent shell session. This means interactive reverse shells, privilege escalation tools that spawn new shells (PwnKit, kernel exploits, sudo abuse), and anything requiring a connected session simply don't work through normal tool calls.

The **shell-server** MCP solves this. It manages TCP listeners and reverse shell sessions as a long-lived server process. Subagents call `start_listener(port=4444)` to open a catcher, send a reverse shell payload through whatever RCE they've achieved, then interact with the shell via `send_command()`. Sessions persist across tool calls, support PTY upgrades for interactive programs, and save transcripts to `engagement/evidence/` on close.

All RCE-producing technique skills (24 of them) prefer catching reverse shells through shell-server over inline command execution. This is especially critical for privilege escalation — you can't catch a PwnKit root shell through a webshell.

### Inter-skill routing

The orchestrator makes every routing decision. When SQL injection leads to credentials, the orchestrator spawns the next agent with the appropriate skill. When BloodHound reveals an ACL path, the orchestrator routes to `acl-abuse` via the AD agent. Context (injection point, working payloads, target platform, mode) is passed in the agent's Task prompt.

## Skills

65 skills across 6 categories — see **[SKILLS.md](SKILLS.md)** for the full inventory with technique details and line counts.

| Category | Skills | Coverage |
|----------|--------|----------|
| Web Application | 32 | SQLi, XSS, SSTI, deserialization, SSRF, auth bypass, and more |
| Active Directory | 16 | Kerberos, ADCS, ACLs, GPO, trust, persistence, lateral movement |
| Privilege Escalation | 11 | Windows + Linux enumeration and technique skills |
| Infrastructure | 4 | Network recon, pivoting, container escapes, SMB exploitation |
| Utility | 2 | Orchestrator + retrospective |

## Engagement logging

Skills carry out engagement logging for structured pentests and state tracking. When an engagement directory exists, skills automatically log activity, findings, and evidence.

```
engagement/
├── scope.md          # Target scope, credentials, rules of engagement
├── state.md          # Compact machine-readable engagement state (snapshot)
├── activity.md       # Chronological action log (append-only)
├── findings.md       # Confirmed vulnerabilities (working tracker)
└── evidence/         # Saved output, responses, dumps
```

- Activity logged at milestones (test confirmed, data extracted, finding discovered)
- Findings numbered with severity, target, technique, impact, and reproduction steps

### State management

Large engagements generate more state than fits in a single conversation context. `state.md` solves this — a compact, machine-readable snapshot of the current engagement that persists across sessions and context compactions.

| Section | Contents |
|---------|----------|
| Targets | Hosts, IPs, URLs, ports, tech stack |
| Credentials | Username/password/hash/token pairs, where they work |
| Access | Current footholds — shells, sessions, tokens, DB access |
| Vulns | One-liner per confirmed vuln: `[found]`, `[active]`, `[done]` |
| Pivot Map | What leads where — vuln X gives access Y, creds Z work on host W |
| Blocked | What was tried and why it failed |

Every skill reads `state.md` on activation and writes back on completion. The orchestrator uses `state.md` + Pivot Map to chain vulnerabilities toward maximum impact. Kept under ~200 lines — one-liner per item, current state not history.

## The retrospective loop

The skills in this repo are a starting point. The retrospective skill is what makes them yours.

After an engagement, run a retrospective. Claude reads the engagement directory — `activity.md`, `state.md`, `findings.md` — and analyzes what happened. It reviews every skill routing decision, identifies gaps in payloads and methodology, flags techniques that were done by hand instead of through a skill, and produces a prioritized list of improvements: skill updates, new skills to build, routing fixes.

The actionable items are specific. Not "improve the SQL injection skill" but "`sql-injection-blind` only carried MySQL `SLEEP()` payloads — add MSSQL `WAITFOR DELAY` and PostgreSQL `pg_sleep()` for time-based detection." You discuss the findings with Claude, decide what to change, and update the skills right there in the same session.

This is where red-run starts to work differently for you than for anyone else. After a few engagements:

- Your web skills carry the payloads that actually worked against the stacks you see most often
- Your AD skills reflect the tools and authentication workflows you prefer
- Your privesc skills cover the edge cases you've personally hit
- Your discovery skills route to techniques in the order that matches your methodology

The cycle is: **engage → retrospective → improve skills → engage again**. Each pass through the loop makes the library more effective for the specific types of targets, environments, and toolchains you work with. The skills become a living record of your methodology — refined by real engagements, not hypothetical coverage.

## Installation

### Prerequisites

- [uv](https://docs.astral.sh/uv/) — Python package manager (for MCP servers)
- Passwordless `sudo nmap` — for the nmap MCP server (see `tools/nmap-server/README.md`)
- A port available for listening (e.g., 4444) — for the shell-server to catch reverse shells

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
1. Installs the **orchestrator** as a native Claude Code skill (`~/.claude/skills/`)
2. Installs **custom subagents** to `~/.claude/agents/`
3. Sets up **MCP servers** — skill-router (ChromaDB + embeddings), nmap-server (sudo nmap wrapper), shell-server (reverse shell manager)
4. Verifies project config (`.mcp.json`, settings, sudo nmap)

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

- **Linux VM** with your pentesting tools installed (Kali, Parrot, or a custom build)
- **Claude Code** installed in the VM — skills execute commands directly, so Claude needs to be where the tools are
- **Pentesting tools** — nmap, netexec, impacket, sqlmap, ffuf, hashcat, etc. Skills reference tools by name; a skill→tool index is coming
- **[Trail of Bits Claude Code configuration](https://github.com/trailofbits/claude-code-config)** — sandbox, hooks, and guardrails this project was built around

### Baseline skills — customize for your workflow

These skills are a **baseline** built from researching publicly available offensive security methodologies. They cover the most common techniques with the top 2-3 payloads per variant. Nearly all skill content was generated by Claude and has not been thoroughly human-reviewed — treat it as a starting point, not a verified reference. Expect errors, gaps, and techniques that need validation against real targets.

## Status

65 skills, ~40,400 lines.

## Disclaimer

These skills are for use in **authorized security testing, CTF competitions, and educational contexts only**. Do not use them against systems you do not have explicit written permission to test.
