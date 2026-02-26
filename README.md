# red-run

A redteam runbook that turns Claude Code into a pentest and CTF partner.

## What is this?

red-run is a redteam partner that knows the techniques, carries the payloads, and can execute when you allow it to.

In **guided mode** (default), Claude walks you through each attack step, shows you the command it would run, explains what to look for in the output, and asks before executing. You stay in the driver's seat. In **autonomous mode**, Claude runs commands directly, makes triage decisions at forks, and only pauses for destructive or high-OPSEC actions. Autonomous mode is better suited for CTFs and lab environments where OPSEC doesn't matter and you can break things.

Skills auto-trigger based on conversation context. Say "I found a SQL injection with error messages" and the `sql-injection-error` skill activates with embedded payloads for 4 database engines. Say "enumerate this domain" and `ad-discovery` runs BloodHound collection and routes findings to technique skills. No slash commands needed.

### What it actually does for you

- **Holds the decision trees** — which technique to try next based on what you're seeing
- **Carries the payloads** — top 2-3 per variant embedded directly, with deep references for the long tail
- **Builds correct commands** — right flags, right syntax, right tool for the job
- **Tracks engagement state** — what's been tried, what worked, what credentials you have, what leads where
- **Routes between attack paths** — chains findings across skills as the engagement evolves
- **Handles OPSEC trade-offs** — ranks techniques by detection risk, defaults to Kerberos-first auth in AD

### What it doesn't do

- Make scope decisions for you
- Replace your judgment on OPSEC/risk trade-offs in a real engagement

## How it works

### Skill types

- **Orchestrator** — takes a target, runs recon, routes to discovery skills, chains vulnerabilities via state management
- **Discovery skills** — identify vulnerabilities and route to the correct technique skill via decision tree
- **Technique skills** — exploit a specific vulnerability class with embedded payloads and bypass techniques

### Modes

- **Guided** (default) — explain each step, ask before executing, present options at decision forks
- **Autonomous** — execute end-to-end, make triage decisions, report at milestones

Say "switch to autonomous" or "guide me through this" at any point.

&nbsp;
<div align="center"<br><b>⚠️⚠️⚠️⚠️ WARNING ⚠️⚠️⚠️⚠️</b></div>

&nbsp;

Autonomous mode pairs with `claude --dangerously-skip-permissions` (a.k.a. yolo mode). **We do not recommend this.** We do not endorse this. We are not responsible for what happens. You will watch Claude chain four skills, pop a shell, and pivot to a subnet you forgot was in scope. It is exhilarating and horrifying in equal measure. Use guided mode or avoid `--dangerously-skip-permissions` entirely. Remember that skills are really just suggestions. YOU are responsible for containing Claude responsibly on your systems. YOU are liable for any legal consequences under the CFAA or equivalent legislation in your jurisdiction.

&nbsp;

<div align="center"><b>⚠️⚠️⚠️⚠️ WARNING ⚠️⚠️⚠️⚠️</b></div>

&nbsp;

### Inter-skill routing

Skills route to each other at escalation points. When SQL injection leads to credentials, the skill suggests pivoting to privilege escalation. When BloodHound reveals an ACL path, the discovery skill routes to `acl-abuse`. Context (injection point, working payloads, target platform, mode) is passed along.

## Skills

63 skills across 6 categories — see **[SKILLS.md](SKILLS.md)** for the full inventory with technique details and line counts.

| Category | Skills | Coverage |
|----------|--------|----------|
| Web Application | 30 | SQLi, XSS, SSTI, deserialization, SSRF, auth bypass, and more |
| Active Directory | 16 | Kerberos, ADCS, ACLs, GPO, trust, persistence, lateral movement |
| Privilege Escalation | 11 | Windows + Linux enumeration and technique skills |
| Infrastructure | 4 | Network recon, pivoting, container escapes, SMB exploitation |
| Utility | 2 | Orchestrator + retrospective |

## Engagement logging

Skills support optional engagement logging for structured pentests. When an engagement directory exists, skills automatically log activity, findings, and evidence.

```
engagement/
├── scope.md          # Target scope, credentials, rules of engagement
├── state.md          # Compact machine-readable engagement state (snapshot)
├── activity.md       # Chronological action log (append-only)
├── findings.md       # Confirmed vulnerabilities (working tracker)
└── evidence/         # Saved output, responses, dumps
```

- **Guided mode** asks if you want to create an engagement directory at the start
- **Autonomous mode** creates it automatically
- Activity logged at milestones (test confirmed, data extracted, finding discovered)
- Findings numbered with severity, target, technique, impact, and reproduction steps
- No engagement directory = no logging (skills work fine without it)

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

The actionable items are specific. Not "improve the XXE skill" but "add a Custom Sudo Script Analysis section to `linux-sudo-suid-capabilities` covering eval/exec/os.system sinks in sudo-allowed scripts, with constraint-satisfaction methodology." You discuss the findings with Claude, decide what to change, and update the skills right there in the same session.

This is where red-run starts to work differently for you than for anyone else. After a few engagements:

- Your web skills carry the payloads that actually worked against the stacks you see most often
- Your AD skills reflect the tools and authentication workflows you prefer
- Your privesc skills cover the edge cases you've personally hit
- Your discovery skills route to techniques in the order that matches your methodology

The cycle is: **engage → retrospective → improve skills → engage again**. Each pass through the loop makes the library more effective for the specific types of targets, environments, and toolchains you work with. The skills become a living record of your methodology — refined by real engagements, not hypothetical coverage.

## Installation

### Prerequisites

- [uv](https://docs.astral.sh/uv/) — Python package manager (for the MCP skill-router)

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
2. Sets up the **MCP skill-router** — Python venv + ChromaDB index for on-demand technique skill loading
3. Verifies project config (`.mcp.json`, settings)

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

This project was built with the [Trail of Bits Claude Code configuration](https://github.com/trailofbits/claude-code-config) in mind:

- **Sandbox enabled** — bwrap sandboxing with deny rules for sensitive paths
- **Hooks** — Trail of Bits' two default hooks (pre-tool approval + post-tool logging)
- **Autonomous mode** — for CTFs and lab environments where OPSEC doesn't matter
- **MCP skill-router** — 62 technique/discovery skills served on-demand via semantic search (ChromaDB + sentence-transformer embeddings)

### Baseline skills — customize for your workflow

These skills are a **baseline** built from researching publicly available offensive security methodologies. They cover the most common techniques with the top 2-3 payloads per variant. Nearly all skill content was generated by Claude and has not been thoroughly human-reviewed — treat it as a starting point, not a verified reference. Expect errors, gaps, and techniques that need validation against real targets.

You should **modify skills to match your own processes and tools**. Everyone has preferred toolchains, custom scripts, internal playbooks, and engagement-specific workflows that generic skills can't capture. Fork this repo, edit the SKILL.md files directly, and make them yours. The skill format is plain Markdown — no build step, no compilation, changes take effect immediately.

## Status

63 skills, ~36,900 lines.

## Disclaimer

These skills are for use in **authorized security testing, CTF competitions, and educational contexts only**. Do not use them against systems you do not have explicit written permission to test.
