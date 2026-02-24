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

### Web Application (30 skills)

| Skill | Technique | Lines |
|-------|-----------|-------|
| `web-discovery` | Content discovery, parameter fuzzing, vulnerability routing | 682 |
| `sql-injection-union` | UNION-based extraction (MySQL, MSSQL, Postgres, Oracle, SQLite) | 349 |
| `sql-injection-error` | Error-based extraction (EXTRACTVALUE, CONVERT, CAST) | 303 |
| `sql-injection-blind` | Boolean, time-based, OOB blind extraction | 364 |
| `sql-injection-stacked` | Stacked queries, second-order injection, command execution | 367 |
| `xss-reflected` | Reflected XSS, filter/WAF/CSP bypass, impact demonstration | 404 |
| `xss-stored` | Stored + blind XSS, callback setup, self-XSS escalation | 344 |
| `xss-dom` | DOM-based XSS, sources/sinks, postMessage, DOM clobbering | 416 |
| `ssti-jinja2` | Jinja2/Python SSTI (+ Mako, Tornado, Django) | 409 |
| `ssti-twig` | Twig/PHP SSTI (+ Smarty, Blade, Latte) | 386 |
| `ssti-freemarker` | Freemarker/Java SSTI (+ Velocity, SpEL, Thymeleaf, Pebble, Groovy) | 446 |
| `ssrf` | Basic/blind SSRF, cloud metadata, filter bypass, gopher/dict protocol | 564 |
| `lfi` | LFI, PHP wrappers, 8 LFI-to-RCE methods, filter bypass, RFI | 571 |
| `command-injection` | OS command injection, filter bypass, blind techniques, argument injection, credential handoff | 545 |
| `xxe` | Classic/blind/OOB XXE, error-based (remote + local DTD), XInclude, file format injection | 515 |
| `file-upload-bypass` | Extension/content-type/magic byte bypass, config exploitation, polyglots, archive traversal | 549 |
| `deserialization-java` | ysoserial gadget chains, JNDI/Log4Shell, JSF ViewState, WebLogic/JBoss/Jenkins | 449 |
| `deserialization-php` | Magic methods, POP chains, PHPGGC, phar:// polyglots, Laravel APP_KEY, type juggling | 410 |
| `deserialization-dotnet` | ysoserial.net, ViewState/machine keys, JSON.NET TypeNameHandling, .NET Remoting | 455 |
| `jwt-attacks` | alg:none, key confusion, kid injection, jwk/jku spoofing, secret brute force, claim tampering | 581 |
| `request-smuggling` | CL.TE, TE.CL, TE.TE obfuscation, H2 downgrade, h2c smuggling, response desync, cache poisoning | 590 |
| `nosql-injection` | MongoDB operator injection, auth bypass, blind regex extraction, $where JS execution, Mongoose RCE | 544 |
| `ldap-injection` | LDAP filter injection, wildcard auth bypass, blind attribute extraction, filter breakout, AD/OpenLDAP | 615 |
| `idor` | Horizontal/vertical access control bypass, UUID/ObjectId prediction, API IDOR, encoding bypass | 596 |
| `cors-misconfiguration` | Origin reflection, null origin, regex bypass, subdomain trust, wildcard abuse, CORS+IDOR chain | 591 |
| `csrf` | Token bypass, SameSite bypass, JSON CSRF, file upload CSRF, WebSocket CSRF, clickjacking chain | 636 |
| `oauth-attacks` | Redirect URI bypass, state bypass, code theft, token leakage, OIDC attacks, PKCE bypass, ATO chains | 636 |
| `password-reset-poisoning` | Host header poisoning, Referer token leakage, email injection, token weakness, brute-force | 559 |
| `2fa-bypass` | Response manipulation, direct navigation, OTP brute-force, backup codes, OAuth bypass, session attacks | 610 |
| `race-condition` | Limit-overrun, HTTP/2 single-packet, last-byte sync, Turbo Intruder, TOCTOU, rate limit bypass | 742 |

### Active Directory (16 skills)

| Skill | Technique | Lines |
|-------|-----------|-------|
| `ad-discovery` | Domain enumeration (BloodHound, LDAP, NetExec), attack surface mapping, routing to 15 technique skills | 587 |
| `kerberos-roasting` | Kerberoasting + AS-REP Roasting + Timeroasting, targeted kerberoasting via ACL abuse | 480 |
| `password-spraying` | Lockout-safe domain spray (Kerberos/NTLM/OWA), policy enumeration, smart password generation | 537 |
| `pass-the-hash` | PTH, Over-Pass-the-Hash, Pass-the-Key (AES), Pass-the-Ticket, lateral movement tools | 500 |
| `kerberos-delegation` | Unconstrained (TGT harvesting + coercion), Constrained (S4U + SPN swapping), RBCD | 533 |
| `kerberos-ticket-forging` | Golden, Silver, Diamond, Sapphire tickets + Pass-the-Ticket injection | 484 |
| `acl-abuse` | GenericAll/Write, WriteDACL, WriteOwner, shadow credentials, AdminSDHolder persistence | 578 |
| `adcs-template-abuse` | ESC1/2/3/6 — SAN manipulation, any-purpose EKU, enrollment agent, EDITF flag abuse | 486 |
| `adcs-access-and-relay` | ESC4/5/7/8/11 — template/CA ACL abuse, NTLM relay to HTTP/RPC enrollment | 520 |
| `adcs-persistence` | ESC9-15, Golden Certificate, certificate theft (DPAPI/CAPI/CNG), cert mapping persistence | 629 |
| `auth-coercion-relay` | PetitPotam/PrinterBug/DFSCoerce coercion, NTLM relay (LDAP/SMB/ADCS/MSSQL), Kerberos relay, LLMNR/NBNS poisoning | 632 |
| `credential-dumping` | DCSync, NTDS extraction, SAM dump, LAPS (legacy + Windows), gMSA/GoldenGMSA, dMSA BadSuccessor, DSRM | 626 |
| `gpo-abuse` | GPO exploitation (SharpGPOAbuse/pyGPOAbuse/GroupPolicyBackdoor), SYSVOL script poisoning, GPP passwords | 555 |
| `trust-attacks` | Trust enumeration, SID history injection (child to forest root), inter-realm TGT forging, PAM trust/shadow principals, cross-forest abuse | 488 |
| `sccm-exploitation` | SCCM enumeration (sccmhunter/SharpSCCM), NAA credential extraction, MP relay to MSSQL, client push relay, PXE boot harvesting, app deployment | 550 |
| `ad-persistence` | DCShadow, Skeleton Key, custom SSP (mimilib/memssp), security descriptor backdoors, ADFS Golden SAML, SID history persistence, golden certificate | 617 |

All AD skills follow a **Kerberos-first authentication** convention — commands default to ccache-based Kerberos auth to avoid NTLM detection signatures (Event 4776, CrowdStrike Identity Module). Exception: relay/coercion attacks are inherently NTLM/network-level.

### Privilege Escalation (11 skills)

| Skill | Technique | Lines |
|-------|-----------|-------|
| `windows-discovery` | WinPEAS/PowerUp/Seatbelt/Watson enumeration, OPSEC-safe privilege checks, routing to 5 technique skills | 590 |
| `windows-token-impersonation` | Potato family (7+ variants by OS version), SeDebug/SeBackup/SeRestore/SeLoadDriver/SeManageVolume exploitation, FullPowers | 524 |
| `windows-service-dll-abuse` | Unquoted paths, weak service perms, DLL search order hijacking, DLL proxying, COM hijacking, service triggers, auto-updater abuse | 557 |
| `windows-uac-bypass` | Fodhelper/eventvwr/sdclt/SilentCleanup/CMSTP/WSReset, COM hijacking, AlwaysInstallElevated MSI, autorun exploitation | 585 |
| `windows-credential-harvesting` | HiveNightmare, DPAPI (SharpDPAPI/mimikatz/dpapi.py), browser creds, PS history, unattend files, vaults, cloud creds | 563 |
| `windows-kernel-exploits` | PrintNightmare/EternalBlue/MS16-032/MS15-051, BYOVD/loldrivers.io, privileged file write/delete, named pipes, leaked handles | 641 |
| `linux-discovery` | LinPEAS/LinEnum/pspy/lse enumeration, system info, sudo/SUID/capabilities/cron assessment, routing to 4 technique skills | 664 |
| `linux-sudo-suid-capabilities` | Sudo NOPASSWD/LD_PRELOAD/CVE-2021-3156/CVE-2019-14287, SUID GTFOBins, shared object injection, 20+ Linux capabilities | 631 |
| `linux-cron-service-abuse` | Cron script hijack, tar/chown/rsync wildcard injection, systemd timer/service abuse, D-Bus command injection, PwnKit/CVE-2021-3560, Unix sockets | 683 |
| `linux-file-path-abuse` | Writable /etc/passwd+shadow+sudoers, NFS no_root_squash, Docker/LXD/disk group escape, library hijacking, PATH hijack, profile injection | 861 |
| `linux-kernel-exploits` | DirtyPipe/DirtyCow/GameOver(lay)/10+ CVEs, exploit suggesters, attackbox-first transfer, restricted shell escape, chroot escape, container kernel escape | 1025 |

### Infrastructure (4 skills)

| Skill | Technique | Lines |
|-------|-----------|-------|
| `network-recon` | Passive recon, host discovery, nmap full scan, 20+ protocol service enumeration with quick wins, OS fingerprinting, vuln scanning, routing | 974 |
| `pivoting-tunneling` | SSH tunneling (L/R/D/J/sshuttle/VPN), Ligolo-ng, Chisel, socat, Windows pivoting, DNS/ICMP/HTTP tunneling, multi-hop, tool compatibility | 1165 |
| `container-escapes` | Docker socket/privileged/cgroup escape, sensitive mounts, capability abuse, K8s SA token/RBAC/etcd/kubelet exploitation, container CVEs, cloud metadata | 1041 |
| `smb-exploitation` | MS08-067, MS17-010/EternalBlue, MS09-050, SMBGhost, OS compatibility matrix, Metasploit target selection, standalone Python fallback | 417 |

### Utility (2 skills)

| Skill | Purpose | Lines |
|-------|---------|-------|
| `orchestrator` | Takes a target, runs recon, routes to discovery skills, chains vulnerabilities via state management | 462 |
| `retrospective` | Post-engagement lessons-learned analysis, skill routing gaps, actionable improvements | 247 |

### Planned

- **Active Directory** (6 extended) — ADIDNS poisoning, DCOM lateral movement, RODC exploitation, named CVEs (NoPAC/PrintNightmare/ZeroLogon), MSSQL AD abuse, deployment targets (MDT/WSUS/SCOM)
- **Infrastructure** (extended) — cloud (AWS/Azure), CI/CD
- **Red Team** — C2, initial access, evasion, persistence, credential dumping
- **Supplemental** — hash cracking, shell cheatsheet, database attacks, binary exploitation

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

### Install

```bash
# Symlink-based (edits in repo reflect immediately)
./install.sh

# Copy-based (for machines without the repo)
./install.sh --copy

# Uninstall
./uninstall.sh
```

Skills install to `~/.claude/skills/red-run-<skill-name>/SKILL.md`.

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
- **No MCP servers** — skills work with vanilla Claude Code (MCP integration may be added later)

### Baseline skills — customize for your workflow

These skills are a **baseline** built from researching publicly available offensive security methodologies. They cover the most common techniques with the top 2-3 payloads per variant. Nearly all skill content was generated by Claude and has not been thoroughly human-reviewed — treat it as a starting point, not a verified reference. Expect errors, gaps, and techniques that need validation against real targets.

You should **modify skills to match your own processes and tools**. Everyone has preferred toolchains, custom scripts, internal playbooks, and engagement-specific workflows that generic skills can't capture. Fork this repo, edit the SKILL.md files directly, and make them yours. The skill format is plain Markdown — no build step, no compilation, changes take effect immediately.

## Status

63 skills built, ~35,600 lines.

## Disclaimer

These skills are for use in **authorized security testing, CTF competitions, and educational contexts only**. Do not use them against systems you do not have explicit written permission to test.
