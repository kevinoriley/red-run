# red-run

An operator's companion for penetration testing and CTF work, built as a Claude Code skill library.

## What is this?

red-run turns Claude Code into a pentest partner that knows the techniques, carries the payloads, and can execute when you tell it to. It's not a push-button autopwn tool and it's not a passive reference doc — it sits between the two.

In **guided mode** (default), Claude walks you through each attack step, shows you the command it would run, explains what to look for in the output, and asks before executing. You stay in the driver's seat. In **autonomous mode**, Claude runs commands directly, makes triage decisions at forks, and only pauses for destructive or high-OPSEC actions. Autonomous is better suited for CTFs and lab environments where OPSEC doesn't matter.

Skills auto-trigger based on conversation context. Say "I found a SQL injection with error messages" and the `sql-injection-error` skill activates with embedded payloads for 4 database engines. Say "enumerate this domain" and `ad-attack-discovery` runs BloodHound collection and routes findings to technique skills. No slash commands needed.

### What it actually does for you

- **Holds the decision trees** — which technique to try next based on what you're seeing
- **Carries the payloads** — top 2-3 per variant embedded directly, with deep references for the long tail
- **Builds correct commands** — right flags, right syntax, right tool for the job
- **Tracks engagement state** — what's been tried, what worked, what credentials you have, what leads where
- **Routes between attack paths** — SQL injection leads to credentials, routes to privilege escalation
- **Handles OPSEC trade-offs** — ranks techniques by detection risk, defaults to Kerberos-first auth in AD

### What it doesn't do

- Make scope decisions for you
- Replace your judgment on OPSEC/risk trade-offs in a real engagement
- Run without your approval in guided mode (the default)

## How it works

### Skill types

- **Orchestrator** — takes a target, runs recon, routes to discovery skills, chains vulnerabilities via state management
- **Discovery skills** — identify vulnerabilities and route to the correct technique skill via decision tree
- **Technique skills** — exploit a specific vulnerability class with embedded payloads and bypass techniques

### Modes

- **Guided** (default) — explain each step, ask before executing, present options at decision forks
- **Autonomous** — execute end-to-end, make triage decisions, report at milestones

Say "switch to autonomous" or "guide me through this" at any point.

### Inter-skill routing

Skills route to each other at escalation points. When SQL injection leads to credentials, the skill suggests pivoting to privilege escalation. When BloodHound reveals an ACL path, the discovery skill routes to `acl-abuse`. Context (injection point, working payloads, target platform, mode) is passed along.

## Skills

### Web Application (29 skills)

| Skill | Technique | Lines |
|-------|-----------|-------|
| `web-vuln-discovery` | Content discovery, parameter fuzzing, vulnerability routing | 299 |
| `sql-injection-union` | UNION-based extraction (MySQL, MSSQL, Postgres, Oracle, SQLite) | 287 |
| `sql-injection-error` | Error-based extraction (EXTRACTVALUE, CONVERT, CAST) | 240 |
| `sql-injection-blind` | Boolean, time-based, OOB blind extraction | 302 |
| `sql-injection-stacked` | Stacked queries, second-order injection, command execution | 306 |
| `xss-reflected` | Reflected XSS, filter/WAF/CSP bypass, impact demonstration | 343 |
| `xss-stored` | Stored + blind XSS, callback setup, self-XSS escalation | 282 |
| `xss-dom` | DOM-based XSS, sources/sinks, postMessage, DOM clobbering | 355 |
| `ssti-jinja2` | Jinja2/Python SSTI (+ Mako, Tornado, Django) | 345 |
| `ssti-twig` | Twig/PHP SSTI (+ Smarty, Blade, Latte) | 322 |
| `ssti-freemarker` | Freemarker/Java SSTI (+ Velocity, SpEL, Thymeleaf, Pebble, Groovy) | 382 |
| `ssrf` | Basic/blind SSRF, cloud metadata, filter bypass, gopher/dict protocol | 503 |
| `lfi` | LFI, PHP wrappers, 8 LFI-to-RCE methods, filter bypass, RFI | 536 |
| `command-injection` | OS command injection, filter bypass, blind techniques, argument injection | 486 |
| `xxe` | Classic/blind/OOB XXE, error-based (remote + local DTD), XInclude, file format injection | 466 |
| `file-upload-bypass` | Extension/content-type/magic byte bypass, config exploitation, polyglots, archive traversal | 506 |
| `deserialization-java` | ysoserial gadget chains, JNDI/Log4Shell, JSF ViewState, WebLogic/JBoss/Jenkins | 404 |
| `deserialization-php` | Magic methods, POP chains, PHPGGC, phar:// polyglots, Laravel APP_KEY, type juggling | 365 |
| `deserialization-dotnet` | ysoserial.net, ViewState/machine keys, JSON.NET TypeNameHandling, .NET Remoting | 408 |
| `jwt-attacks` | alg:none, key confusion, kid injection, jwk/jku spoofing, secret brute force, claim tampering | 533 |
| `request-smuggling` | CL.TE, TE.CL, TE.TE obfuscation, H2 downgrade, h2c smuggling, response desync, cache poisoning | 570 |
| `nosql-injection` | MongoDB operator injection, auth bypass, blind regex extraction, $where JS execution, Mongoose RCE | 519 |
| `idor` | Horizontal/vertical access control bypass, UUID/ObjectId prediction, API IDOR, encoding bypass | 569 |
| `cors-misconfiguration` | Origin reflection, null origin, regex bypass, subdomain trust, wildcard abuse, CORS+IDOR chain | 565 |
| `csrf` | Token bypass, SameSite bypass, JSON CSRF, file upload CSRF, WebSocket CSRF, clickjacking chain | 609 |
| `oauth-attacks` | Redirect URI bypass, state bypass, code theft, token leakage, OIDC attacks, PKCE bypass, ATO chains | 610 |
| `password-reset-poisoning` | Host header poisoning, Referer token leakage, email injection, token weakness, brute-force | 533 |
| `2fa-bypass` | Response manipulation, direct navigation, OTP brute-force, backup codes, OAuth bypass, session attacks | 585 |
| `race-condition` | Limit-overrun, HTTP/2 single-packet, last-byte sync, Turbo Intruder, TOCTOU, rate limit bypass | 719 |

### Active Directory (13 skills)

| Skill | Technique | Lines |
|-------|-----------|-------|
| `ad-attack-discovery` | Domain enumeration (BloodHound, LDAP, NetExec), attack surface mapping, routing to 15 technique skills | 511 |
| `kerberos-roasting` | Kerberoasting + AS-REP Roasting + Timeroasting, targeted kerberoasting via ACL abuse | 436 |
| `password-spraying` | Lockout-safe domain spray (Kerberos/NTLM/OWA), policy enumeration, smart password generation | 508 |
| `pass-the-hash` | PTH, Over-Pass-the-Hash, Pass-the-Key (AES), Pass-the-Ticket, lateral movement tools | 473 |
| `kerberos-delegation` | Unconstrained (TGT harvesting + coercion), Constrained (S4U + SPN swapping), RBCD | 508 |
| `kerberos-ticket-forging` | Golden, Silver, Diamond, Sapphire tickets + Pass-the-Ticket injection | 463 |
| `acl-abuse` | GenericAll/Write, WriteDACL, WriteOwner, shadow credentials, AdminSDHolder persistence | 554 |
| `adcs-template-abuse` | ESC1/2/3/6 — SAN manipulation, any-purpose EKU, enrollment agent, EDITF flag abuse | 457 |
| `adcs-access-and-relay` | ESC4/5/7/8/11 — template/CA ACL abuse, NTLM relay to HTTP/RPC enrollment | 475 |
| `adcs-persistence` | ESC9-15, Golden Certificate, certificate theft (DPAPI/CAPI/CNG), cert mapping persistence | 611 |
| `auth-coercion-relay` | PetitPotam/PrinterBug/DFSCoerce coercion, NTLM relay (LDAP/SMB/ADCS/MSSQL), Kerberos relay, LLMNR/NBNS poisoning | 581 |
| `credential-dumping` | DCSync, NTDS extraction, SAM dump, LAPS (legacy + Windows), gMSA/GoldenGMSA, dMSA BadSuccessor, DSRM | 603 |
| `gpo-abuse` | GPO exploitation (SharpGPOAbuse/pyGPOAbuse/GroupPolicyBackdoor), SYSVOL script poisoning, GPP passwords | 532 |

All AD skills follow a **Kerberos-first authentication** convention — commands default to ccache-based Kerberos auth to avoid NTLM detection signatures (Event 4776, CrowdStrike Identity Module). Exception: relay/coercion attacks are inherently NTLM/network-level.

### Planned

- **Active Directory** (3 remaining) — trust attacks, SCCM exploitation, AD persistence
- **Privilege Escalation** — Windows, Linux, macOS
- **Infrastructure** — network recon, pivoting, cloud (AWS/Azure), containers, CI/CD
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

## Installation

### Prerequisites

Skills reference `~/docs/` for deep payload content beyond what's embedded. Clone these (optional — skills degrade gracefully without them):

```bash
git clone <removed> ~/docs/public-security-references
git clone <removed> ~/docs/public-security-references
git clone <removed> ~/docs/public-security-references
```

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

## Source material

Skills synthesize content from three reference repositories:

| Repo | Strength |
|------|----------|
| [public-security-references](<removed>) | Web payloads, injection techniques — deepest per-technique coverage |
| [public-security-references](<removed>) | AD, red team ops, cloud, evasion — 15 ADCS ESC files, full delegation chain |
| [public-security-references](<removed>) | Broadest scope — binary exploitation, macOS, mobile, network protocols |

Each skill embeds the top 2-3 payloads per variant (80% coverage) and references `~/docs/` for WAF bypass, edge cases, and the long tail.

## Status

Phase 4 (Active Directory) in progress. Batch 4 (Relay & Credentials) complete. 43 skills built, ~20,700 lines. See `task_plan.md` for the full build plan.

## Disclaimer

These skills are for use in **authorized security testing, CTF competitions, and educational contexts only**. Do not use them against systems you do not have explicit written permission to test.
