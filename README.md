# red-run

Claude Code skill library for penetration testing and CTF work.

## What is this?

A collection of technique-focused skills that Claude Code uses during authorized security assessments and CTF competitions. Skills auto-trigger based on conversation context — describe what you're attacking and Claude activates the relevant skill with real payloads, per-technology variants, and step-by-step exploitation guidance.

No slash commands needed. Say "I found a SQL injection with error messages" and the `sql-injection-error` skill activates. Say "test this web app for vulnerabilities" and `web-vuln-discovery` runs discovery and routes to technique skills based on findings.

## How it works

### Skill types

- **Discovery skills** — identify vulnerabilities and route to the correct technique skill via decision tree
- **Technique skills** — exploit a specific vulnerability class with embedded payloads and bypass techniques

### Modes

- **Guided** (default) — explain each step, ask before executing, present options at decision forks
- **Autonomous** — execute end-to-end, make triage decisions, report at milestones

Say "switch to autonomous" or "guide me through this" at any point to change modes.

### Inter-skill routing

Skills route to each other at escalation points. When SQL injection leads to credentials, the skill suggests pivoting to privilege escalation. Context (injection point, working payloads, target platform, mode) is passed along.

## Skills

### Web Application

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
| `idor` | Horizontal/vertical access control bypass, UUID/ObjectId prediction, API IDOR, encoding bypass, automated enumeration | 569 |
| `cors-misconfiguration` | Origin reflection, null origin, regex bypass, subdomain trust, wildcard abuse, CORS+IDOR chain | 565 |
| `csrf` | Token bypass, SameSite bypass, JSON CSRF, file upload CSRF, WebSocket CSRF, clickjacking chain | 609 |
| `oauth-attacks` | Redirect URI bypass, state bypass, code theft, token leakage, OIDC attacks, PKCE bypass, ATO chains | 610 |

**Remaining Phase 3:** Password reset poisoning, 2FA bypass, race conditions

### Planned categories

- **Active Directory** — enumeration, Kerberoasting, delegation, ADCS, relay, ACL abuse, DCSync
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

Large engagements generate more state than fits in a single conversation context. `state.md` solves this — it's a compact, machine-readable snapshot of the current engagement that persists across sessions and context compactions.

**Sections:**

| Section | Contents |
|---------|----------|
| Targets | Hosts, IPs, URLs, ports, tech stack |
| Credentials | Username/password/hash/token pairs, where they work |
| Access | Current footholds — shells, sessions, tokens, DB access |
| Vulns | One-liner per confirmed vuln: `[found]`, `[active]`, `[done]` |
| Pivot Map | What leads where — vuln X gives access Y, creds Z work on host W |
| Blocked | What was tried and why it failed |

**How it works:**
- Every skill reads `state.md` on activation — skips retesting, leverages existing access
- Every skill writes back on completion — adds new credentials, vulns, pivot paths
- The orchestrator reads `state.md` to chain vulnerabilities toward maximum impact
- Kept under ~200 lines — one-liner per item, current state not history
- New session? Read `state.md` + `scope.md` and you're caught up

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

Phase 3 (web application skills) in progress. See `task_plan.md` for the full build plan.

## Disclaimer

These skills are for use in **authorized security testing, CTF competitions, and educational contexts only**. Do not use them against systems you do not have explicit written permission to test.
