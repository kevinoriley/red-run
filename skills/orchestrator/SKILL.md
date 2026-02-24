---
name: orchestrator
description: >
  Master orchestrator for penetration testing engagements. Use when the user
  provides a target (IP, hostname, URL, subnet) and wants to start a
  structured assessment. Handles scoping, recon, attack surface mapping,
  vulnerability chaining, and routing to discovery and technique skills.
  Also triggers on: "pentest this target", "start an engagement", "scan this
  host", "assess this network", "attack this target", "full pentest",
  "start testing", "engagement against", "begin assessment".
  OPSEC: varies by phase — recon is low, exploitation is medium-high.
  Tools: nmap, httpx, bbot, ffuf, netexec, nuclei.
  Do NOT use for single-technique exploitation — route directly to the
  relevant technique skill instead (e.g., sql-injection-union, xss-reflected).
---

# Penetration Test Orchestrator

You are orchestrating a penetration test. Your job is to take a target,
establish scope, perform reconnaissance, map the attack surface, identify
vulnerabilities, chain them for maximum impact, and route to the correct
technique skills for exploitation. All testing is under explicit written
authorization.

## Skill Routing Is Mandatory

When this skill says "Route to **skill-name**", you MUST invoke the named
skill using the Skill tool. Do NOT execute techniques inline — even if the
attack path seems obvious or you already know the technique. Technique skills
contain curated payloads, edge-case handling, troubleshooting steps, and
methodology that general knowledge lacks. Skipping skill invocation trades
thoroughness for speed and risks missing things on harder targets.

This applies in both guided and autonomous modes. Autonomous mode means you
make triage and routing decisions without asking — it does not mean you bypass
the skill library.

### If the Skill Tool Fails

If invoking a skill via the Skill tool returns an error (file not found, skill
not loaded, empty content), **STOP**. Do not fall back to executing the
technique inline. Do not read the skill file with the Read tool and execute its
contents. Tell the user:

> Skill invocation failed. Run `./install.sh` from the red-run repo directory
> to reinstall skills, then restart this session.

Skills fail when symlinks are broken (repo moved, install pointed at wrong
path). Inline execution is never an acceptable fallback — it skips payloads,
edge-case handling, and methodology that the skill contains.

### Commands the Orchestrator May Execute Directly

The orchestrator routes to skills — it does not run attack tools itself.
The only commands the orchestrator may execute directly are:

- `mkdir -p engagement/evidence` — engagement directory creation
- File writes to `engagement/` — scope.md, state.md, activity.md, findings.md
- `httpx -u <target> -title -tech-detect -status-code -follow-redirects` — initial web triage only

Everything else — nmap, netexec, ffuf, nuclei, sqlmap, any exploitation tool —
MUST go through the appropriate skill via the Skill tool.

### Pre-Routing Checkpoint

Before every skill invocation, write `engagement/state.md` and append to
`engagement/activity.md` with current findings. Format:
```
### [HH:MM] orchestrator → routing to <skill-name>
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
   ### [HH:MM] orchestrator → <target>
   - Invoked (engagement starting)
   ```

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

STOP. Invoke **network-recon** via the Skill tool. Pass: target IP, hostname,
or CIDR range, current mode, and any credentials from scope.
Do not execute nmap, masscan, or netexec commands inline.

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

STOP. Invoke **web-discovery** via the Skill tool. Pass: target URL,
technology stack (from network-recon results), current mode.
Do not execute ffuf, httpx, or nuclei commands inline.

### Host Enumeration (if domain environment suspected)

STOP. Invoke **ad-discovery** via the Skill tool. Pass: target IP, domain name
(from LDAP rootDSE or SMB discovery), any credentials.
Do not execute netexec or ldapsearch commands inline.

### Update State

After discovery skills return, update `engagement/state.md` Targets section
with discovered hosts, ports, services, and technologies.

Log to `engagement/activity.md`:
```markdown
### [HH:MM] orchestrator → recon
- Routed to network-recon → N open ports found
- Web services found: <list>
- Technologies: <list>
- Domain environment: yes/no
```

## Step 3: Attack Surface Mapping

Based on recon results, categorize the attack surface:

| Surface | Indicators | Action |
|---------|-----------|--------|
| Web application | HTTP/HTTPS, login forms, APIs | STOP. Invoke **web-discovery** via the Skill tool. |
| Active Directory | LDAP (389/636), Kerberos (88), SMB domain | STOP. Invoke **ad-discovery** via the Skill tool. |
| Containers / K8s | Docker API (2375), K8s API (6443/8443), kubelet (10250), etcd (2379), or inside a container | STOP. Invoke **container-escapes** via the Skill tool. |
| Database | MySQL (3306), MSSQL (1433), PostgreSQL (5432) | Direct DB testing |
| Mail | SMTP (25/587), IMAP (143/993) | Credential attacks, phishing |
| File shares | SMB (445), NFS (2049) | Enumeration, sensitive files |
| Remote access | SSH (22), RDP (3389), WinRM (5985) | STOP. Invoke **password-spraying** via the Skill tool. |
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

STOP. Invoke **web-discovery** via the Skill tool. Pass: target URL,
technology stack, current mode, any credentials.
Do not execute ffuf, httpx, or nuclei commands inline.

### Active Directory

STOP. Invoke **ad-discovery** via the Skill tool. Pass: DC IP, domain name,
any credentials, current mode.
Do not execute netexec, ldapsearch, or bloodhound commands inline.

### Credential Attacks

For services with authentication (SSH, RDP, SMB, web login):

STOP. Invoke **password-spraying** via the Skill tool. Pass: target IP,
service type(s), any known usernames and passwords, current mode.
Do not execute netexec or hydra commands inline.

## Step 5: Vulnerability Chaining

This is the critical orchestrator function. Read `engagement/state.md` and
analyze the Pivot Map to chain vulnerabilities for maximum impact.

### Chaining Strategy

Think through these chains systematically:

**Information → Access:**
- LFI reads config → credentials → database/service access
- SSRF reaches internal service → metadata credentials → cloud access
- XXE reads files → SSH keys or passwords → host access
- SQLi dumps users table → password reuse → admin panel

**Access → Deeper Access:**
- Web shell → host enumeration → privilege escalation
- Database access → xp_cmdshell or UDF → OS command execution
- JWT forgery → admin panel → file upload → web shell
- Deserialization RCE → service account → AD enumeration

**Lateral Movement:**
- Credentials from one host → test against all others in scope
- Service account → Kerberoasting → more credentials
- Machine keys from IIS → ViewState RCE on other IIS sites
- Database link → linked server → second database
- Host access on new subnet → invoke **pivoting-tunneling** via Skill tool → then invoke **network-recon** via Skill tool on internal network

**Privilege Escalation:**
- Local admin → dump credentials → domain user
- Domain user → Kerberoasting/ASREProasting → service accounts
- Service account → delegation abuse → domain admin
- ADCS misconfiguration → certificate forgery → domain admin
- Containerized shell → invoke **container-escapes** via Skill tool → host access → invoke **linux-discovery** or **windows-discovery** via Skill tool

### Decision Logic

When reading state.md, the orchestrator should:

1. **Check for unexploited vulns** — route to the appropriate technique skill
2. **Check for unchained access** — can existing access reach new targets?
3. **Check credentials** — have all found credentials been tested against all
   services?
4. **Check pivot map** — are there identified paths not yet followed?
5. **Check blocked items** — has anything changed that might unblock a
   previously failed technique?
6. **Assess progress toward objectives** — are we closer to the goal defined
   in scope.md?

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

```bash
# On compromised host — collect proof
whoami /all > engagement/evidence/host-whoami.txt
ipconfig /all > engagement/evidence/host-network.txt
systeminfo > engagement/evidence/host-sysinfo.txt

# Domain info if applicable
net user /domain > engagement/evidence/domain-users.txt
net group "Domain Admins" /domain > engagement/evidence/domain-admins.txt
```

## Step 7: Reporting

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
