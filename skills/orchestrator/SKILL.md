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

## Mode

Check if the user has set a mode:
- **Guided** (default): Present findings at each phase. Ask which attack
  paths to pursue. Explain routing decisions. Confirm before moving to
  exploitation.
- **Autonomous**: Execute recon through exploitation. Make triage decisions.
  Route to technique skills automatically. Report at phase boundaries and
  when significant access is gained.

If unclear, default to guided.

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

Map the attack surface. Adjust techniques based on what's in scope.

### Network Recon (if IP/subnet in scope)

```bash
# Fast port scan
nmap -sS -T4 --top-ports 1000 -oA engagement/evidence/nmap-top1000 TARGET

# Service/version detection on open ports
nmap -sV -sC -p OPEN_PORTS -oA engagement/evidence/nmap-svc TARGET

# UDP quick scan (top 50)
nmap -sU --top-ports 50 -oA engagement/evidence/nmap-udp TARGET
```

### Web Discovery (if HTTP/HTTPS found)

```bash
# Identify web technologies
httpx -u https://TARGET -title -tech-detect -status-code -follow-redirects

# Screenshot web services
httpx -u https://TARGET -screenshot -srd engagement/evidence/screenshots
```

### Host Enumeration (if domain environment suspected)

```bash
# SMB enumeration
netexec smb TARGET
netexec smb TARGET --shares
netexec smb TARGET --users

# LDAP check
netexec ldap TARGET
```

### Update State

After recon, update `engagement/state.md` Targets section with discovered
hosts, ports, services, and technologies.

Log to `engagement/activity.md`:
```markdown
### [HH:MM] orchestrator → recon
- Scanned TARGET with nmap — N open ports
- Web services found: <list>
- Technologies: <list>
- Domain environment: yes/no
```

## Step 3: Attack Surface Mapping

Based on recon results, categorize the attack surface:

| Surface | Indicators | Route To |
|---------|-----------|----------|
| Web application | HTTP/HTTPS, login forms, APIs | **web-vuln-discovery** |
| Active Directory | LDAP (389/636), Kerberos (88), SMB domain | **ad-attack-discovery** (when available) |
| Database | MySQL (3306), MSSQL (1433), PostgreSQL (5432) | Direct DB testing |
| Mail | SMTP (25/587), IMAP (143/993) | Credential attacks, phishing |
| File shares | SMB (445), NFS (2049) | Enumeration, sensitive files |
| Remote access | SSH (22), RDP (3389), WinRM (5985) | Credential spraying |
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

Route to **web-vuln-discovery** with the target URL. It will:
1. Run content and parameter discovery
2. Test for injection points
3. Route to technique skills (SQLi, XSS, SSTI, SSRF, etc.)

### Active Directory

Route to **ad-attack-discovery** (when available) with domain info. It will:
1. Enumerate users, groups, trusts
2. Identify attack paths (Kerberoastable, delegation, ADCS)
3. Route to technique skills

### Credential Attacks

For services with authentication (SSH, RDP, SMB, web login):

```bash
# Password spraying (careful — lockout policies)
netexec smb TARGET -u users.txt -p 'SeasonYear!' --no-bruteforce

# Check known credentials against other services
netexec smb TARGET -u 'found_user' -p 'found_pass'
netexec winrm TARGET -u 'found_user' -p 'found_pass'
netexec rdp TARGET -u 'found_user' -p 'found_pass'
```

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

**Privilege Escalation:**
- Local admin → dump credentials → domain user
- Domain user → Kerberoasting/ASREProasting → service accounts
- Service account → delegation abuse → domain admin
- ADCS misconfiguration → certificate forgery → domain admin

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
4. Route to **pentest-findings** for formal writeups of each finding

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
