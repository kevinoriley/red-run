---
name: ad-discovery
description: >
  Enumerates Active Directory domains and maps attack surface for penetration
  testing.
keywords:
  - enumerate domain
  - AD recon
  - bloodhound
  - domain enumeration
  - active directory
  - find attack paths
  - domain controllers
  - kerberos
tools:
  - bloodhound-python
  - rusthound-ce
  - netexec
  - certipy
  - bloodyAD
  - kerbrute
  - Impacket
  - PowerView
opsec: medium
---

# AD Attack Discovery

You are helping a penetration tester enumerate an Active Directory domain and
identify attack paths. All testing is under explicit written authorization.

This skill works at three access levels:
1. **No credentials** — network-level recon, poisoning, RID cycling
2. **Username only** — AS-REP roasting, Kerberos user validation
3. **Valid credentials** — full enumeration, BloodHound, ADCS, ACLs

## Mode

Check if the user or orchestrator has set a mode:
- **Guided** (default): Before executing any command that sends traffic to a
  target, present the command with a one-line explanation of what it does and
  why. Wait for explicit user approval before executing. Never batch multiple
  target-touching commands without approval — present them one at a time (or as
  a small logical group if they achieve a single objective, e.g., "enumerate SMB
  shares"). Local-only operations (file writes, output parsing, engagement
  logging, hash cracking) do not require approval. At decision forks, present
  options and let the user choose.
- **Autonomous**: Run full enumeration pipeline. Prioritize findings by
  impact. Route to technique skills automatically. Report at milestones.

If unclear, default to guided.

## Engagement Logging

Check for `./engagement/` directory. If absent, proceed without logging.

When an engagement directory exists:
- Print `[ad-discovery] Activated → <target>` to the screen on activation.
- **Evidence** → save significant output to `engagement/evidence/` with
  descriptive filenames (e.g., `sqli-users-dump.txt`, `ssrf-aws-creds.json`).

Do NOT write to `engagement/activity.md`, `engagement/findings.md`, or
engagement state. The orchestrator maintains these files. Report all findings
in your return summary.

## Scope Boundary

This skill covers Active Directory discovery — enumerating domain objects,
identifying misconfigurations, and routing to technique skills. When you reach
the boundary of this scope — whether through a routing instruction ("Route to
**skill-name**") or by discovering findings outside your domain — **STOP**.

Do not load or execute another skill. Do not continue past your scope boundary.
Instead, return to the orchestrator with:
  - What was found (vulns, credentials, access gained)
  - Recommended next skill (the bold **skill-name** from routing instructions)
  - Context to pass (injection point, target, working payloads, etc.)

The orchestrator decides what runs next. Your job is to execute this skill
thoroughly and return clean findings.

**Stay in methodology.** Only use techniques documented in this skill. If you
encounter a scenario not covered here, note it and return — do not improvise
attacks, write custom exploit code, or apply techniques from other domains.
The orchestrator will provide specific guidance or route to a different skill.

You MUST NOT:
- Perform Kerberoasting or AS-REP roasting beyond identifying targets — route
  to **kerberos-roasting**
- Exploit delegation misconfigurations — route to **kerberos-delegation**
- Exploit ACL misconfigurations — route to **acl-abuse**
- Perform credential dumping — route to **credential-dumping**
- Forge tickets — route to **kerberos-ticket-forging**
- Perform coercion or relay attacks — route to **auth-coercion-relay**
- Exploit ADCS beyond enumeration — route to **adcs-template-abuse** or
  **adcs-access-and-relay**

When you find exploitable attack paths: update state.md, log to activity.md,
and present routing recommendations. Do not continue past enumeration.

## State Management

Call `get_state_summary()` from the state-reader MCP server to read current
engagement state. Use it to:
- Skip re-testing targets, parameters, or vulns already confirmed
- Leverage existing credentials or access for this technique
- Understand what's been tried and failed (check Blocked section)

**Do NOT write engagement state.** When your work is complete, report all
findings clearly in your return summary. The orchestrator parses your summary
and records state changes. Your return summary must include:
- New targets/hosts discovered (with ports and services)
- New credentials or tokens found
- Access gained or changed (user, privilege level, method)
- Vulnerabilities confirmed (with status and severity)
- Pivot paths identified (what leads where)
- Blocked items (what failed and why, whether retryable)

## Prerequisites

- Network access to the target domain (ports 88, 135, 389, 445, 636)
- For unauthenticated enumeration: just network access
- For authenticated enumeration: valid domain credentials (any privilege level)
- Tools: `netexec` (nxc), `bloodhound-python` or `rusthound-ce`, `certipy`,
  `bloodyAD`, `kerbrute`, Impacket suite (`GetUserSPNs.py`, `GetNPUsers.py`,
  `lookupsid.py`)

**Kerberos-first authentication** (when credentials are available):

This skill may start unauthenticated. Once credentials are obtained, switch
to Kerberos authentication for all subsequent enumeration:

```bash
# Get a TGT (password, hash, or AES key)
getTGT.py DOMAIN/user:'Password123'@dc.domain.local
# or with NTLM hash
getTGT.py DOMAIN/user@dc.domain.local -hashes :NTHASH

export KRB5CCNAME=user.ccache

# Then use -k -no-pass on all Impacket tools
# Use --use-kcache on NetExec
# Use -k on Certipy and bloodyAD
```

## Step 1: Initial Reconnaissance

Identify domain controllers and assess the network posture.

### Find Domain Controllers

```bash
# DNS SRV records
nslookup -type=srv _ldap._tcp.dc._msdcs.DOMAIN.LOCAL
nslookup -type=srv _kerberos._tcp.DOMAIN.LOCAL

# NetExec SMB scan — shows OS, signing, SMBv1
nxc smb 10.10.10.0/24

# NetExec generate /etc/hosts entries
nxc smb 10.10.10.0/24 --generate-hosts-file hosts
```

### Check Signing and Relay Posture

```bash
# SMB signing — signing:False = relay target
nxc smb 10.10.10.0/24 | grep -i "signing:False"

# LDAP signing — signing:None = relay to LDAP viable
nxc ldap DC01.DOMAIN.LOCAL

# Determine if LDAPS is available
nxc ldap DC01.DOMAIN.LOCAL --port 636
```

**Findings:**
- SMB signing disabled on non-DCs -> note for **auth-coercion-relay**
- LDAP signing not required -> note for **auth-coercion-relay** (relay to LDAP)
- Domain name, DC hostnames, OS versions -> record in the engagement state

## Step 2: Unauthenticated Enumeration

Use when no valid credentials are available yet.

### Null Session / Guest Access

```bash
# SMB null session
nxc smb DC01.DOMAIN.LOCAL -u '' -p ''
nxc smb DC01.DOMAIN.LOCAL -u 'guest' -p ''

# enum4linux
enum4linux -a -u "" -p "" DC01.DOMAIN.LOCAL

# rpcclient
rpcclient -U "" -N DC01.DOMAIN.LOCAL -c "enumdomusers;enumdomgroups;querydominfo"
```

### RID Cycling (Unauthenticated User Enumeration)

```bash
# NetExec — enumerate users via RID brute force
nxc smb DC01.DOMAIN.LOCAL -u 'guest' -p '' --rid-brute 10000

# Impacket
lookupsid.py -no-pass 'guest@DC01.DOMAIN.LOCAL' 20000

# Extract just usernames
nxc smb DC01.DOMAIN.LOCAL -u '' -p '' --rid-brute \
  | awk -F'\\\\| ' '/SidTypeUser/ {print $3}' > users.txt
```

### Kerberos Username Enumeration

```bash
# kerbrute — validates usernames via Kerberos pre-auth responses
# Generates Event 4771, NOT 4625 (often less monitored)
kerbrute userenum -d DOMAIN.LOCAL --dc DC01.DOMAIN.LOCAL usernames.txt
```

Use output as username list for **password-spraying** and AS-REP roasting checks.

### LLMNR/NBT-NS/mDNS Poisoning Check

If network position allows, note LLMNR/NBT-NS traffic for Responder-based
hash capture. → STOP. Return to orchestrator recommending **auth-coercion-relay**.
Pass: DC IP, domain name, network position, LLMNR/NBT-NS traffic details,
current mode. Do not execute poisoning or relay commands inline.

## Step 3: BloodHound Collection

The single highest-value enumeration step. Requires valid domain credentials.

### Linux (Remote Collection)

```bash
# bloodhound-python — LDAP-based, remote
bloodhound-python -d DOMAIN.LOCAL -u 'user' -p 'Password123' \
  -gc DC01.DOMAIN.LOCAL -c all -ns DC_IP

# rusthound-ce — faster, includes ADCS data
rusthound-ce -d DOMAIN.LOCAL -u 'user@DOMAIN.LOCAL' -p 'Password123' \
  -o /tmp/bloodhound -z --adcs

# With Kerberos auth
export KRB5CCNAME=user.ccache
bloodhound-python -d DOMAIN.LOCAL -u 'user' -k -no-pass \
  -gc DC01.DOMAIN.LOCAL -c all
```

### Windows (On-Host Collection)

```powershell
# SharpHound — full collection
.\SharpHound.exe -c all -d DOMAIN.LOCAL --searchforest

# Stealthier — DC-only mode (no host enumeration)
.\SharpHound.exe --CollectionMethod DCOnly

# OPSEC — throttle and randomize
.\SharpHound.exe -c all,GPOLocalGroup --throttle 10000 --jitter 23

# SOAPHound — uses ADWS instead of LDAP (avoids LDAP monitoring)
SOAPHound.exe --buildcache -c c:\temp\cache.txt
SOAPHound.exe -c c:\temp\cache.txt --bhdump -o c:\temp\bh-output
SOAPHound.exe -c c:\temp\cache.txt --certdump -o c:\temp\bh-output
```

### ADCS Certificate Data

```bash
# Certipy — certificate template enumeration for BloodHound
certipy find 'DOMAIN/user:Password123@DC01.DOMAIN.LOCAL' -bloodhound

# Find vulnerable templates only
certipy find 'DOMAIN/user:Password123@DC01.DOMAIN.LOCAL' -vulnerable -hide-admins

# With Kerberos
certipy find 'DOMAIN/user@DC01.DOMAIN.LOCAL' -k -bloodhound
```

### BloodHound Analysis Priorities

After importing data, run these queries first:
1. **Shortest Paths to Domain Admins** — identify the quickest win
2. **Kerberoastable Users** — prioritize by blast radius and pwdLastSet age
3. **AS-REP Roastable Users** — free hashes, no special access needed
4. **Unconstrained Delegation** — TGT harvesting opportunities
5. **Dangerous ACLs** — GenericAll/WriteDACL/WriteOwner on high-value targets
6. **ADCS Attack Paths** — ESC1-ESC15 (requires certipy data import)
7. **Owned -> Domain Admins** — mark owned principals and find chains

## Step 4: Targeted Enumeration

Deeper enumeration beyond BloodHound. Run these based on what BloodHound reveals.

### Password Policy

```bash
# NetExec
nxc smb DC01.DOMAIN.LOCAL -u 'user' -p 'Password123' --pass-pol

# enum4linux
enum4linux -u 'user' -p 'Password123' -P DC01.DOMAIN.LOCAL

# PowerView
(Get-DomainPolicy)."SystemAccess"
```

Record lockout threshold, observation window, complexity requirements. Pass
to **password-spraying** skill.

### SPN Enumeration (Kerberoasting Targets)

```bash
# Impacket — list accounts with SPNs
GetUserSPNs.py DOMAIN/user:'Password123' -dc-ip DC_IP

# NetExec
nxc ldap DC01.DOMAIN.LOCAL -u 'user' -p 'Password123' --kerberoasting output.txt

# Rubeus — stats only (no ticket requests)
.\Rubeus.exe kerberoast /stats
```

If SPNs found on user accounts → STOP. Return to orchestrator recommending
**kerberos-roasting**. Pass: DC IP, domain name, SPN list, current credentials,
current mode. Do not request or crack service tickets inline.

### AS-REP Roastable Accounts

```bash
# Impacket — enumerate users without pre-auth
GetNPUsers.py DOMAIN/user:'Password123' -dc-ip DC_IP

# bloodyAD — LDAP filter for DONT_REQ_PREAUTH
bloodyAD -u user -p 'Password123' -d DOMAIN.LOCAL --host DC_IP \
  get search --filter '(&(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))' \
  --attr sAMAccountName
```

If found → STOP. Return to orchestrator recommending **kerberos-roasting**
(AS-REP section). Pass: DC IP, domain name, AS-REP roastable user list, current
mode. Do not request or crack AS-REP hashes inline.

### Delegation Enumeration

```bash
# Unconstrained delegation
bloodyAD -u user -p 'Password123' -d DOMAIN.LOCAL --host DC_IP \
  get search --filter '(userAccountControl:1.2.840.113556.1.4.803:=524288)' \
  --attr sAMAccountName,dNSHostName

# Constrained delegation
bloodyAD -u user -p 'Password123' -d DOMAIN.LOCAL --host DC_IP \
  get search --filter '(msDS-AllowedToDelegateTo=*)' \
  --attr sAMAccountName,msDS-AllowedToDelegateTo

# RBCD
bloodyAD -u user -p 'Password123' -d DOMAIN.LOCAL --host DC_IP \
  get search --filter '(msDS-AllowedToActOnBehalfOfOtherIdentity=*)' \
  --attr sAMAccountName

# PowerView
Get-DomainComputer -Unconstrained
Get-DomainUser -TrustedToAuth
Get-DomainComputer -TrustedToAuth
```

If found → STOP. Return to orchestrator recommending **kerberos-delegation**.
Pass: DC IP, domain name, delegation type and targets, current credentials,
current mode. Do not exploit delegation inline.

### Privileged Group Membership

```bash
# AdminCount=1 (privileged group members, may have stale perms)
nxc ldap DC01.DOMAIN.LOCAL -u 'user' -p 'Password123' --admin-count

# Specific dangerous groups
bloodyAD -u user -p 'Password123' -d DOMAIN.LOCAL --host DC_IP \
  get object "DNSAdmins" --attr msds-memberTransitive
bloodyAD -u user -p 'Password123' -d DOMAIN.LOCAL --host DC_IP \
  get object "Backup Operators" --attr msds-memberTransitive
```

### LAPS / gMSA / dMSA

```bash
# LAPS — check if current user can read local admin passwords
nxc ldap DC01.DOMAIN.LOCAL -u 'user' -p 'Password123' -M laps

# gMSA — readable managed service account passwords
nxc ldap DC01.DOMAIN.LOCAL -u 'user' -p 'Password123' --gmsa
```

If readable → STOP. Return to orchestrator recommending **credential-dumping**.
Pass: DC IP, domain name, LAPS/gMSA target details, current credentials,
current mode. Do not extract managed passwords inline.

### Trust Enumeration

```bash
# NetExec
nxc ldap DC01.DOMAIN.LOCAL -u 'user' -p 'Password123' -M enum_trust

# Impacket
nltest /domain_trusts /all_trusts /v

# PowerView
Get-DomainTrust
Get-NetForestDomain
Get-DomainForeignUser
Get-DomainForeignGroupMember
```

If trusts found → STOP. Return to orchestrator recommending **trust-attacks**.
Pass: DC IP, domain name, trust relationships enumerated, trust types and
directions, current credentials, current mode. Do not exploit trust
relationships inline.

### Share Enumeration

```bash
# NetExec — find accessible shares
nxc smb 10.10.10.0/24 -u 'user' -p 'Password123' --shares

# Spider shares for sensitive files
nxc smb DC01.DOMAIN.LOCAL -u 'user' -p 'Password123' -M spider_plus
```

Check SYSVOL/NETLOGON for Group Policy Preferences (GPP) passwords, scripts
with embedded credentials, and configuration files.

**High-value file patterns in shares** — when spidering user home directories,
SYSVOL, or custom shares, look for:

| Pattern | Why |
|---------|-----|
| `*.xml` (especially `azure.xml`, `gpp.xml`, `*.runconfig.xml`) | Azure AD credential exports (`PSADPasswordCredential`), GPP cpassword, deployment configs |
| `Groups.xml`, `Services.xml`, `Scheduledtasks.xml`, `DataSources.xml` | GPP passwords (MS14-025) — in SYSVOL `Policies/` subdirectories |
| `web.config`, `*.config` | .NET connection strings, API keys |
| `*.ps1`, `*.bat`, `*.cmd`, `*.vbs` | Scripts with hardcoded credentials |
| `*.kdbx`, `*.key` | KeePass databases and key files |
| `*.pfx`, `*.p12`, `*.pem` | Certificates and private keys |
| `unattend.xml`, `sysprep.xml` | Deployment credentials |

Download and inspect any XML files found in user home directories — Azure AD
credential exports are a common source of cleartext domain passwords.

### Session Enumeration

```bash
# Where are high-value users logged in?
nxc smb 10.10.10.0/24 -u 'user' -p 'Password123' --sessions
nxc smb 10.10.10.0/24 -u 'user' -p 'Password123' --loggedon-users

# PowerView
Invoke-UserHunter -Stealth
Find-DomainUserLocation
```

### Local Admin Access

```bash
# Where does the current user have local admin?
nxc smb 10.10.10.0/24 -u 'user' -p 'Password123'
# Look for (Pwn3d!) in output

# PowerView
Find-LocalAdminAccess -Verbose
```

If local admin found → STOP. Return to orchestrator recommending
**credential-dumping** (SAM/LSASS). Pass: target hostname, local admin
credentials, DC IP, domain name, current mode. Do not dump credentials inline.

### SCCM / Deployment

```bash
# SCCM discovery
python3 sccmhunter.py find -u 'user' -p 'Password123' -d DOMAIN.LOCAL -dc-ip DC_IP
```

If SCCM found → STOP. Return to orchestrator recommending
**sccm-exploitation**. Pass: DC IP, domain name, SCCM server details, current
credentials, current mode. Do not exploit SCCM inline.

## Step 5: Attack Surface Routing

Map enumeration findings to technique skills. This is the core routing table.
When a match below is found, STOP — return to the orchestrator recommending
the matched skill. Do not execute attack techniques inline.

| Finding | Indicator | Route To |
|---------|-----------|----------|
| User accounts with SPNs | GetUserSPNs output shows SPNs | **kerberos-roasting** |
| Users without pre-auth | GetNPUsers / DONT_REQ_PREAUTH flag | **kerberos-roasting** (AS-REP section) |
| Valid username list obtained | RID cycling / kerbrute / LDAP | **password-spraying** |
| NTLM hash obtained | SAM dump / LSASS / secretsdump | **pass-the-hash** |
| AES keys obtained | DCSync / secretsdump / LSASS | **pass-the-hash** (Pass-the-Key) |
| Kerberos ticket captured | Delegation / ticket dump | **pass-the-hash** (Pass-the-Ticket) |
| Unconstrained delegation host | TRUSTED_FOR_DELEGATION flag | **kerberos-delegation** |
| Constrained delegation | msDS-AllowedToDelegateTo set | **kerberos-delegation** |
| RBCD writable | Write to msDS-AllowedToActOnBehalf | **kerberos-delegation** |
| krbtgt hash obtained | DCSync of krbtgt | **kerberos-ticket-forging** |
| Service account hash obtained | Kerberoast / DCSync | **kerberos-ticket-forging** (Silver) |
| GenericAll on user/group | BloodHound / ACL scan | **acl-abuse** |
| WriteDACL / WriteOwner | BloodHound / ACL scan | **acl-abuse** |
| ForceChangePassword | BloodHound | **acl-abuse** |
| msDS-KeyCredentialLink writable | BloodHound | **acl-abuse** (Shadow Credentials) |
| Vulnerable ADCS templates (ESC1-3,6) | certipy find -vulnerable | **adcs-template-abuse** |
| CA/template ACL abuse (ESC4-5,7) | certipy / BloodHound ADCS | **adcs-access-and-relay** |
| HTTP/RPC enrollment (ESC8,11) | certipy / nmap web enrollment | **adcs-access-and-relay** |
| Weak cert mapping (ESC9-15) | certipy find | **adcs-persistence** |
| SMB signing disabled | nxc smb signing:False | **auth-coercion-relay** |
| LDAP signing not required | nxc ldap signing:None | **auth-coercion-relay** |
| Spooler service running | `ls \\\\host\\pipe\\spoolss` | **auth-coercion-relay** |
| LLMNR/NBT-NS traffic | Responder analysis mode | **auth-coercion-relay** |
| DCSync rights (Replication perms) | BloodHound | **credential-dumping** |
| Local admin on DC | BloodHound / Pwn3d! | **credential-dumping** |
| LAPS readable | nxc -M laps output | **credential-dumping** |
| gMSA/dMSA readable | nxc --gmsa output | **credential-dumping** |
| GPO write access | BloodHound | **gpo-abuse** |
| Domain/forest trusts | Trust enumeration | **trust-attacks** |
| SCCM infrastructure | sccmhunter find | **sccm-exploitation** |
| Post-DA compromise | Full domain control | **ad-persistence** |

### Priority Order

When multiple attack paths exist, prioritize by OPSEC and reliability:

1. **Kerberos roasting / AS-REP roasting** — offline cracking, low detection
2. **ADCS template abuse** — certificate-based, stealthy, persistent
3. **ACL abuse** — targeted, often unmonitored
4. **Delegation abuse** — Kerberos-based, moderate detection
5. **Password spraying** — risk of lockout, use as last resort for initial access
6. **Coercion/relay** — requires network position, noisy
7. **Credential dumping** — requires existing admin access

## Step 6: Escalate or Pivot

After mapping the attack surface:
- **Multiple paths identified**: In guided mode, present the top 3 paths ranked
  by OPSEC and reliability. In autonomous mode, pursue the highest-value path.
- **No clear path**: Expand enumeration scope (additional subnets, different
  protocols), try password spraying, or check for relay opportunities.
- **Credentials found in shares/GPP**: Route to **pass-the-hash** or use for
  deeper authenticated enumeration.

When routing to a technique skill, pass along:
- Target user/host/service
- Current credentials and access level
- Domain name and DC hostname
- Current mode (guided/autonomous)
- Relevant enumeration output

## Troubleshooting

### BloodHound Collection Fails

- **LDAP connection refused**: Try port 636 (LDAPS) with `--ssl` flag
- **Access denied**: Verify credentials; any domain user can run BloodHound
- **Timeout**: Use `--CollectionMethod DCOnly` for stealthier, faster collection
- **Missing ADCS data**: Use `certipy find -bloodhound` separately and merge

### Kerberos Errors

- **KRB_AP_ERR_SKEW**: Clock out of sync (> 5 minutes from DC). This is a
  **Clock Skew Interrupt** — stop immediately and return to the orchestrator.
  Do not retry or fall back to NTLM. Fix requires root: `sudo ntpdate DC_IP`
- **KDC cannot find the name**: Use FQDN hostnames, not IP addresses. Ensure
  DNS resolves to the DC or add entries to `/etc/hosts`

### NetExec Connection Issues

- **SMB SessionError STATUS_NOT_SUPPORTED**: Target may require SMBv3 or
  NTLMv2. Try `--smb2` flag
- **Connection timed out**: Host may be down or firewalled. Try different
  protocols (LDAP, WinRM, RDP)

### No Credentials Available

Start with:
1. RID cycling for username list
2. AS-REP roasting against discovered usernames
3. LLMNR/NBT-NS poisoning (if on-network)
4. Password spraying with common passwords
5. Check for anonymous LDAP bind (`nxc ldap DC -u '' -p ''`)
