---
name: ad-discovery
description: >
  Enumerates Active Directory domains and maps attack surface for penetration
  testing. Use when targeting an AD environment, starting a domain assessment,
  or when the orchestrator identifies AD services (port 88, 389, 445, 636).
  Triggers on: "enumerate domain", "AD recon", "bloodhound", "domain enumeration",
  "active directory", "find attack paths", "domain controllers", "kerberos".
  OPSEC: medium (LDAP queries, SMB connections, BloodHound collection generate
  logs). Tools: bloodhound-python, rusthound-ce, netexec, certipy, bloodyAD,
  kerbrute, Impacket, PowerView.
  Do NOT use for web application testing — use **web-discovery** instead.
  Do NOT use for cloud-only Azure AD/Entra ID — use cloud-specific skills.
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

Check for `./engagement/` directory. If absent:
- **Guided**: Ask if the user wants to initialize an engagement directory.
- **Autonomous**: Create it automatically with `scope.md`, `state.md`,
  `activity.md`, `findings.md`, and `evidence/`.

When an engagement directory exists, log as you work:
- **Activity** -> append to `engagement/activity.md` at milestones:
  `### [HH:MM] ad-discovery -> <domain>` with enumeration results.
- **Evidence** -> save BloodHound JSON, enumeration output, and scan results
  to `engagement/evidence/` (e.g., `ad-enum-bloodhound.zip`, `ad-enum-spns.txt`,
  `ad-enum-shares.txt`).

### Invocation Log

Immediately on activation — before reading state.md or doing any assessment —
log invocation to both the screen and activity.md:

1. **On-screen**: Print `[ad-discovery] Activated → <target>` so the operator
   sees which skill is running.
2. **activity.md**: Append:
   ```
   ### [HH:MM] ad-discovery → <target>
   - Invoked (assessment starting)
   ```

This entry must be written NOW, not deferred. Subsequent milestone entries
append bullet points under this same header.


## State Management

If `engagement/state.md` exists, read it before starting. Use it to:
- Skip re-enumeration of already-mapped targets and services
- Leverage existing credentials for authenticated enumeration
- Check what techniques have already been tried (Blocked section)

Write `engagement/state.md` at these checkpoints (not just at completion):
1. **After confirming a vulnerability** — add to Vulns with `[found]`
2. **After successful exploitation** — add credentials, access, pivot paths
3. **Before routing to another skill** — the next skill reads state.md on activation

At each checkpoint and on completion, update the relevant sections of
`engagement/state.md`:
- **Targets**: DCs, member servers, workstations, services discovered
- **Credentials**: Any creds found in descriptions, shares, or SYSVOL
- **Vulns**: Attack surface findings (SPNs, delegation, weak ACLs, ADCS)
- **Pivot Map**: Enumeration findings mapped to technique skills
- **Blocked**: Enumeration that failed and why

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
- Domain name, DC hostnames, OS versions -> record in state.md

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
hash capture. Route to **auth-coercion-relay** for exploitation.

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

If SPNs found on user accounts -> route to **kerberos-roasting**.

### AS-REP Roastable Accounts

```bash
# Impacket — enumerate users without pre-auth
GetNPUsers.py DOMAIN/user:'Password123' -dc-ip DC_IP

# bloodyAD — LDAP filter for DONT_REQ_PREAUTH
bloodyAD -u user -p 'Password123' -d DOMAIN.LOCAL --host DC_IP \
  get search --filter '(&(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))' \
  --attr sAMAccountName
```

If found -> route to **kerberos-roasting** (AS-REP section).

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

If found -> route to **kerberos-delegation**.

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

If readable -> route to **credential-dumping**.

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

If trusts found -> route to **trust-attacks**.

### Share Enumeration

```bash
# NetExec — find accessible shares
nxc smb 10.10.10.0/24 -u 'user' -p 'Password123' --shares

# Spider shares for sensitive files
nxc smb DC01.DOMAIN.LOCAL -u 'user' -p 'Password123' -M spider_plus
```

Check SYSVOL/NETLOGON for Group Policy Preferences (GPP) passwords, scripts
with embedded credentials, and configuration files.

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

If local admin found -> route to **credential-dumping** (SAM/LSASS), then
**pass-the-hash** for lateral movement.

### SCCM / Deployment

```bash
# SCCM discovery
python3 sccmhunter.py find -u 'user' -p 'Password123' -d DOMAIN.LOCAL -dc-ip DC_IP
```

If SCCM found -> route to **sccm-exploitation**.

## Step 5: Attack Surface Routing

Map enumeration findings to technique skills. This is the core routing table.

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

**Before routing**: Write `engagement/state.md` and append to
`engagement/activity.md` with results so far. The next skill reads state.md
on activation — stale state means duplicate work or missed context.

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

- **KRB_AP_ERR_SKEW**: Clock out of sync. Fix with `sudo ntpdate DC_IP` or
  `sudo rdate -n DC_IP` (requires root — present to user for manual execution)
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
