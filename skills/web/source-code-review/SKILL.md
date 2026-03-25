---
name: source-code-review
description: >
  Security-focused source code review for application source obtained during
  an engagement (git dumps, LFI reads, share access, backups). Finds hardcoded
  credentials, injection sinks, auth bypass paths, and framework-specific
  weaknesses. Use when source code is discovered from any source.
keywords:
  - source code review
  - code audit
  - git dump
  - git-dumper
  - .git exposure
  - hardcoded credentials
  - hardcoded password
  - application source
  - code review
  - SAST
  - static analysis
tools:
  - grep
  - read
  - glob
opsec: low
---

# Source Code Review

You are helping a penetration tester review application source code for
security vulnerabilities. All testing is under explicit written authorization.

This skill is designed for the **research teammate (opus)**. Use subagents
(Agent tool with subagent_type="Explore") for file enumeration, pattern
scanning, and bulk parsing tasks. Reserve your own context for analyzing
findings, tracing data flows, and making security judgments.

## Engagement Logging

Check for `./engagement/` directory. If absent, proceed without logging.

When an engagement directory exists:
- Print `[source-code-review] Activated → <target>` on activation.
- Save findings to `engagement/evidence/research/source-review-<app>.md`.

## Scope Boundary

This skill covers static analysis of application source for exploitable
vulnerabilities. When you identify a confirmed vulnerability class, STOP
and return with the finding — the lead routes to the matching technique
skill for exploitation.

Do not attempt exploitation. Do not modify source files. Do not run the
application. Analyze only.

## State Management

Call `get_state_summary()` to understand current engagement context —
existing credentials, access levels, and known vulns inform what to
prioritize in the review.

## Prerequisites

- Application source code accessible on the attackbox (typically in
  `engagement/evidence/` from git-dumper, LFI reads, or share access)
- The lead provides: source path, technology hints, what access produced
  the source, and what the engagement needs (creds, auth bypass, RCE path)

## Step 1: Reconnaissance (use subagent)

Spawn an Explore subagent to map the codebase structure:

```
"List all files in <source_path> grouped by type. Identify:
 - Framework (Django, Flask, Express, Spring, Laravel, .NET, etc.)
 - Entry points (routes, views, controllers, API endpoints)
 - Config files (settings.py, .env, web.config, application.yml, etc.)
 - Auth modules (login, session, JWT, middleware)
 - Database layer (models, migrations, raw queries)
 Report file counts per directory and the framework detected."
```

## Step 2: Credential Harvesting (use subagent)

Spawn an Explore subagent to grep for secrets — this is the highest-value,
lowest-effort pass:

```
"Search all files in <source_path> for hardcoded secrets. Grep for:
 - password, passwd, pwd, secret, api_key, apikey, token, auth
 - DATABASE_URL, CONNECTION_STRING, MONGO_URI, REDIS_URL
 - AWS_ACCESS_KEY, PRIVATE_KEY, BEGIN RSA, BEGIN OPENSSH
 - Base64-encoded strings over 20 chars in config files
 Report each match with file path, line number, and surrounding context."
```

Review the subagent's results. Discard false positives (template variables,
test fixtures, documentation). For confirmed credentials:
- Message state-mgr: `[add-cred]` for each
- Note which service each credential is for

## Step 3: Auth & Session Review

Read auth-related files yourself (these require security judgment):

- **Login flow** — password comparison (timing-safe?), lockout logic, MFA
- **Session handling** — cookie flags, token generation, session fixation
- **JWT** — algorithm confusion (none/HS256 vs RS256), secret strength, claim validation
- **Role checks** — are admin endpoints checking roles? Decorator/middleware gaps?
- **Password reset** — predictable tokens, host header injection, rate limiting
- **Registration** — can you create admin accounts? Mass assignment?

## Step 4: Injection Surface Mapping (use subagent)

Spawn an Explore subagent to find dangerous sinks:

```
"Search <source_path> for injection patterns. For each match report
 file, line, and the dangerous function:

 SQL: execute(, raw(, query(, cursor.execute, .extra(, $where, db.query
 Command: os.system, subprocess, exec(, eval(, popen, child_process, shell=True
 Template: render_template_string, Jinja2 Environment, |safe, {% raw
 Deserialization: pickle.loads, yaml.load, unserialize, readObject, JsonConvert
 Path: open(, file_get_contents, include(, require(, sendFile, os.path.join + user input
 SSRF: requests.get, urllib, fetch(, HttpClient with user-controlled URL
 XSS: innerHTML, document.write, v-html, dangerouslySetInnerHTML"
```

For each finding, trace the data flow yourself:
- Does user input reach the sink without sanitization?
- Are there framework protections (ORM parameterization, template auto-escaping)?
- What's the impact (RCE, data access, auth bypass)?

## Step 5: Framework-Specific Checks

Based on the framework detected in Step 1:

**Python/Django:** `DEBUG = True`, `SECRET_KEY` hardcoded, `@csrf_exempt`,
raw SQL in views, `ALLOWED_HOSTS = ['*']`, pickle sessions, custom template tags

**Python/Flask:** `app.secret_key`, `debug=True`, Jinja2 `|safe` filter,
`render_template_string` with user input, no CSRF protection

**PHP/Laravel:** `.env` in webroot, `APP_DEBUG=true`, mass assignment
(`$fillable`/`$guarded`), blade `{!! !!}` unescaped, SQL in raw queries

**Node/Express:** `eval()` with user input, prototype pollution, NoSQL
injection (`$gt`, `$ne`), missing helmet headers, JWT secret in source

**Java/Spring:** SpEL injection, actuator endpoints exposed, insecure
deserialization (ObjectInputStream), Thymeleaf SSTI, path traversal in
resource handlers

**.NET:** `ViewState` MAC disabled, SQL string concatenation, `BinaryFormatter`
deserialization, weak `machineKey`, LDAP injection in DirectorySearcher

## Step 6: Business Logic

Review for logic flaws that aren't injection-based:
- **IDOR** — are object lookups filtered by the current user?
- **Race conditions** — TOC/TOU in payment, voting, token generation
- **Privilege escalation** — can a regular user's request include admin params?
- **Information disclosure** — error messages, stack traces, debug endpoints

## Step 7: Report Findings

Write all findings to `engagement/evidence/research/source-review-<app>.md`.

For each finding:
```
### <Finding Title>
- **Severity:** critical/high/medium/low
- **File:** <path>:<line>
- **Type:** <sqli/cmdi/auth-bypass/hardcoded-cred/etc.>
- **Description:** <what the vulnerability is>
- **Exploitation path:** <how an attacker would use this>
- **Recommended technique skill:** <skill name if applicable>
```

Message state-mgr with `[add-vuln]` for each confirmed vulnerability.
Message lead with the findings file path and one-line summary.

## Troubleshooting

### Source is partial (LFI reads, not full repo)
Focus on the files you have. Config files alone can yield creds and
architecture insights. Single controller files can reveal injection points.

### Codebase is too large (>1000 files)
Prioritize: config → auth → routes/controllers → models → middleware.
Use subagents aggressively for grep passes. Only read files that grep
flagged.

### Obfuscated/minified code
For JavaScript: look for source maps (`.map` files). For PHP: check for
`eval(base64_decode(` patterns. For compiled languages: note in findings
and recommend the lead use a decompiler.
