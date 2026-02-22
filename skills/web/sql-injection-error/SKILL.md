---
name: sql-injection-error
description: >
  Guide error-based SQL injection exploitation during authorized penetration testing.
  Use when the user has found a SQL injection point and the application returns database
  error messages. Also use when someone says "I see SQL errors", "error-based SQLi",
  "the app shows database errors", or "EXTRACTVALUE / CONVERT / CAST injection".
  Do NOT use for blind injection (no errors visible) — that's sql-injection-blind.
---

# Error-Based SQL Injection

You are guiding a penetration tester through error-based SQL injection exploitation.
The tester has found an injection point where the application displays database error
messages. Your job is to help them extract data efficiently.

## Workflow

### Step 1: Assess the situation

Ask the tester (if not already known):
1. **What's the injection point?** — URL, parameter name, request method
2. **What error have you seen?** — paste the error message
3. **Do you know the DBMS?** — if not, you'll fingerprint it

If they've already shared this context, skip straight to the relevant step.

### Step 2: Identify the DBMS

If the DBMS is unknown, fingerprint it from the error message. Read the reference
material for error signatures:

```
Read ~/claude/red-run/skills/web/sql-injection-error/skill.md
```

Common error fingerprints:
- "You have an error in your SQL syntax" → MySQL
- "Unclosed quotation mark" / "CONVERT" → MSSQL
- "ERROR: invalid input syntax for" → PostgreSQL
- "ORA-" prefix → Oracle

If the error doesn't clearly identify the DBMS, suggest these identification payloads:
- `' AND EXTRACTVALUE(1,CONCAT(0x7e,version()))--+` (MySQL)
- `' AND 1=CONVERT(INT,@@version)--+` (MSSQL)
- `' AND 1=CAST(version() AS INT)--+` (PostgreSQL)
- `' AND 1=utl_inaddr.get_host_name((SELECT banner FROM v$version WHERE ROWNUM=1))--+` (Oracle)

### Step 3: Extract data

Once DBMS is confirmed, load the full technique reference:

```
Read ~/claude/red-run/skills/web/sql-injection-error/skill.md
```

Walk the tester through extraction in this order:
1. **Current user and database** — confirms extraction works
2. **List databases/schemas** — enumerate available targets
3. **List tables** — in the target database
4. **List columns** — in the target table
5. **Extract data** — credentials, secrets, flags

For each step:
- Provide the exact payload for their DBMS, substituting their actual parameter and injection point
- Warn about the ~32 character truncation limit (MySQL EXTRACTVALUE/UPDATEXML) and show SUBSTRING pagination if needed
- If a payload is blocked, suggest alternatives from the reference (UPDATEXML → GTID_SUBSET → JSON_KEYS → FLOOR(RAND()))

### Step 4: Handle problems

If the tester hits issues, consult the Troubleshooting section of the reference skill
and the source material:

```
Read ~/docs/public-security-references/SQL Injection/README.md
```

Common problems:
- **WAF blocking keywords** — try conditional comments, hex encoding, alternative functions
- **Output truncated** — use SUBSTRING pagination
- **Errors no longer showing** — may have triggered rate limiting; switch to blind techniques
- **Need to go faster** — suggest sqlmap with `--technique=E`

### Step 5: Document and escalate

After extracting target data:
- Summarize what was extracted
- Suggest post-exploitation paths (file read, command execution, credential reuse)
- Reference other skills as appropriate:
  - `sql-injection-stacked` for command execution via stacked queries
  - `sql-injection-union` if UNION becomes viable
  - `sql-injection-blind` if errors stop appearing

## Source Material

When you need deeper reference for edge cases, WAF bypass, or DB-specific syntax:

```
Read ~/docs/public-security-references/SQL Injection/MySQL Injection.md
Read ~/docs/public-security-references/SQL Injection/MSSQL Injection.md
Read ~/docs/public-security-references/SQL Injection/PostgreSQL Injection.md
Read ~/docs/public-security-references/SQL Injection/OracleSQL Injection.md
Read ~/docs/public-security-references/src/pentesting-web/sql-injection/README.md
```

## Important

- All testing must be under explicit written authorization
- Prefer non-destructive read-only extraction — error-based is inherently read-only
- Save evidence (request/response pairs) as you go
- OPSEC: error-based payloads appear in application and DB logs
