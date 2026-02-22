# red-run

Claude Code skill library for penetration testing and CTF work.

## What is this?

A collection of structured, technique-focused skills that Claude Code can use during authorized security assessments and CTF competitions. Each skill is a markdown file with enumeration steps, exploitation commands, per-technology variants, cleanup procedures, and OPSEC notes.

The goal: when you're in a pentest or CTF and you know (or suspect) what you're up against, Claude Code can pull the relevant skill and walk through exploitation step-by-step with real commands — not generic advice.

## How it works

Skills are organized by category and technique:

```
skills/
  web/
    web-vuln-discovery/skill.md     # Entry point — fuzz, test, route to technique
    sql-injection-union/skill.md    # UNION-based SQLi (MySQL, MSSQL, Postgres, Oracle, SQLite)
    sql-injection-error/skill.md    # Error-based extraction
    sql-injection-blind/skill.md    # Boolean, time-based, OOB blind SQLi
    ...
  ad/                               # Active Directory attacks
  privesc/                          # Privilege escalation
  cloud/                            # AWS, Azure, GCP
  network/                          # Recon, pivoting, protocols
  containers/                       # Docker, K8s, CI/CD
  c2/                               # Command and control
  redteam/                          # Initial access, evasion, persistence
```

Each category has a **discovery skill** as the entry point. Discovery skills help you identify what's vulnerable and route to the right technique skill via a decision tree.

## Source material

Skills are synthesized from three reference repositories:

| Repo | Strength |
|------|----------|
| [public-security-references](<removed>) | AD, red team ops, cloud, evasion |
| [public-security-references](<removed>) | Web payloads, injection techniques |
| [public-security-references](<removed>) | Broadest scope — binary exploitation, macOS, mobile, network protocols |

## Status

Work in progress. See `task_plan.md` for the full build plan and current phase.

## Disclaimer

These skills are for use in **authorized security testing, CTF competitions, and educational contexts only**. Do not use them against systems you do not have explicit written permission to test.
