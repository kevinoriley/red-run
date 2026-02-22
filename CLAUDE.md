# red-run

Claude Code skill library for penetration testing and CTF work.

## Directory Layout

```
red-run/
  skills/
    _template/          # Canonical skill template
      skill.md
    web/                # Web application attacks
    ad/                 # Active Directory
    privesc/            # Privilege escalation (Windows, Linux, macOS)
    cloud/              # AWS, Azure, GCP
    network/            # Recon, protocols, pivoting
    containers/         # Docker, Kubernetes, CI/CD
    c2/                 # Command and control frameworks
    redteam/            # Initial access, evasion, persistence, creds
  findings.md           # Source material research notes
  task_plan.md          # Phased build plan
  progress.md           # Session log
```

## Skill File Format

Every skill lives at `skills/<category>/<skill-name>/skill.md` and follows the template at `skills/_template/skill.md`.

### Required sections
- **Front matter** (YAML): name, description, category, tools, opsec level, references
- **Prerequisites**: access level, tools, conditions
- **Enumeration**: detect if target is vulnerable
- **Exploitation**: step-by-step with commented commands
- **Cleanup**: artifact removal

### Optional sections
- Post-Exploitation, Detection, Troubleshooting

### Conventions
- Skill names use kebab-case: `sql-injection-union`, `kerberoasting`, `docker-socket-escape`
- One technique per skill — split broad topics into focused skills
- Commands must include comments explaining what each step does
- Reference the source file(s) in front matter so content can be traced back
- OPSEC rating: `low` = passive/read-only, `medium` = creates artifacts, `high` = noisy/detected by EDR

## Reference Material

| Repo | Path | Strength |
|------|------|----------|
| public-security-references | `~/docs/public-security-references` | AD, red team ops, cloud, evasion |
| public-security-references | `~/docs/public-security-references` | Web payloads, injection techniques |
| public-security-references | `~/docs/public-security-references` | Broadest scope, binary exploitation, macOS, mobile, network protocols |

When authoring skills, synthesize from all three repos — don't just copy from one.
