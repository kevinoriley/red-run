# Writing Skills

This guide covers how to create new skills for the red-run library. Every skill is a self-contained `SKILL.md` file that lives at `skills/<category>/<skill-name>/SKILL.md`.

## Skill File Format

A skill file has two parts: YAML frontmatter (for indexing) and a markdown body (the actual methodology).

### Frontmatter

The frontmatter is required and drives the skill-router's semantic search:

```yaml
---
name: sql-injection-union
description: >
  UNION-based SQL injection extraction for MySQL, MSSQL, PostgreSQL,
  Oracle, and SQLite. Covers column count detection, type matching,
  and multi-table data extraction.
keywords:
  - sqli
  - union select
  - information_schema
  - sqlmap
tools:
  - curl
  - sqlmap
  - browser
opsec: medium
---
```

| Field | Purpose | Indexing |
|-------|---------|---------|
| `name` | Skill identifier (kebab-case) | Exact match |
| `description` | What the skill does, 2-3 sentences | Semantic embedding |
| `keywords` | Search terms — technique names, tool names, CVE IDs, protocol names | Exact match boost |
| `tools` | Tools used by this skill | Tool-name lookup |
| `opsec` | Detection risk: `low`, `medium`, `high` | Included in search results |

The MCP skill-router indexer builds embedding documents from these fields. `description` provides semantic context for natural-language queries, `keywords` provide exact-match terms, and `tools` enable "what skill uses nmap?" lookups.

> **Description guidelines:** Focus on technique scope and when to use it. Don't include trigger phrases, negative conditions, or OPSEC details — those belong in `keywords` and `opsec` respectively.

### Body Structure

The body follows a consistent structure. Use the template at `skills/_template/SKILL.md` as your starting point.

#### 1. Preamble

```markdown
# SQL Injection — UNION-Based

You are helping a penetration tester with UNION-based SQL injection.
All testing is under explicit written authorization.
```

Sets the context for the teammate executing the skill.

#### 2. Engagement Logging

```markdown
## Engagement Logging

Check for `./engagement/` directory. If absent, proceed without logging.

When an engagement directory exists:
- Print `[sql-injection-union] Activated → <target>` on activation.
- Save evidence to `engagement/evidence/` with descriptive filenames.
```

Skills save evidence files. State writes go through the state MCP server. Deduplication is at the database level.

#### 3. Scope Boundary

Defines what the skill covers and when to stop. When the skill reaches its scope boundary (via a routing instruction or discovering out-of-scope findings), it must return to the orchestrator rather than continuing.

#### 4. State Management

```markdown
## State Management

Call `get_state_summary()` from the state MCP server to read
current engagement state.
```

Skills read state to avoid re-testing confirmed vulnerabilities, leverage existing credentials, and check what's been tried.

> **State access:** Teammates read state directly via `get_state_summary()`. All writes go through the **state-mgr teammate** via structured `[action]` messages — teammates never call state write tools directly.

> **Technique-vuln linkage:** If a skill produces credentials through an active technique (roasting, dumping, injection, coercion), the teammate must create a vuln record for the technique before reporting the credential with `via_vuln_id`. State-mgr enforces this gate.

#### 5. Tool Discovery

Skills check locally for tools before downloading — pentest distros often have everything pre-installed. The template includes the standard search order.

#### 6. Exploit and Tool Transfer

The **attackbox-first workflow**: download on attackbox, review, serve via HTTP, pull from target. Never download directly to the target from the internet.

#### 7. Prerequisites

Required access level, tools, and conditions. Includes standard subsections for:

- **Special characters in credentials** — the Write-to-file workaround for `!` and other shell metacharacters
- **Impacket binary naming** — checking for `tool.py` vs `impacket-tool` variants
- **Tool output directory** — `cd $TMPDIR &&` prefix for tools that write to CWD

#### 8. Steps

The core methodology, structured as assess → confirm → exploit → escalate/pivot:

```markdown
## Step 1: Assess
Determine target database, injection point, column count.

## Step 2: Confirm Vulnerability
Test with ORDER BY / UNION SELECT NULL payloads.

## Step 3: Exploit
### Variant A: MySQL
### Variant B: MSSQL
### Variant C: PostgreSQL

## Step 4: Escalate or Pivot
- DB creds found → STOP. Return recommending **pass-the-hash**.
- File read available → STOP. Return recommending **lfi**.
```

#### 9. Stall Detection

Standard section (from template) that defines the 5-round stall rule — if the teammate spends 5+ rounds on the same failure, it must stop and message the lead.

#### 10. AV/EDR Detection

Standard section (from template) for recognizing and handling antivirus detection. The teammate stops immediately and messages the lead with structured context for the bypass teammate.

#### 11. Troubleshooting

Common problems and solutions specific to this technique.

## Conventions

### Naming

- **kebab-case**: `sql-injection-union`, `kerberos-roasting`, `docker-socket-escape`
- **One technique per skill**: Split broad topics into focused skills. "SQL injection" becomes four skills: union, error, blind, stacked.
- **Discovery vs technique**: Discovery skills are named `<domain>-discovery` (e.g., `web-discovery`, `ad-discovery`). Technique skills are named after the technique.

### Embedded Payloads

Embed the top 2-3 payloads per database/variant directly in the skill for 80% coverage. Don't rely on external payload lists — the skill should be self-contained.

```markdown
### MySQL UNION Extraction

​```bash
# Extract version
' UNION SELECT NULL,version(),NULL-- -

# Extract all tables
' UNION SELECT NULL,GROUP_CONCAT(table_name),NULL
  FROM information_schema.tables
  WHERE table_schema=database()-- -
​```
```

### OPSEC Ratings

Rate honestly based on detection likelihood:

- **low** — passive enumeration, read-only queries, no artifacts
- **medium** — creates files on target, failed auth attempts, tool execution
- **high** — kernel exploits, credential dumping, AV evasion, noisy scans

## Inter-Skill Routing

Skills reference other skills using **bold names** in their escalation sections:

```markdown
## Step 4: Escalate or Pivot

- Database credentials found: STOP. Return to orchestrator recommending
  **pass-the-hash**. Pass: username, NTLM hash, target hosts.
- File read achieved: STOP. Return to orchestrator recommending
  **lfi**. Pass: URL, parameter, working wrapper.
```

The lead uses these bold references to search for the next skill and assign it to the right teammate.

> **Teammates never self-route:** Skills must STOP and return when they hit a routing instruction. The teammate must not load or execute another skill — the lead decides what runs next.

### Discovery Skill Maintenance

When creating a new technique skill, **update the corresponding discovery skill's routing table** to include it. For example, adding a new web technique skill requires updating `web-discovery`'s routing section.

Discovery skills must route to every technique skill in their domain. A technique skill that isn't referenced by any discovery skill will never be invoked.

## Attackbox-First Transfer

Never download exploits or tools directly to the target from the internet. The mandatory workflow:

1. **Check locally first** — `which tool`, `find /opt /usr/share -name 'tool'`
2. **Download on attackbox** (only if not found locally)
3. **Review** — inspect source code before transferring
4. **Serve** — `python3 -m http.server 8080` from the directory
5. **Pull from target** — `wget` or `curl` from the target to the attackbox

Inline source code written via heredoc is fine — the operator can read it directly.

## Kerberos-First Convention

All AD skills default to Kerberos authentication via ccache:

```bash
# Get TGT
getTGT.py DOMAIN/user -hashes :NTHASH
export KRB5CCNAME=$TMPDIR/user.ccache

# Use Kerberos auth in all tools
impacket-secretsdump -k -no-pass DC.domain.local
nxc smb DC.domain.local --use-kcache
certipy req -k -no-pass -dc-ip 10.10.10.5
bloodyAD -k -d domain.local --host DC.domain.local
```

This avoids NTLM-specific detections (Event 4776, CrowdStrike Identity Module PTH signatures). Skills where Kerberos doesn't apply (relay, coercion, password spraying) must explicitly state why and note the NTLM detection surface.

## Template Walkthrough

The full template is at `skills/_template/SKILL.md`. To create a new skill:

1. **Copy the template**: `cp -r skills/_template skills/<category>/<skill-name>`
2. **Fill frontmatter**: Set name, description, keywords, tools, opsec
3. **Write the preamble**: One sentence setting the context
4. **Define scope**: What this skill covers and where it stops
5. **Write steps**: Assess → Confirm → Exploit → Escalate/Pivot
6. **Add payloads**: Embed the most common payloads directly
7. **Add troubleshooting**: Document known failure modes and fixes
8. **Update discovery skill**: Add routing entry in the parent discovery skill
9. **Re-index**: Run the skill-router indexer to pick up the new skill

The template includes standard sections for engagement logging, state management, tool discovery, stall detection, AV/EDR handling, and DNS failure handling. Keep these — they ensure consistent teammate behavior across all skills.
