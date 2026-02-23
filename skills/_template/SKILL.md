---
name: <skill-name>
description: >
  <What this skill does in one sentence>. Use this skill when the user
  <explicit trigger conditions>. Also triggers on: "<phrase1>", "<phrase2>",
  "<phrase3>". OPSEC: <low|medium|high>. Tools: <tool1>, <tool2>.
  Do NOT use when <negative conditions> — use <other-skill> instead.
---

# <Skill Display Name>

You are helping a penetration tester with <technique description>. All testing
is under explicit written authorization.

## Mode

Check if the user or orchestrator has set a mode:
- **Guided** (default): Explain each step before executing. Ask for confirmation.
  Present options at decision forks. Show what to look for in output.
- **Autonomous**: Execute end-to-end. Make triage decisions at forks. Report
  findings at milestones. Only pause for destructive or high-OPSEC actions.

If unclear, default to guided.

## Engagement Logging

Check for `./engagement/` directory. If absent:
- **Guided**: Ask if the user wants to initialize an engagement directory.
- **Autonomous**: Create it automatically with `activity.md`, `findings.md`, and
  `evidence/`.

When an engagement directory exists, log as you work:
- **Activity** → append to `engagement/activity.md` at milestones (test confirmed,
  data extracted, finding discovered, pivot to another skill):
  `### [HH:MM] <skill-name> → <target>` with bullet points of actions and results.
- **Findings** → append to `engagement/findings.md` when a vulnerability is confirmed:
  `## N. Title [Severity]` with target, technique, impact, evidence path, repro command.
- **Evidence** → save significant output to `engagement/evidence/` with descriptive
  filenames (e.g., `sqli-users-dump.txt`, `ssrf-aws-creds.json`).

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

- <Required access level or position>
- <Required tools (with install note)>
- <Conditions that must be true>

## Step 1: Assess

If not already provided by the orchestrator or conversation context, determine:
1. <Key info needed>
2. <Key info needed>
3. <Key info needed>

Skip if context was already provided.

## Step 2: Confirm Vulnerability

<How to verify the technique applies. Embedded test payloads.>

## Step 3: Exploit

### Variant A: <Description>

```bash
# Explanation of what this does
command arg1 arg2
```

### Variant B: <Description>

```bash
# Alternative when Variant A fails or is blocked
command arg1 arg2
```

## Step N: Escalate or Pivot

After completing this technique:
- <Outcome 1>: Route to **<other-skill-name>**
- <Outcome 2>: Route to **<other-skill-name>**
- <Outcome 3>: Summarize findings, suggest next steps

When routing, pass along: injection point, target technology, current mode,
and any payloads that already succeeded.

## Troubleshooting

### <Common Problem>
<Solution>
