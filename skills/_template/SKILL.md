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

## Deep Reference

For edge cases, WAF bypass, or alternative payloads beyond what's embedded above:

```
Read ~/docs/public-security-references/<relevant-path>
Read ~/docs/public-security-references/src/<relevant-path>
Read ~/docs/public-security-references/<relevant-path>
```

## Troubleshooting

### <Common Problem>
<Solution>
