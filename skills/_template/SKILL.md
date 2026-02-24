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
- **Guided** (default): Before executing any command that sends traffic to a
  target, present the command with a one-line explanation of what it does and
  why. Wait for explicit user approval before executing. Never batch multiple
  target-touching commands without approval — present them one at a time (or as
  a small logical group if they achieve a single objective, e.g., "enumerate SMB
  shares"). Local-only operations (file writes, output parsing, engagement
  logging, hash cracking) do not require approval. At decision forks, present
  options and let the user choose.
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

### Invocation Log

Immediately on activation — before reading state.md or doing any assessment —
log invocation to both the screen and activity.md:

1. **On-screen**: Print `[<skill-name>] Activated → <target>` so the operator
   sees which skill is running.
2. **activity.md**: Append:
   ```
   ### [HH:MM] <skill-name> → <target>
   - Invoked (assessment starting)
   ```

This entry must be written NOW, not deferred. Subsequent milestone entries
append bullet points under this same header.

## Skill Routing Is Mandatory

When this skill says "Route to **skill-name**" or "→ **skill-name**", you MUST
invoke that skill using the Skill tool. Do NOT execute the technique inline —
even if the attack is trivial or you already know the answer. Skills contain
operator-specific methodology, client-scoped payloads, and edge-case handling
that general knowledge does not.

This applies in both guided and autonomous modes. Autonomous mode means you
make routing decisions without asking — it does not mean you skip skills.

**Scope boundary:** This skill covers <scope>. If your findings lead outside
this scope, STOP — update state.md and route to the appropriate skill. Do not
continue past your scope boundary.

## State Management

If `engagement/state.md` exists, read it before starting. Use it to:
- Skip re-testing targets, parameters, or vulns already confirmed
- Leverage existing credentials or access for this technique
- Understand what's been tried and failed (check Blocked section)

Write `engagement/state.md` at these checkpoints (not just at completion):
1. **After confirming a vulnerability** — add to Vulns with `[found]`
2. **After successful exploitation** — add credentials, access, pivot paths
3. **Before routing to another skill** — the next skill reads state.md on activation

At each checkpoint and on completion, update the relevant sections of
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

**Before routing**: Write `engagement/state.md` and append to
`engagement/activity.md` with results so far. The next skill reads state.md
on activation — stale state means duplicate work or missed context.

After completing this technique:
- <Outcome 1>: STOP. Invoke **<other-skill-name>** via the Skill tool. Pass: <context>. Do not execute <category> commands inline.
- <Outcome 2>: STOP. Invoke **<other-skill-name>** via the Skill tool. Pass: <context>. Do not execute <category> commands inline.
- <Outcome 3>: Summarize findings, suggest next steps

When routing, always pass along: injection point, target technology, current
mode, and any payloads that already succeeded.

## Troubleshooting

### <Common Problem>
<Solution>
