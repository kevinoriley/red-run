---
name: retrospective
description: >
  Post-engagement lessons-learned retrospective. Reads the engagement directory,
  analyzes skill routing decisions, identifies knowledge gaps and missing skills,
  and produces an actionable improvement report. Use when the user asks for a
  retrospective, lessons learned, engagement review, skill gaps analysis, or
  post-engagement review. Also triggers on: "what went wrong", "what worked",
  "review the engagement", "skill coverage audit", "how did the skills perform".
  OPSEC: low — reads local files only, no target interaction.
  Tools: none (file reads and analysis only).
  Do NOT use during an active engagement — this is a post-mortem skill.
  Do NOT use for formal finding writeups — this skill analyzes skill library
  performance, not individual vulnerabilities.
---

# Engagement Retrospective

You are conducting a post-engagement retrospective for a penetration tester.
Your job is to analyze what happened during the engagement, evaluate how the
skill library performed, identify gaps, and produce actionable improvement
items. All analysis is local — you never touch the target.

## Prerequisites

- `engagement/` directory must exist with at least `activity.md` and `state.md`
- The engagement should be complete or paused — this is a post-mortem, not a
  mid-engagement review
- Access to the red-run skill library (installed via `install.sh`)

If `engagement/activity.md` or `engagement/state.md` are missing, tell the user:

> Cannot run retrospective — engagement/activity.md and engagement/state.md are
> required. These files are created by the orchestrator or discovery skills
> during an engagement.

## Engagement Logging

If `engagement/` exists (it should — that's a prerequisite), log this
retrospective:

1. **On-screen**: Print `[retrospective] Activated → engagement review`
2. **activity.md**: Append:
   ```
   ### [YYYY-MM-DD HH:MM:SS] retrospective → engagement review
   - Invoked (post-engagement analysis starting)
   ```

On completion, save the full report to `engagement/retrospective.md` and append
a final entry to activity.md summarizing the actionable items found.

## Step 1: Gather Context

Read all engagement files:

1. `engagement/scope.md` — targets, objectives, rules of engagement
2. `engagement/state.md` — final engagement state snapshot
3. `engagement/activity.md` — chronological activity log
4. `engagement/findings.md` — confirmed vulnerabilities

If any file is missing (other than the required two), note it but continue with
what's available.

Summarize the engagement for the user:
- **Target(s)** and objective(s)
- **Outcome**: Were objectives met? Partially? Not at all?
- **Timeline**: How many skill invocations, roughly how long
- **Final state**: What access/credentials/vulns existed at completion

Ask the user if this summary is accurate and whether there's context not
captured in the engagement files (e.g., decisions made verbally, time pressure,
scope changes mid-engagement).

## Step 2: Skill Routing Analysis

Read `engagement/activity.md` and compare against the skill library.

For each activity entry, determine:
1. **Was a skill invoked?** Check for skill name references in activity entries.
2. **Was it the right skill?** Did the activity match the skill's scope?
3. **Were any skills skipped?** Look for technique execution that should have
   been routed through a skill (e.g., running sqlmap directly instead of
   invoking sql-injection-union).
4. **Was anything done inline that a skill covers?** Identify commands or
   techniques executed outside the skill framework.

Build a routing ledger:

| Activity | Skill Used | Correct? | Notes |
|----------|-----------|----------|-------|
| Web recon | web-discovery | Yes | — |
| SQL injection | (inline) | No | Should have routed to sql-injection-union |

Present this ledger to the user and discuss any routing decisions that seem
wrong or suboptimal.

## Step 3: Knowledge Gap Analysis

For each skill that was invoked during the engagement, evaluate:

1. **Did the skill have adequate payloads?** Were hand-crafted payloads needed
   that should be embedded in the skill?
2. **Were edge cases hit?** Did the target present conditions the skill didn't
   cover (e.g., unusual encodings, non-standard ports, WAF bypass needed)?
3. **Was troubleshooting adequate?** Did the skill's troubleshooting section
   cover the problems encountered?
4. **Was the methodology complete?** Were steps missing or out of order?
5. **Were tool commands correct?** Did embedded commands work or need
   modification?

For each gap found, note the specific skill and what's missing.

## Step 4: Missing Skill Identification

Identify techniques used during the engagement that don't have a corresponding
skill. Consider:

1. **Techniques used manually** — anything done by hand that was non-trivial
   and repeatable
2. **Tool workflows** — complex tool chains that could be standardized
3. **Edge-case techniques** — bypass methods, unusual attack paths, or niche
   protocols encountered

For each missing skill, propose:
- **Skill name** (kebab-case)
- **Category** (web, ad, privesc, network, etc.)
- **What it would cover**
- **Why it's needed** (one-off or likely to recur?)

## Step 5: Operational Review

Evaluate four operational dimensions:

### Manual Interventions
- What was done by hand that a skill should automate?
- Were payloads crafted manually that should be embedded?
- Was tool setup or configuration needed that should be in prerequisites?

### OPSEC
- Were OPSEC ratings respected? Did noisy skills get used when quiet
  alternatives existed?
- Were detection-prone techniques used unnecessarily?
- Was Kerberos-first authentication followed in AD environments?
- Were any OPSEC incidents noted (alerts triggered, blocks encountered)?

### Routing Efficiency
- Were there unnecessary detours? (e.g., broad scanning when targeted testing
  would have found the same issue faster)
- Were redundant scans run? (e.g., re-scanning ports already in state.md)
- Were there missed shortcuts? (e.g., credentials found early but not tested
  against other services until late)
- Did the orchestrator chain vulnerabilities effectively?

### State Management
- Was `state.md` kept current? Were there stale reads?
- Did skills write state before routing to the next skill?
- Was the Blocked section used effectively?
- Was the Pivot Map accurate and used for decision-making?

## Step 6: Critical Path Review

Map the actual kill chain from recon to objective (or as far as the engagement
got):

```
[recon] → [discovery] → [initial access] → [pivot/escalation] → [objective]
```

For each step, note:
- What skill handled it
- Whether it was the fastest path
- What blocked progress and how it was resolved
- Whether steps could have been parallelized or reordered

Identify bottlenecks — where did the engagement stall, and why?

## Step 7: Write Report

Produce `engagement/retrospective.md` with all findings:

```markdown
# Engagement Retrospective

## Summary
<One paragraph: target, objective, outcome>

## Kill Chain
<Ordered attack path from recon to objective>

## Skill Routing Review
### Skills Invoked
- <skill-name> — <what it did, whether it performed well>
### Skills Skipped (Should Have Been Invoked)
- <skill-name> — <why it should have been invoked, what was done instead>
### Inline Execution (Should Have Been Routed)
- <description of what was done inline instead of via a skill>

## Knowledge Gaps
### <skill-name>
- <missing payload, edge case, or methodology>

## Missing Skills
- **<proposed-skill-name>** (<category>) — <what it would cover, why needed>

## Operational Review
### Manual Interventions
- <what was done manually that should be automated>
### OPSEC
- <assessment of noise level, detection surface>
### Routing Efficiency
- <unnecessary detours, missed shortcuts>
### State Management
- <quality of state.md flow, stale reads, missing updates>

## Actionable Items
Priority-ordered list:
1. [skill-update] <skill-name>: <specific change needed>
2. [new-skill] <proposed-name>: <brief description>
3. [routing-fix] <skill-name>: <routing table update needed>
4. [template-fix] <change to _template or conventions>
```

After writing the report, append a summary to `engagement/activity.md`:

```
### [YYYY-MM-DD HH:MM:SS] retrospective → complete
- Report written to engagement/retrospective.md
- Actionable items: N skill-update, N new-skill, N routing-fix, N template-fix
```

Present the actionable items to the user and ask which ones to prioritize.

## Troubleshooting

### Engagement directory exists but files are empty
The engagement may have been run without logging enabled. Do the retrospective
from conversation context instead — ask the user to describe what happened, then
analyze the current session transcript.

### Activity log has no skill references
Skills may have been executed inline (without the Skill tool) or the engagement
predates the current skill library. Flag this as a routing gap and reconstruct
the timeline from state.md and findings.md instead.

### Multiple engagement directories
If the user has run multiple engagements, ask which one to review. Look for
date-stamped directories or scope.md contents to differentiate them.
