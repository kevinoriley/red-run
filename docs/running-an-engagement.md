# Running an Engagement

This page describes how the **CTF orchestrator** drives a penetration test from target to objective. The orchestrator is one skill (`skills/orchestrator/SKILL.md`) — a different orchestrator would use the same skill library with completely different workflow logic. See [Architecture](architecture.md#platform-vs-strategy) for more on this separation.

## Starting a Test

Trigger the orchestrator with a target:

```
attack 10.10.10.5
pentest 192.168.1.0/24
hack school.flight.htb
```

Any of these trigger phrases work: `pwn`, `attack`, `pentest`, `hack`, `scan`, `assess`, `test`, `pop`, `engage`, or `CTF target`.

### Scope Gathering

The orchestrator's first action is gathering scope:

1. **Targets** — IPs, hostnames, CIDR ranges
2. **Credentials** — any provided usernames, passwords, hashes
3. **Rules of engagement** — what's in scope, what's off-limits
4. **Objectives** — flags, domain admin, data exfiltration goals

### Engagement Configuration

After the CTF disclaimer, the orchestrator runs a config wizard that captures operator preferences upfront:

| Setting | Options | Default |
|---------|---------|---------|
| C2 framework | shell-server, Sliver, operator-managed | shell-server |
| Web proxy | disabled, Burp on loopback, custom URL | disabled |
| Callback interface | auto, tun0, wg0, custom | auto |
| Default scan type | quick, full | quick |
| Cracking method | local, external rig, skip | local |

These are written to `engagement/config.yaml`. On resume, the orchestrator reads this file and skips the corresponding hard stops — no repeated questions about scan type, proxy, or cracking method.

### Engagement Directory

The orchestrator creates the engagement directory structure:

```
engagement/
├── config.yaml       # Operator preferences from config wizard
├── scope.md          # Target scope and rules of engagement
├── state.db          # SQLite engagement state database
├── dump-state.sh     # Export state.db as markdown (operator convenience)
├── web-proxy.json    # Machine-readable proxy config (from config.yaml)
├── web-proxy.sh      # Shell snippet for proxy env vars (from config.yaml)
└── evidence/         # Saved output and dumps
    └── logs/         # Agent JSONL transcripts
```

It initializes `state.db` via `init_engagement()` and writes the scope to `scope.md`.

## Engagement Workflow

The orchestrator follows this decision flow from target to objective:

<p align="center">
  <img src="../workflow.svg" width="700" alt="Engagement workflow: Scope → Recon → Attack Surface → Discovery & Exploitation → Chaining → Complete">
</p>

## Reconnaissance

After scope setup, the orchestrator runs reconnaissance.

### Scan Type Selection

If `config.yaml` has a default scan type, the orchestrator uses it without prompting. Otherwise:

> **Hard Stop:** The orchestrator pauses and asks the operator to choose a scan type before proceeding. This is one of several **hard stops** — points where the orchestrator requires operator input.

Options:

- **Quick** — Top ports, fast service detection
- **Full** — All 65535 ports with version detection and scripts (`-A -p- -T4`)
- **Custom** — Operator-specified nmap flags
- **Import XML** — Parse existing nmap XML output

The orchestrator spawns the `network-recon-agent` with the `network-recon` skill, which runs nmap via the nmap-server MCP and enumerates discovered services.

### Hostname Resolution

When nmap discovers hostnames that don't resolve from the attackbox, the orchestrator hits a **hard stop**:

1. Writes a `hosts-update.sh` script with the required `/etc/hosts` entries
2. Pauses and asks the operator to run it
3. Resumes only after confirmation

This pattern repeats when web discovery finds virtual hosts that need resolution.

### Web Discovery

If `config.yaml` has a proxy decision, the orchestrator uses it without prompting — `web-proxy.json` and `web-proxy.sh` are generated from the config. Otherwise, when HTTP/HTTPS ports are found, the orchestrator hits a **Web proxy** hard stop. The operator can enable Burp on loopback (`127.0.0.1`), enable Burp on a dedicated proxy IP, or skip proxying entirely.

If Burp proxying is enabled, the orchestrator records the listener URL in `engagement/scope.md`, writes `engagement/web-proxy.json` for browser defaults, and writes `engagement/web-proxy.sh` for CLI tools so subsequent web agents route through the same Burp listener. If the operator skips proxying, those files are still written in direct mode so the original no-proxy behavior is preserved explicitly.

Only after that decision is made does the orchestrator spawn the `web-discovery-agent` with the `web-discovery` skill. This performs content discovery, technology fingerprinting, parameter fuzzing, and vulnerability identification.

## Attack Surface Presentation

After recon, the orchestrator categorizes the attack surface:

- **Web** — HTTP/HTTPS services, applications, APIs
- **Active Directory** — Domain controllers, Kerberos, LDAP
- **SMB** — File shares, named pipes
- **Database** — MSSQL, MySQL, PostgreSQL
- **Containers** — Docker, Kubernetes
- **Remote Access** — SSH, RDP, WinRM

It presents the surface with chain analysis — how vulnerabilities might connect to achieve objectives — and the operator picks the attack path.

## Skill Routing

The orchestrator needs to pick the right skill for each situation. Most of the time, skills tell it what to do next — a discovery skill's decision tree says "if you found SQLi, route to **sql-injection-union**", and the orchestrator looks that up in a hardcoded routing table that maps skill names to agents. But sometimes the orchestrator encounters a situation that doesn't match any hardcoded route — an unusual service, an uncommon vulnerability, a technology the decision trees don't cover. That's where RAG comes in.

### What RAG means here

RAG stands for Retrieval-Augmented Generation. In red-run, it means the orchestrator can search the skill library by describing what it needs in plain English, instead of knowing the exact skill name in advance.

Here's how it works under the hood:

1. **Indexing** — When you run `install.sh`, the indexer (`tools/skill-router/indexer.py`) reads every `SKILL.md` file and extracts structured YAML frontmatter: the skill's description, keywords, tool names, and OPSEC rating. It builds a text document from these fields and computes a vector embedding using `all-MiniLM-L6-v2`, a sentence-transformer model that converts text into 384-dimensional vectors. These vectors are stored in ChromaDB, a local vector database at `tools/skill-router/.chromadb/`.

2. **Searching** — When the orchestrator calls `search_skills("AJP connector on port 8009")`, the skill-router converts that query into a vector using the same model and finds the closest matches by cosine similarity. The `ajp-ghostcat` skill's frontmatter mentions "AJP", "port 8009", "CVE-2020-1938", and "Ghostcat" — its vector is close to the query vector, so it ranks high. Results below 0.4 similarity are filtered out automatically.

3. **Loading** — The orchestrator reviews the search results (each includes the skill's description and OPSEC rating), picks the best match, and tells the agent to load it via `get_skill("ajp-ghostcat")`. The agent gets the full `SKILL.md` content — methodology, payloads, troubleshooting — injected into its context.

The "augmented generation" part is that Claude doesn't rely on its training data to know how to exploit AJP Ghostcat. Instead, the skill's methodology is retrieved from the local library and injected into the prompt, giving the agent precise, tested instructions rather than general knowledge.

### Hardcoded vs dynamic routing

Most routing is hardcoded. Discovery skills have decision trees that cover common scenarios, and the orchestrator has a routing table that maps ~60 skill names to their agents. RAG is the fallback for everything else:

- **Hardcoded**: "Web discovery found SQL injection" → route to `sql-injection-union` via `web-exploit-agent`
- **Dynamic (RAG)**: "Nmap found AJP on port 8009" → `search_skills("AJP connector")` → finds `ajp-ghostcat` → route via `web-exploit-agent`

The orchestrator validates search results before loading — a high similarity score doesn't guarantee relevance. The embedding model can confuse adjacent techniques (SSRF vs CSRF, IDOR vs ACL-abuse), so the orchestrator reads each result's description to confirm it matches the situation. If nothing fits, it proceeds with general methodology and notes the coverage gap.

### Context passing

When the orchestrator spawns an agent, it passes engagement context in the task prompt:

- Injection point details (URL, parameter, method)
- Target technology (framework, database, OS version)
- Working payloads from previous skills
- Burp proxy listener (`http://IP:PORT`) when the operator enabled capture
- Credentials and access levels

See [Agents](agents.md) for the full agent model and routing table.

## Hard Stops

The orchestrator has several points where it **must** pause for operator input:

| Hard Stop | When | Why |
|-----------|------|-----|
| **Scan type** | Before reconnaissance | Operator controls scan intensity and stealth |
| **Web proxy** | Immediately after HTTP/HTTPS ports are found | Operator decides whether Burp captures web traffic, which IP it binds to, and which port to use |
| **Hostname resolution** | New hostnames discovered | `/etc/hosts` changes require sudo |
| **Password spray intensity** | New usernames discovered | Spray intensity affects account lockout risk |
| **Vhost resolution** | Web discovery finds virtual hosts | Same as hostname resolution |

Hard stops prevent the orchestrator from making high-impact decisions autonomously. The operator always controls scan intensity, credential spraying risk, and system-level changes.

## Chaining Logic

After each skill completes, the orchestrator runs a **chaining analysis** using `get_state_summary()`. It walks this decision tree:

1. **Unexploited vulnerabilities?** → Route to the matching technique skill
2. **Shell access without root/admin?** → Route to host discovery (Linux or Windows)
3. **Untested credentials?** → Test against all known services
4. **Uncracked hashes?** → Route to credential-cracking (inline)
5. **Pivot paths available?** → Route to the skill that exploits the pivot
6. **Objectives met?** → Post-exploitation and wrap-up

This loop continues until objectives are met or all paths are exhausted. The pivot map in state tracks "what leads where" — a SQL injection that yields database credentials, credentials that work on a different host, a privilege escalation that enables DCSync.

## Recovery Paths

When agents hit obstacles, the orchestrator has structured recovery:

### AV/EDR Blocked

When a payload is caught by antivirus:

1. The technique agent stops and returns structured AV-blocked context
2. The orchestrator spawns the `evasion-agent` with `av-edr-evasion`
3. The evasion agent builds a bypass payload (custom compilation, AMSI bypass, LOLBins)
4. The orchestrator re-invokes the original skill with the AV-safe payload
5. If no bypass works, the technique is recorded as blocked and the orchestrator moves to the next vector

### Clock Skew

Kerberos authentication fails when clock skew exceeds 5 minutes:

1. The orchestrator writes a `clock-sync.sh` script
2. Pauses for the operator to sync clocks
3. Re-invokes the skill after confirmation

### DNS Resolution Failure

When tools fail on hostname resolution, the orchestrator follows the same hostname resolution hard stop pattern.

## Monitoring During Engagement

### Dashboard

The [agent dashboard](dashboard-and-monitoring.md) provides real-time visibility into what agents are doing. Run it in a separate terminal:

```bash
bash operator/agent-dashboard/dashboard.sh
```

### Event Watcher

The orchestrator spawns an event watcher (`tools/hooks/event-watcher.sh`) in the background to poll `state_events` for real-time findings from discovery agents. When a discovery agent writes a credential or vulnerability mid-run, the event watcher detects it and notifies the orchestrator.

See [Dashboard and Monitoring](dashboard-and-monitoring.md) for full details.

## Post-Engagement

When objectives are met (or all paths exhausted), the orchestrator:

1. **Collects evidence** — ensures all findings are in `engagement/evidence/`
2. **Updates state** — marks vulnerabilities as `done`, verifies access records
3. **Verifies objectives** — confirms flags captured, access achieved
4. **Summarizes** — produces an engagement summary with key findings

### Retrospective

The `retrospective` skill is how red-run gets better for *you* over time. After an engagement, it reads through everything that happened — the activity log, engagement state, findings, and the raw JSONL transcripts from every agent — and produces a structured analysis of what worked, what didn't, and what to fix.

It evaluates five things:

1. **Skill routing** — Did the orchestrator pick the right skills? Were any skills skipped that should have been used? Was anything executed inline (without loading a skill) that a skill already covers? This produces a routing ledger showing every decision and whether it was correct.

2. **Knowledge gaps** — For each skill that was used, did it have the right payloads? Did the target hit edge cases the skill didn't cover? Were tool commands correct or did the agent have to improvise? Each gap becomes a specific edit to make.

3. **Missing skills** — Were techniques used manually that should be skills? It cross-references against the full skill inventory via `search_skills()` to distinguish actual coverage gaps from routing gaps (skill exists but wasn't used).

4. **Operational review** — Were OPSEC ratings respected? Were there unnecessary detours? Did the orchestrator chain vulnerabilities efficiently or miss shortcuts?

5. **Critical path** — Maps the actual kill chain and identifies bottlenecks where the engagement stalled.

The output is `engagement/retrospective.md` with a priority-ordered list of actionable items: skill updates, new skills to write, routing fixes, and template changes. After you review and pick which items to prioritize, the retrospective skill makes the edits directly — updating skill files, creating new skills from the template, fixing routing tables — and re-indexes the skill library so changes take effect immediately.

This is the feedback loop that makes the skill library adapt to your targets and methodology. Skills ship as baseline templates; retrospectives refine them based on what you actually encounter.
