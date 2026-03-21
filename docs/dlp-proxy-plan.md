# DLP Proxy Architecture Plan

A tokenization layer that prevents client-identifying data from reaching
Anthropic's servers during penetration testing engagements.

## Problem

Every Claude Code API call sends the full conversation context to Anthropic.
Target IPs, hostnames, discovered credentials, vulnerability details tied to
identifiable targets — all of it lands in API logs. For a pentest firm, "here's
how to break into MegaCorp" sitting on a third-party's servers is a liability.

## Solution

Replace sensitive values with tokens before they reach Claude. Claude sees
`TOKEN_HOST_001` instead of `10.0.5.100`, makes routing decisions based on
tokens, and real values only exist locally. Commands get detokenized before
execution, results get tokenized before Claude sees them.

## Orchestrator Variant

`/red-run-handsoff` — the third orchestrator variant alongside `/red-run-ctf`
(agent teams) and `/red-run-legacy` (subagents). Each phase below builds on
the previous.

---

## Phase 1: Operator-as-DLP (handsoff mode)

**Target: this weekend. No new infrastructure — just a new orchestrator skill
and a tokenizer script.**

### How it works

```
Operator provides scope (real IPs, hostnames, creds)
    ↓
Tokenizer script registers them in token.db, returns tokens
    ↓
Operator starts Claude with tokenized scope: "attack TOKEN_HOST_001"
    ↓
Orchestrator proposes actions using tokens
    ↓
Operator reads proposal, detokenizes mentally or via script
    ↓
Operator executes command in a separate tmux pane
    ↓
Operator pipes output through tokenizer: nmap 10.0.5.100 | tokenize
    ↓
Operator pastes tokenized result back to Claude
    ↓
Orchestrator updates state, proposes next action
```

Claude never executes anything. Pure advisory mode.

### Components to build

**1. Token database (`tools/dlp/token.db`)**

```sql
CREATE TABLE tokens (
    token TEXT PRIMARY KEY,       -- TOKEN_HOST_001
    real_value TEXT NOT NULL,      -- 10.0.5.100
    token_type TEXT NOT NULL,      -- host | credential | domain | url | username | pii
    context TEXT,                  -- "primary target", "DC", "discovered via SMB enum"
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE patterns (
    id INTEGER PRIMARY KEY,
    pattern TEXT NOT NULL,         -- regex pattern to match in output
    token TEXT NOT NULL,           -- token to replace with
    FOREIGN KEY (token) REFERENCES tokens(token)
);
```

The `patterns` table auto-generates regexes for each token. For a host
`10.0.5.100`, patterns include:
- `10\.0\.5\.100` (literal IP)
- `10\.0\.5\.100:\d+` (IP:port)
- `10-0-5-100` (dash-separated variant, shows up in some tools)

For a domain `megacorp.local`, patterns include:
- `megacorp\.local`
- `\.megacorp\.local` (subdomains)
- `DC=megacorp,DC=local` (LDAP DN)
- `MEGACORP\\` (NetBIOS prefix)
- `@megacorp\.local` (UPN suffix)

**2. Tokenizer CLI (`tools/dlp/tokenize.py`)**

```bash
# Register scope items
python3 tokenize.py register --type host --value "10.0.5.100" --context "primary target"
python3 tokenize.py register --type domain --value "megacorp.local" --context "AD domain"
python3 tokenize.py register --type credential --value "admin:P@ssw0rd" --context "provided by client"

# Tokenize text (pipe mode)
echo "Connected to 10.0.5.100 on port 445" | python3 tokenize.py filter
# → "Connected to TOKEN_HOST_001 on port 445"

# Detokenize (for operator execution)
echo "nmap TOKEN_HOST_001" | python3 tokenize.py defilter
# → "nmap 10.0.5.100"

# Auto-register new discoveries from tool output
# (detects IPs, hostnames, emails not yet in db, prompts operator to confirm)
python3 tokenize.py discover < nmap_output.txt

# Dump token map
python3 tokenize.py dump
```

**3. Orchestrator skill (`skills/handsoff/SKILL.md`)**

New orchestrator variant: `/red-run-handsoff`

Key differences from `/red-run-ctf`:
- Does NOT spawn teammates or subagents
- Does NOT execute any tools against targets
- Proposes actions with tokenized values
- Expects operator to report results back
- Maintains state.db with tokenized values
- All state queries and writes use tokens

The skill instructs Claude to:
- Present proposed commands clearly with token values
- Wait for operator to report results
- Parse tokenized results and update state
- Make routing decisions and propose next actions
- Never attempt to execute commands itself

**4. tmux workflow**

```
┌─────────────────────────┬──────────────────────────┐
│                         │                          │
│  Claude (lead)          │  Operator execution      │
│  Proposes tokenized     │  Runs real commands      │
│  actions, updates state │  Pipes through tokenizer │
│                         │                          │
│  "Run nmap quick scan   │  $ nmap -sV -sC 10.0.5  │
│   against TOKEN_HOST_001│  .100 | python3 tokenize │
│   with -sV -sC"        │  .py filter > /tmp/out   │
│                         │                          │
│  Operator pastes:       │  $ cat /tmp/out          │
│  "Results: 22/tcp open  │  (copy to Claude pane)   │
│   ssh, 445/tcp open     │                          │
│   TOKEN_HOST_001..."    │                          │
│                         │                          │
└─────────────────────────┴──────────────────────────┘
```

### What Phase 1 does NOT solve

- Automated execution (operator is the bottleneck)
- New sensitive values discovered mid-engagement that aren't in the token db
  (operator must manually register them via `tokenize.py discover`)
- Screenshots or binary data
- Values Claude infers from context (CVEs are public, service versions
  narrow down the target)

### Estimated effort

- Token database + CLI: ~2 hours
- Orchestrator skill variant: ~4 hours (adapt from red-run-ctf, strip all
  execution, add advisory-mode prompting)
- Testing against a CTF box: ~2 hours
- Total: a weekend

---

## Phase 2: MCP DLP Proxy (automated tokenization)

**Target: after Phase 1 proves the concept and token db design is validated.**

### How it works

```
Claude Code → dlp-proxy MCP → [detokenize input] → real MCP server
                             ← [tokenize output]  ←

Claude Code → dlp-proxy:safe_bash → [detokenize] → execute → [tokenize] → return
```

A single MCP server sits between Claude Code and all backend servers. Claude
only connects to the dlp-proxy. Real MCP servers run locally but aren't
exposed to Claude.

### Architecture

```
.mcp.json (what Claude sees):
    dlp-proxy:
        command: "uv run --directory tools/dlp python proxy.py"
        # Exposes ALL tools from all backend servers, plus safe_bash

dlp-proxy internally connects to (NOT in .mcp.json):
    skill-router   → pass-through (no sensitive data)
    nmap-server    → tokenize scan results
    shell-server   → detokenize commands, tokenize output
    browser-server → detokenize URLs, tokenize page content
    rdp-server     → detokenize hosts, tokenize text output
    state-writer   → pass-through (already tokenized)
    state-interim  → pass-through (already tokenized)
```

### Components to build

**1. MCP-to-MCP proxy (`tools/dlp/proxy.py`)**

Generic proxy that:
- On startup: connects to all backend MCP servers, discovers tools
- Exposes same tools to Claude (same names, same schemas)
- On tool call: detokenize input → call backend → tokenize output → return
- Also exposes `safe_bash(command, description)` tool

```python
# Pseudo-architecture
class DLPProxy:
    def __init__(self, token_db, backends):
        self.tokenizer = Tokenizer(token_db)
        self.backends = {}  # name → MCP client connection

    async def handle_tool_call(self, tool_name, params):
        # Determine backend from tool name prefix
        backend = self.route(tool_name)

        # Detokenize all string values in params
        clean_params = self.tokenizer.detokenize_dict(params)

        # Call real backend
        result = await backend.call(tool_name, clean_params)

        # Tokenize result
        safe_result = self.tokenizer.tokenize_text(result)

        return safe_result
```

**2. Safe Bash tool**

Replaces Claude's native Bash tool. Exposed via dlp-proxy MCP.

```python
@mcp.tool()
def safe_bash(command: str, description: str = "") -> str:
    """Execute a shell command with DLP tokenization."""
    real_command = tokenizer.detokenize_text(command)
    result = subprocess.run(real_command, shell=True, capture_output=True)
    output = result.stdout.decode() + result.stderr.decode()
    return tokenizer.tokenize_text(output)
```

Native Bash disabled via Claude Code permissions:
```json
{
  "permissions": {
    "deny": ["Bash"]
  }
}
```

**3. Auto-discovery of new sensitive values**

When tokenizing tool output, the proxy also scans for potential new
sensitive values not yet in the token db:

- IP addresses not in token db → auto-register with type "host"
- Hostnames matching known domain patterns → auto-register
- Email addresses → auto-register with type "pii"
- Strings matching credential patterns (`password=`, `secret:`) → flag

Auto-registered tokens get logged so operator can review. False positives
(public IPs, generic hostnames) are a nuisance but not a security risk —
over-tokenizing is better than under-tokenizing.

**4. Credential handling**

Credentials discovered mid-engagement:
- `add_credential(username="admin", secret="P@ssw0rd")` arrives at proxy
- Proxy auto-registers both username and secret as tokens
- State.db stores `TOKEN_USER_002` and `TOKEN_CRED_002`
- Claude sees: "Found credential TOKEN_USER_002:TOKEN_CRED_002"
- When Claude tells a teammate to authenticate, the proxy detokenizes

Special case: Claude discovers a password that's just a random string
(no `password=` prefix). The proxy's regex won't catch it. The state-server
tool call DOES catch it because the proxy knows `add_credential`'s `secret`
parameter is always sensitive — tokenize by parameter name, not by content.

**5. Tool-specific tokenization rules**

| MCP Server | Input detokenization | Output tokenization |
|------------|---------------------|---------------------|
| skill-router | none needed | none needed (static skill content) |
| nmap-server | `target` param | full result (IPs, hostnames, banners) |
| shell-server | `command` param in start_process/send_command | all output (command results from target) |
| browser-server | `url` param | page content, cookies, JS results |
| rdp-server | `host` param | text output only (screenshots are binary — Phase 3) |
| state-writer | pass-through (already tokenized) | pass-through |
| state-interim | pass-through (already tokenized) | pass-through |
| safe_bash | full command | full output |

### What Phase 2 does NOT solve

- Screenshots (binary image data with rendered hostnames)
- Values embedded in complex formats (base64-encoded configs, serialized
  objects, encrypted data that gets decrypted on-target)
- Semantic inference (Claude knows TOKEN_HOST_001 runs Exchange 2016 CU23
  with CVE-2021-26855 — anyone can narrow that down)
- File content read via Claude's native Read tool (need to disable and
  route through proxy, or accept the risk for local files)

### Native tool handling

Claude's built-in tools (Read, Write, Edit, Glob, Grep) operate on local
files. These files may contain sensitive data (nmap XML output, evidence
files). Options:

- **Accept the risk**: local files are working artifacts. The file PATHS
  don't contain sensitive data (engagement/evidence/nmap-scan.xml is fine).
  The file CONTENTS might, but Claude needs to read them to make decisions.
  This is a deliberate trade-off — the proxy catches 90% via MCP tools,
  local files are the remaining 10%.
- **Disable native file tools**: route all reads through a `safe_read` MCP
  tool that tokenizes content. Heavy-handed, breaks many workflows.
- **PostToolUse hook**: tokenize Read tool output before Claude processes it.
  If hooks can modify tool results (unclear), this is the cleanest option.

Recommend: accept the risk for Phase 2. Most sensitive data flows through
MCP tools (nmap results, shell output, browser content). Files on disk are
secondary.

### Estimated effort

- MCP-to-MCP proxy framework: ~1 week
- Tool-specific tokenization rules: ~3 days
- Safe Bash implementation: ~2 days
- Auto-discovery of new sensitive values: ~3 days
- Integration testing: ~1 week
- Total: ~3-4 weeks

---

## Phase 3: Local Model Enhancement

**Target: after Phase 2 is stable and gaps are identified from real engagements.**

### What it adds

A local model (llama 3.1 8B, phi-3, or similar) reviews tool output for
sensitive data that regex missed:

```
Tool output → regex tokenizer (fast, catches 90%) → local model review
(catches remaining edge cases) → Claude
```

### Use cases

- IP address embedded in a Java stack trace
- Hostname in a base64-decoded config file
- Client name in an HTTP response body
- Internal URL in a JavaScript source map
- Screenshot OCR for hostnames in title bars and admin panels

### Architecture

```python
async def tokenize_with_model(text: str, token_db) -> str:
    # Phase 2 regex tokenization first
    partially_tokenized = regex_tokenize(text, token_db)

    # Check if any real values might remain
    if likely_contains_sensitive(partially_tokenized):
        # Local model reviews
        prompt = f"""Review this text for any remaining sensitive data
        (IPs, hostnames, domains, credentials, PII) that should be
        replaced with tokens. Known tokens: {token_db.dump_map()}
        Text: {partially_tokenized}"""

        result = local_model.generate(prompt)
        # Parse model's suggestions, register new tokens, re-tokenize
```

### Performance

- Local 8B model inference: ~100-500ms per tool call
- Acceptable for most tools (nmap takes minutes, the model adds <1s)
- For high-frequency tools (send_command in rapid succession), skip
  model review and rely on regex only

### Screenshot handling

- Render screenshot → OCR (tesseract) → tokenize text → flag if
  sensitive values found
- Can't modify the image itself — just flag it and optionally block
  it from being sent to Claude
- Or: generate a text description of the screenshot via local
  vision model, tokenize that, send text instead of image

### Estimated effort

- Local model integration: ~1 week
- Training/prompt engineering for reliable detection: ~2 weeks
- Screenshot OCR pipeline: ~1 week
- Performance tuning: ~1 week
- Total: ~5-6 weeks

---

## Token Design

### Token format

```
TOKEN_<TYPE>_<SEQ>

Types:
  HOST   — IP addresses, hostnames
  DOMAIN — AD domains, DNS domains
  USER   — usernames, account names
  CRED   — passwords, hashes, keys, tickets
  URL    — full URLs
  EMAIL  — email addresses
  PII    — names, phone numbers, other PII
  NET    — subnets, CIDR ranges
  ORG    — organization names, client identifiers

Examples:
  TOKEN_HOST_001    → 10.0.5.100
  TOKEN_HOST_002    → dc01.megacorp.local
  TOKEN_DOMAIN_001  → megacorp.local
  TOKEN_USER_001    → admin
  TOKEN_CRED_001    → P@ssw0rd123!
  TOKEN_NET_001     → 10.0.5.0/24
  TOKEN_ORG_001     → MegaCorp Industries
```

### Semantic preservation

Some tokenization must preserve semantic meaning for Claude to route correctly:

| Real value | Bad token | Good token | Why |
|-----------|-----------|------------|-----|
| `dc01.megacorp.local` | `TOKEN_HOST_002` | `dc01.TOKEN_DOMAIN_001` | Claude needs to know it's a DC |
| `10.0.5.0/24` | `TOKEN_HOST_003` | `TOKEN_NET_001` | Claude needs to know it's a subnet for pivoting |
| `svc_sql@megacorp.local` | `TOKEN_USER_001` | `svc_sql@TOKEN_DOMAIN_001` | Service account name hints at SQL service |
| `MEGACORP\admin` | `TOKEN_USER_002` | `TOKEN_DOMAIN_001\admin` | Domain prefix needed for auth commands |

Rule: tokenize the identifying component (domain, org, IP) but preserve
the functional component (role prefix, service name, subnet mask).

### Credential metadata

Claude doesn't need the actual password to make routing decisions. The token
db stores metadata that the proxy can include in state summaries:

```
TOKEN_CRED_001:
    type: password
    valid: true
    access_level: domain_admin
    works_on: [SMB, WinRM, LDAP]
    source: kerberoasting
```

Claude sees: "TOKEN_USER_001 has TOKEN_CRED_001 (domain_admin, valid on
SMB/WinRM/LDAP, from kerberoasting)" — enough to make routing decisions
without the actual password.

---

## Integration with red-run

### install.sh

Phase 1: install tokenizer CLI to `tools/dlp/`
Phase 2: install dlp-proxy MCP server, add to `.mcp.json` template

### Engagement workflow

Phase 1:
```
1. Operator registers scope: python3 tools/dlp/tokenize.py register ...
2. Operator starts claude with tokenized scope
3. Orchestrator runs in advisory mode
4. Operator executes + reports back
```

Phase 2:
```
1. Operator registers scope via dlp-proxy setup tool
2. Claude starts with dlp-proxy as sole MCP connection
3. Orchestrator runs normally (agent teams or subagents)
4. All tool I/O transparently tokenized by proxy
5. Operator monitors via tmux panes (sees tokenized output in Claude,
   real output in evidence files on disk)
```

### Evidence files

Evidence written to `engagement/evidence/` contains REAL data (it's written
by tool execution, not by Claude). This is correct — evidence is for the
operator, not for Claude. If Claude reads evidence files via the Read tool
(Phase 2 gap), those reads contain real data. Acceptable trade-off.

### State database

State.db stores tokenized values in Phase 1 and Phase 2. The operator can
run `dump-state.sh` to see tokenized state, then pipe through the
detokenizer for the real report:

```bash
bash engagement/dump-state.sh | python3 tools/dlp/tokenize.py defilter
```

### Reporting

The orchestrator generates reports with tokenized values. Operator
detokenizes the final report for client delivery:

```bash
python3 tools/dlp/tokenize.py defilter < engagement/report.md > report-real.md
```

---

## Risk Assessment

| Risk | Phase 1 | Phase 2 | Phase 3 |
|------|---------|---------|---------|
| Known scope items (IPs, domains) leak | None (operator filters) | None (regex catches) | None |
| New discoveries leak (found mid-engagement) | Medium (operator must register) | Low (auto-discovery) | Very low |
| Credentials leak | None (operator filters) | Low (parameter-aware tokenization) | Very low |
| Values in complex formats (base64, etc.) | Medium | Medium | Low |
| Screenshots contain sensitive data | N/A (no screenshots) | Medium (binary bypass) | Low (OCR) |
| Semantic inference from context | Accepted | Accepted | Accepted |
| Native file Read contains real data | N/A | Medium | Medium |

The "accepted" risk of semantic inference is inherent to the approach.
If Claude knows TOKEN_HOST_001 runs Exchange 2016 CU23 vulnerable to
ProxyShell, that narrows the target significantly. But it doesn't directly
identify the client — the token prevents the IP/hostname correlation.
