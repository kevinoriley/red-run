# Installation

## Prerequisites

Run red-run in a dedicated VM, not on your daily driver. red-run is [designed so Claude never needs sudo](architecture.md#privilege-boundaries), but it still runs offensive tools, opens listeners, and makes network connections to targets — you want that happening in an isolated environment. A standard pentesting VM (Kali, Parrot, or a minimal Debian/Ubuntu with your tools) works fine.

red-run requires the following installed:

| Requirement | Purpose | Install |
|-------------|---------|---------|
| [Claude Code](https://docs.anthropic.com/en/docs/claude-code) | CLI host for skills, agents, and MCP servers | `npm install -g @anthropic-ai/claude-code` |
| [uv](https://docs.astral.sh/uv/) | Python package manager for MCP servers | `curl -LsSf https://astral.sh/uv/install.sh \| sh` |
| [Docker](https://docs.docker.com/engine/install/) | Containerized nmap and pentest toolbox | See Docker docs |

## Install

```bash
git clone https://github.com/blacklanternsecurity/red-run.git
cd red-run
./install.sh
```

### What `install.sh` does

The installer runs five steps:

**1. Native skills** — Installs the orchestrator skill to `~/.claude/skills/red-run-orchestrator/`. This is the only skill installed as a native Claude Code skill. All other skills (67 discovery + technique skills) are served on-demand via the MCP skill-router.

**2. Custom subagents** — Installs 10 domain-specific agent definitions to `~/.claude/agents/`. These are the `.md` files that define each agent's system prompt, available tools, and execution model.

**3. MCP server dependencies** — Runs `uv sync` for all 5 MCP servers (skill-router, nmap-server, shell-server, state-server, browser-server) to install Python dependencies into isolated `.venv/` directories.

**4. Docker images** — Builds two Docker images:

- `red-run-nmap:latest` — Alpine + nmap for containerized scanning
- `red-run-shell:latest` — Tools that need persistent sessions or raw sockets (evil-winrm, impacket, chisel, ligolo-ng, socat, Responder, mitm6, tcpdump)

**5. Skill indexing** — Runs the ChromaDB indexer to embed all skills for semantic search. Downloads the `all-MiniLM-L6-v2` embedding model (~80MB) on first run.

**6. Browser setup** — Installs Chromium via Playwright (~150MB) for headless browser automation.

**7. Config verification** — Checks that `.mcp.json` and `.claude/settings.json` are properly configured.

### Symlink vs copy mode

```bash
./install.sh          # Default: symlinks (edits in repo reflect immediately)
./install.sh --copy   # Copies (for standalone machines without persistent repo)
```

Symlink mode is recommended for development — changes to skills and agents in the repo take effect immediately without re-running the installer. Copy mode is for machines where the repo won't stay in place.

> **Repo must stay in place:** Regardless of install mode, the repo directory must remain accessible. The skill-router MCP server reads skill files from `skills/` at runtime, and all MCP servers are launched from the `tools/` directory via `.mcp.json`.

### Hardening with permission denies

red-run is [designed so Claude never needs sudo](architecture.md#privilege-boundaries) — nmap and Responder run inside Docker containers, and system changes like `/etc/hosts` are hard stops that require operator action. You can enforce this by denying `sudo` in `~/.claude/settings.json`:

```json
{
  "permissions": {
    "deny": [
      "Bash(sudo *)",
      "Bash(rm -rf *)",
      "Bash(rm -fr *)",
      "Bash(git push --force*)",
      "Bash(git reset --hard*)"
    ]
  }
}
```

The `Bash(sudo *)` rule makes Claude Code refuse any Bash command starting with `sudo`. The other rules block common destructive commands. See the [Trail of Bits Claude Code hardening guide](https://blog.trailofbits.com/2025/07/10/securing-claude-code/) for the full recommended configuration.

## Engagement firewall (optional)

An nftables firewall is available in `operator/engagement-firewall/` for operators who want OS-level network isolation. It restricts outbound traffic to Anthropic API endpoints and in-scope targets. See `operator/engagement-firewall/README.md` for setup and live target additions.

## Running

Start Claude Code from the red-run repo directory:

```bash
cd red-run
claude --dangerously-skip-permissions
```

All skills delegate to autonomous agents. The orchestrator still presents routing decisions for operator approval before spawning each agent. MCP servers start automatically via `.mcp.json`. Give the orchestrator a target:

> "Scan and attack 10.10.10.5"

## Uninstall

```bash
./uninstall.sh
```

This removes:

- Native skills from `~/.claude/skills/red-run-*/`
- Custom subagents from `~/.claude/agents/`
- ChromaDB index (`tools/skill-router/.chromadb/`)
- Python venvs (`tools/*/. venv/`)
- Docker images (`red-run-nmap:latest`, `red-run-shell:latest`)

It does **not** remove `.mcp.json` or `.claude/settings.json` (project config), and it does not touch the `engagement/` directory.

## Troubleshooting

### Docker not available

```
WARNING: Docker required for nmap MCP server but not available.
```

Install Docker and ensure the daemon is running. The nmap-server and shell-server privileged mode require Docker. The rest of the toolkit works without it.

### Broken symlinks

```
ERROR: Broken skill: ~/.claude/skills/red-run-orchestrator/SKILL.md -> unknown
```

The repo directory was moved or deleted after install. Either move it back or re-run `./install.sh`.

### Missing uv

```
ERROR: uv is required but not found.
```

Install uv: `curl -LsSf https://astral.sh/uv/install.sh | sh`

### Embedding model download fails

The skill-router downloads `all-MiniLM-L6-v2` on first run. If your VM lacks internet access, download the model elsewhere and set `HF_HUB_OFFLINE=1` (already set in `.mcp.json` for runtime). For initial indexing, internet access is required.

### Chromium install fails

If `playwright install chromium` fails behind a proxy, download Chromium manually. See [Playwright docs](https://playwright.dev/python/docs/browsers#install-behind-a-firewall-or-a-proxy) for proxy configuration.

### MCP servers not starting

Verify `.mcp.json` exists in the repo root and `.claude/settings.json` has `enableAllProjectMcpServers: true`. Check server logs with:

```bash
uv run --directory tools/skill-router python server.py  # Should start without errors
```
