# Installation

## Prerequisites

Run red-run in a dedicated VM, not on your daily driver. red-run is [designed so Claude never needs sudo](architecture.md#privilege-boundaries), but it still runs offensive tools, opens listeners, and makes network connections to targets — you want that happening in an isolated environment. A standard pentesting VM (Kali, Parrot, or a minimal Debian/Ubuntu with your tools) works fine.

red-run requires the following installed:

| Requirement | Purpose | Install |
|-------------|---------|---------|
| [Claude Code](https://docs.anthropic.com/en/docs/claude-code/getting-started) | CLI host for skills, agents, and MCP servers | See [Claude Code install docs](https://docs.anthropic.com/en/docs/claude-code/getting-started) |
| [uv](https://docs.astral.sh/uv/) | Python package manager for MCP servers | See [uv install docs](https://docs.astral.sh/uv/getting-started/installation/) |
| [Docker](https://docs.docker.com/engine/install/) | Containerized nmap and pentest toolbox | See [Docker install docs](https://docs.docker.com/engine/install/) |

### Optional: C2 Framework

red-run works out of the box with shell-server (raw TCP reverse shells + interactive processes). For C2 integration, install the framework separately:

| C2 | Components | Install |
|----|-----------|---------|
| [Sliver](https://github.com/BishopFox/sliver) | Server + Client (both required) | See below |

**Sliver install** (both binaries needed — server for the daemon, client for implant generation):
```bash
# Server (~260MB)
curl -L https://github.com/BishopFox/sliver/releases/latest/download/sliver-server_linux-amd64 \
  -o ~/.local/bin/sliver-server && chmod +x ~/.local/bin/sliver-server
# Client (~38MB)
curl -L https://github.com/BishopFox/sliver/releases/latest/download/sliver-client_linux-amd64 \
  -o ~/.local/bin/sliver && chmod +x ~/.local/bin/sliver
```

More C2 frameworks (Mythic, Havoc) planned. Custom C2 integration is supported via operator-provided MCP servers and reference docs.

## Install

```bash
git clone https://github.com/blacklanternsecurity/red-run.git
cd red-run
./install.sh
```

### What `install.sh` does

The installer runs five steps:

**1. Native skills** — Installs orchestrator skills to `~/.claude/skills/red-run-ctf/` (agent teams, default) and `~/.claude/skills/red-run-legacy/` (subagent-based). All other skills (67 discovery + technique skills) are served on-demand via the MCP skill-router.

**2. Teammate templates** — Teammate spawn prompts live in `teammates/` in the repo (not installed globally). The legacy subagent definitions in `agents/` are only installed with `--legacy`.

**3. MCP server dependencies** — Runs `uv sync` for all 6 MCP servers (skill-router, nmap-server, shell-server, state-server, browser-server, rdp-server) to install Python dependencies into isolated `.venv/` directories.

**4. Docker images** — Builds two Docker images:

- `red-run-nmap:latest` — Alpine + nmap for containerized scanning
- `red-run-shell:latest` — Tools that need persistent sessions or raw sockets (evil-winrm, impacket, chisel, ligolo-ng, socat, Responder, mitm6, tcpdump)

**5. Skill indexing** — Runs the ChromaDB indexer to embed all skills for semantic search. Downloads the `all-MiniLM-L6-v2` embedding model (~80MB) on first run.

**6. Browser setup** — Installs Chromium via Playwright (~150MB) for headless browser automation.

**7. Config verification** — Checks that `.mcp.json` and `.claude/settings.json` are properly configured.

### Attackbox dependencies

The installer sets up red-run itself, but skills also depend on standard pentesting tools installed on the attackbox (nmap, ffuf, sqlmap, hashcat, impacket, git-dumper, etc.). After installing, run the preflight check:

```bash
bash preflight.sh
```

Preflight verifies that required tools are in `$PATH` and reports missing ones with install commands. See [dependencies](dependencies.md) for the full list organized by category.

### Symlink vs copy mode

```bash
./install.sh          # Default: symlinks (edits in repo reflect immediately)
./install.sh --copy   # Copies (snapshots skills and agents into ~/.claude/)
```

Symlink mode is recommended — changes to skills and agents in the repo take effect immediately without re-running the installer. Copy mode snapshots the files, so you need to re-run the installer to pick up changes.

Both modes require the repo directory to stay in place. MCP servers run from `tools/` and the skill-router reads skill files from `skills/` at runtime.

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

## Running

### Quick start (shell-server only)

```bash
cd red-run
./run.sh
```

`run.sh` starts shell-server, launches Claude Code, and auto-triggers `/red-run-ctf`. The orchestrator asks config questions (scan type, proxy, etc.) on first run. Give it a target IP to begin.

### With C2 (Sliver or custom)

```bash
cd red-run
bash config.sh             # config wizard — picks C2 backend, patches .mcp.json
./run.sh                   # starts C2 daemon + MCP, launches Claude Code
```

`config.sh` is optional if you're using shell-server only. Required if you want a C2 backend — it generates operator configs, registers the C2 MCP server, and writes `engagement/config.yaml` so the orchestrator skips its built-in wizard.

### Flags

```bash
./run.sh --lead=legacy  # use /red-run-legacy instead
./run.sh --yolo         # skip permission prompts
```

If shell-server has active sessions from a previous run, `run.sh` prompts to keep, clear, or restart them.

## Uninstall

```bash
./uninstall.sh
```

This removes:

- Native skills from `~/.claude/skills/red-run-*/`
- Legacy subagents from `~/.claude/agents/` (if installed)
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
ERROR: Broken skill: ~/.claude/skills/red-run-ctf/SKILL.md -> unknown
```

The repo directory was moved or deleted after install. Either move it back or re-run `./install.sh`.

### Missing uv

```
ERROR: uv is required but not found.
```

See [uv install docs](https://docs.astral.sh/uv/getting-started/installation/).

### Embedding model download fails

The skill-router downloads `all-MiniLM-L6-v2` on first run. If your VM lacks internet access, download the model elsewhere and set `HF_HUB_OFFLINE=1` (already set in `.mcp.json` for runtime). For initial indexing, internet access is required.

### Chromium install fails

If `playwright install chromium` fails behind a proxy, download Chromium manually. See [Playwright docs](https://playwright.dev/python/docs/browsers#install-behind-a-firewall-or-a-proxy) for proxy configuration.

### MCP servers not starting

Verify `.mcp.json` exists in the repo root and `.claude/settings.json` has `enableAllProjectMcpServers: true`. Check server logs with:

```bash
uv run --directory tools/skill-router python server.py  # Should start without errors
```
