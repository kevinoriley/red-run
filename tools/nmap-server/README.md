# nmap MCP Server

MCP server wrapping `sudo nmap` for red-run subagents. Eliminates the sudo
handoff bottleneck — subagents call `nmap_scan` directly and get structured
JSON back.

## Prerequisites

### 1. Install nmap

```bash
# Debian/Ubuntu
sudo apt install nmap

# Arch
sudo pacman -S nmap
```

### 2. Configure passwordless sudo for nmap

Create a sudoers drop-in file:

```bash
echo "$USER ALL=(root) NOPASSWD: /usr/bin/nmap" | sudo tee /etc/sudoers.d/nmap
sudo chmod 440 /etc/sudoers.d/nmap
```

Verify it works:

```bash
sudo -n nmap --version
```

### 3. Install Python dependencies

```bash
uv sync --directory tools/nmap-server
```

## Usage

The server runs as an MCP server, started automatically by Claude Code via
`.mcp.json`. To test manually:

```bash
uv run --directory tools/nmap-server python server.py
```

## Tools

| Tool | Parameters | Description |
|------|-----------|-------------|
| `nmap_scan` | `target` (required), `options` (default `-A -p- -T4`), `save_to` (optional path) | Run sudo nmap, return parsed JSON |
| `get_scan` | `scan_id` | Retrieve previous scan results |
| `list_scans` | (none) | List all session scans |

## Configuration

| Env Variable | Default | Description |
|-------------|---------|-------------|
| `NMAP_TIMEOUT` | `600` | Max scan duration in seconds |

## Output

`nmap_scan` returns structured JSON with:
- Hosts (IP, status, hostnames, OS matches)
- Ports (number, protocol, state, service, banner)
- NSE script results
- Scan summary and timing

Raw XML is automatically saved to `engagement/evidence/nmap-<target>.xml`
when the engagement directory exists.
