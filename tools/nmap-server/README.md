# nmap MCP Server

MCP server running nmap inside a Docker container for red-run subagents.
Eliminates the sudo attack surface — nmap runs in an isolated container with
minimal capabilities, and all inputs are validated before execution.

## Prerequisites

### 1. Install Docker

```bash
# Debian/Ubuntu
sudo apt install docker.io
sudo usermod -aG docker $USER
# Log out and back in for group change to take effect

# Or install Docker Engine: https://docs.docker.com/engine/install/
```

### 2. Build the nmap image

```bash
docker build -t red-run-nmap:latest tools/nmap-server/
```

The `install.sh` script does this automatically.

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
| `nmap_scan` | `target` (required), `options` (default `-A -p- -T4`), `save_to` (optional path) | Run nmap in Docker, return parsed JSON |
| `get_scan` | `scan_id` | Retrieve previous scan results |
| `list_scans` | (none) | List all session scans |

## Configuration

| Env Variable | Default | Description |
|-------------|---------|-------------|
| `NMAP_TIMEOUT` | `600` | Max scan duration in seconds |
| `NMAP_DOCKER_IMAGE` | `red-run-nmap:latest` | Docker image to use for nmap |

## Security

### Container isolation

Nmap runs inside a minimal Alpine container with:
- `--network=host` for raw socket access to the target network
- `--cap-drop=ALL --cap-add=NET_RAW --cap-add=NET_ADMIN` — only network capabilities
- `--rm` — container is removed after each scan
- No volume mounts — XML output goes to stdout, evidence saved by the host-side MCP server

### Input validation

All inputs are validated before reaching `subprocess.run()`:

- **Options**: Blocklist of dangerous flags (`-iL`, `-oN`, `--datadir`, etc.)
  that could read/write files or override paths. `--script` arguments must be
  bare names (no paths or URLs).
- **Target**: Blocks shell metacharacters (`;|&` etc.), path traversal (`..`),
  and whitespace injection.
- **save_to**: Resolved path must be under `engagement/evidence/`.
- **Filename sanitization**: Target strings used in evidence filenames are
  stripped of unsafe characters.

## Output

`nmap_scan` returns structured JSON with:
- Hosts (IP, status, hostnames, OS matches)
- Ports (number, protocol, state, service, banner)
- NSE script results
- Scan summary and timing

Raw XML is automatically saved to `engagement/evidence/nmap-<target>.xml`
when the engagement directory exists.
