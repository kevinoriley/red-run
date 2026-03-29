# Sliver C2 MCP Server

MCP server wrapping [Sliver C2](https://github.com/BishopFox/sliver) gRPC API
via [sliver-py](https://github.com/moloch--/sliver-py). Provides session
management, implant generation, command execution, file transfer, and pivot
operations for red-run teammates.

## Prerequisites

- **Sliver server** installed and running as daemon (`sliver-server daemon`)
- **Operator config** at `engagement/sliver.cfg` (generated via
  `sliver-server operator --name red-run --lhost 127.0.0.1 --save engagement/sliver.cfg`
  or via `config.sh`)

## Transport

SSE on `127.0.0.1:8023` (configurable via `SLIVER_SSE_PORT`).

## Tools

### Listener Management

| Tool | Description |
|------|-------------|
| `start_mtls_listener(host, port)` | Start mTLS listener for implant callbacks |
| `start_https_listener(host, port, domain)` | Start HTTPS listener |
| `list_jobs()` | List active listener jobs |
| `kill_job(job_id)` | Stop a listener |

### Implant Generation

| Tool | Description |
|------|-------------|
| `generate_implant(os, arch, mtls_host, mtls_port, format, name)` | Build session-mode implant (obfuscated) |
| `generate_stager(os, arch, protocol, host, port)` | Build small first-stage stager |

### Session Operations

| Tool | Description |
|------|-------------|
| `list_sessions()` | List active sessions with metadata |
| `execute(session_id, exe, args, shell_cmd, output)` | Run command on target. Use `shell_cmd="id && uname -a"` for shell commands, or `exe`+`args` (JSON array) for direct exec |
| `upload(session_id, local_path, remote_path)` | Upload file to target |
| `download(session_id, remote_path, local_path)` | Download file from target |
| `ifconfig(session_id)` | List target network interfaces |
| `kill_session(session_id)` | Terminate session |

### Pivot Management

| Tool | Description |
|------|-------------|
| `start_pivot_listener(session_id, pivot_type, bind_address, bind_port)` | Start TCP pivot on compromised host |
| `list_pivots()` | List active pivot listeners |

## Graceful Degradation

If no operator config exists, all tools return an error message directing the
operator to run `config.sh`. The server starts and binds its SSE port
regardless — it just can't connect to Sliver without credentials.

## HTTP Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /status` | Health check — returns connection status and session count |
