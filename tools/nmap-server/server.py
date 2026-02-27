"""MCP server wrapping sudo nmap for red-run subagents.

Provides three tools:
- nmap_scan: Run a sudo nmap scan with parsed results
- get_scan: Retrieve results of a previous scan
- list_scans: List all scans run this session

Eliminates the sudo handoff bottleneck — subagents call nmap_scan directly
and get structured JSON back instead of waiting for manual user execution.

Usage:
    uv run python server.py

Requires: passwordless sudo for nmap (see README.md for sudoers config).
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

from libnmap.parser import NmapParser
from mcp.server.fastmcp import FastMCP

NMAP_TIMEOUT = int(os.environ.get("NMAP_TIMEOUT", "600"))

# Resolve engagement directory relative to the project root, not the server's
# own directory.  uv run --directory changes cwd to tools/nmap-server/, so
# bare Path("engagement/...") would land artifacts inside the tools tree.
_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent


def _check_sudo_nmap() -> str | None:
    """Check if passwordless sudo nmap is available. Returns error message or None."""
    try:
        result = subprocess.run(
            ["sudo", "-n", "nmap", "--version"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode != 0:
            return (
                "sudo nmap failed. Configure passwordless sudo for nmap.\n"
                "Add to /etc/sudoers.d/nmap:\n"
                "  <username> ALL=(root) NOPASSWD: /usr/bin/nmap"
            )
    except FileNotFoundError:
        return "nmap not found. Install nmap first."
    except subprocess.TimeoutExpired:
        return "sudo nmap timed out — passwordless sudo may not be configured."
    return None


def _parse_nmap_xml(xml_content: str) -> dict:
    """Parse nmap XML output into structured dict via python-libnmap."""
    report = NmapParser.parse_fromstring(xml_content)

    hosts = []
    for host in report.hosts:
        host_data: dict = {
            "ip": host.address,
            "status": host.status,
            "hostnames": [h for h in host.hostnames],
        }

        if host.os_fingerprinted:
            os_matches = []
            for osm in host.os.osmatches:
                os_matches.append(
                    {
                        "name": osm.name,
                        "accuracy": osm.accuracy,
                    }
                )
            host_data["os_matches"] = os_matches

        ports = []
        for svc in host.services:
            port_data: dict = {
                "port": svc.port,
                "protocol": svc.protocol,
                "state": svc.state,
                "service": svc.service,
                "banner": svc.banner,
            }

            if svc.scripts_results:
                port_data["scripts"] = svc.scripts_results

            ports.append(port_data)

        host_data["ports"] = ports
        hosts.append(host_data)

    return {
        "command": report.commandline,
        "start_time": report.started,
        "end_time": report.endtime,
        "elapsed": report.elapsed,
        "summary": report.summary,
        "hosts_up": report.hosts_up,
        "hosts_total": report.hosts_total,
        "hosts": hosts,
    }


def _save_evidence(xml_content: str, target: str, save_to: str | None) -> str | None:
    """Save raw XML to engagement/evidence/ or custom path. Returns path or None."""
    if save_to:
        out_path = Path(save_to)
    else:
        evidence_dir = _PROJECT_ROOT / "engagement" / "evidence"
        if not evidence_dir.exists():
            return None
        safe_target = target.replace("/", "_").replace(" ", "_")
        out_path = evidence_dir / f"nmap-{safe_target}.xml"

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(xml_content)
    return str(out_path)


def create_server() -> FastMCP:
    """Create and configure the nmap MCP server."""
    mcp = FastMCP(
        "red-run-nmap-server",
        instructions=(
            "Provides nmap scanning for red-run subagents. "
            "Use nmap_scan to run scans (no sudo handoff needed). "
            "Use get_scan to retrieve previous results. "
            "Use list_scans to see session history."
        ),
    )

    # In-memory scan storage for the session
    scans: dict[str, dict] = {}

    # Check sudo nmap availability at startup
    sudo_error = _check_sudo_nmap()
    if sudo_error:
        print(f"WARNING: {sudo_error}", file=sys.stderr)

    @mcp.tool()
    def nmap_scan(
        target: str,
        options: str = "-A -p- -T4",
        save_to: str = "",
    ) -> str:
        """Run a sudo nmap scan and return parsed results.

        Executes `sudo nmap` with the given options, parses XML output, and
        returns structured JSON with hosts, ports, services, scripts, and OS
        detection. Results are automatically saved to engagement/evidence/ if
        the directory exists.

        Args:
            target: Target IP, hostname, or CIDR range (e.g., "10.10.10.5",
                    "10.10.10.0/24", "target.htb").
            options: nmap options string (default: "-A -p- -T4"). Do NOT
                     include output flags (-oX, -oA, etc.) — XML output is
                     handled internally.
            save_to: Optional path to save raw XML output. If empty, saves to
                     engagement/evidence/nmap-<target>.xml when the engagement
                     directory exists.
        """
        if sudo_error:
            return f"ERROR: {sudo_error}"

        # Build command — always use -oX - for XML to stdout
        cmd = ["sudo", "nmap"]
        cmd.extend(options.split())
        cmd.extend(["-oX", "-", target])

        scan_id = str(uuid.uuid4())[:8]
        start = datetime.now(tz=timezone.utc)

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=NMAP_TIMEOUT,
            )
        except subprocess.TimeoutExpired:
            return (
                f"ERROR: nmap scan timed out after {NMAP_TIMEOUT}s. "
                f"Set NMAP_TIMEOUT env var for longer scans."
            )

        if result.returncode != 0 and not result.stdout:
            return f"ERROR: nmap failed (exit {result.returncode}): {result.stderr}"

        xml_content = result.stdout
        if not xml_content.strip():
            return f"ERROR: nmap produced no output. stderr: {result.stderr}"

        # Parse XML
        try:
            parsed = _parse_nmap_xml(xml_content)
        except Exception as e:
            return f"ERROR: Failed to parse nmap XML: {e}\nRaw stderr: {result.stderr}"

        # Save evidence
        evidence_path = _save_evidence(
            xml_content, target, save_to if save_to else None
        )

        # Store in session memory
        scans[scan_id] = {
            "scan_id": scan_id,
            "target": target,
            "options": options,
            "command": " ".join(cmd),
            "timestamp": start.isoformat(),
            "parsed": parsed,
            "evidence_path": evidence_path,
        }

        # Build response
        response = {
            "scan_id": scan_id,
            "command": " ".join(cmd),
            "evidence_path": evidence_path,
            **parsed,
        }

        return json.dumps(response, indent=2, default=str)

    @mcp.tool()
    def get_scan(scan_id: str) -> str:
        """Retrieve full parsed results for a previous scan by ID.

        Args:
            scan_id: The scan ID returned by nmap_scan (e.g., "a1b2c3d4").
        """
        if scan_id not in scans:
            available = ", ".join(scans.keys()) if scans else "none"
            return f"Scan '{scan_id}' not found. Available scans: {available}"

        scan = scans[scan_id]
        return json.dumps(scan, indent=2, default=str)

    @mcp.tool()
    def list_scans() -> str:
        """List all scans run this session with target, timestamp, and host count."""
        if not scans:
            return "No scans run this session."

        lines = []
        for sid, scan in scans.items():
            parsed = scan["parsed"]
            hosts_up = parsed.get("hosts_up", 0)
            lines.append(
                f"**{sid}** | {scan['target']} | {scan['timestamp']} | "
                f"{hosts_up} host(s) up | {scan['options']}"
            )

        return "\n".join(lines)

    return mcp


def main() -> None:
    server = create_server()
    server.run()


if __name__ == "__main__":
    main()
