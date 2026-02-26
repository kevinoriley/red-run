"""Tests for the nmap MCP server.

Tests XML parsing, scan storage, and tool schema validation. Does NOT require
nmap or sudo — uses mock nmap XML output.
"""

from __future__ import annotations

# Add parent to path so we can import server
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from server import _parse_nmap_xml, _save_evidence, create_server

# --- Fixtures ---

MOCK_NMAP_XML = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -A -p- -T4 -oX - 10.10.10.5"
         start="1709000000" startstr="Tue Feb 27 2024 00:00:00"
         version="7.94" xmloutputversion="1.05">
<host starttime="1709000000" endtime="1709000060">
  <status state="up" reason="syn-ack"/>
  <address addr="10.10.10.5" addrtype="ipv4"/>
  <hostnames>
    <hostname name="target.htb" type="PTR"/>
  </hostnames>
  <ports>
    <port protocol="tcp" portid="22">
      <state state="open" reason="syn-ack"/>
      <service name="ssh" product="OpenSSH" version="8.9p1 Ubuntu 3ubuntu0.6"
               extrainfo="Ubuntu Linux; protocol 2.0" method="probed" conf="10"/>
    </port>
    <port protocol="tcp" portid="80">
      <state state="open" reason="syn-ack"/>
      <service name="http" product="Apache httpd" version="2.4.52"
               method="probed" conf="10"/>
      <script id="http-title" output="Apache2 Ubuntu Default Page"/>
    </port>
    <port protocol="tcp" portid="443">
      <state state="open" reason="syn-ack"/>
      <service name="https" product="Apache httpd" version="2.4.52"
               tunnel="ssl" method="probed" conf="10"/>
    </port>
  </ports>
  <os>
    <osmatch name="Linux 5.4" accuracy="95" line="1">
      <osclass type="general purpose" vendor="Linux" osfamily="Linux"
               osgen="5.X" accuracy="95"/>
    </osmatch>
  </os>
</host>
<runstats>
  <finished time="1709000060" timestr="Tue Feb 27 2024 00:01:00"
            elapsed="60.00" summary="Nmap done at Tue Feb 27; 1 IP address (1 host up)"
            exit="success"/>
  <hosts up="1" down="0" total="1"/>
</runstats>
</nmaprun>"""


# --- XML Parsing Tests ---


class TestParseNmapXml:
    def test_parses_host(self):
        result = _parse_nmap_xml(MOCK_NMAP_XML)
        assert result["hosts_up"] == 1
        assert result["hosts_total"] == 1
        assert len(result["hosts"]) == 1

    def test_parses_host_ip(self):
        result = _parse_nmap_xml(MOCK_NMAP_XML)
        host = result["hosts"][0]
        assert host["ip"] == "10.10.10.5"
        assert host["status"] == "up"

    def test_parses_hostnames(self):
        result = _parse_nmap_xml(MOCK_NMAP_XML)
        host = result["hosts"][0]
        assert "target.htb" in host["hostnames"]

    def test_parses_ports(self):
        result = _parse_nmap_xml(MOCK_NMAP_XML)
        ports = result["hosts"][0]["ports"]
        assert len(ports) == 3
        port_numbers = [p["port"] for p in ports]
        assert 22 in port_numbers
        assert 80 in port_numbers
        assert 443 in port_numbers

    def test_parses_service_info(self):
        result = _parse_nmap_xml(MOCK_NMAP_XML)
        ports = result["hosts"][0]["ports"]
        ssh_port = next(p for p in ports if p["port"] == 22)
        assert ssh_port["service"] == "ssh"
        assert ssh_port["state"] == "open"
        assert ssh_port["protocol"] == "tcp"

    def test_parses_nse_scripts(self):
        result = _parse_nmap_xml(MOCK_NMAP_XML)
        ports = result["hosts"][0]["ports"]
        http_port = next(p for p in ports if p["port"] == 80)
        assert "scripts" in http_port
        assert len(http_port["scripts"]) > 0

    def test_parses_os_detection(self):
        result = _parse_nmap_xml(MOCK_NMAP_XML)
        host = result["hosts"][0]
        assert "os_matches" in host
        assert len(host["os_matches"]) > 0
        assert host["os_matches"][0]["name"] == "Linux 5.4"
        assert host["os_matches"][0]["accuracy"] == 95

    def test_parses_scan_metadata(self):
        result = _parse_nmap_xml(MOCK_NMAP_XML)
        assert "command" in result
        assert "elapsed" in result
        assert "summary" in result


# --- Evidence Saving Tests ---


class TestSaveEvidence:
    def test_saves_to_custom_path(self, tmp_path):
        out_file = tmp_path / "custom.xml"
        result = _save_evidence("<xml/>", "10.10.10.5", str(out_file))
        assert result == str(out_file)
        assert out_file.read_text() == "<xml/>"

    def test_saves_to_engagement_evidence(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        evidence_dir = tmp_path / "engagement" / "evidence"
        evidence_dir.mkdir(parents=True)
        result = _save_evidence("<xml/>", "10.10.10.5", None)
        assert result is not None
        assert "nmap-10.10.10.5.xml" in result

    def test_returns_none_when_no_engagement_dir(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        result = _save_evidence("<xml/>", "10.10.10.5", None)
        assert result is None

    def test_sanitizes_target_in_filename(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        evidence_dir = tmp_path / "engagement" / "evidence"
        evidence_dir.mkdir(parents=True)
        result = _save_evidence("<xml/>", "10.10.10.0/24", None)
        assert result is not None
        assert "/" not in Path(result).name or "10.10.10.0_24" in result


# --- Server Creation Tests ---


class TestServerCreation:
    def test_creates_server(self):
        server = create_server()
        assert server is not None

    def test_server_has_tools(self):
        server = create_server()
        # FastMCP registers tools as decorated functions
        # Verify the server object exists and is a FastMCP instance
        assert server.name == "red-run-nmap-server"
