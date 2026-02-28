"""Tests for nmap input validation.

Tests every blocked flag, allowed flags, --script name vs path, target
metacharacters, save_to traversal, and filename sanitization.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from validate import (
    ValidationError,
    sanitize_target_for_filename,
    validate_options,
    validate_save_to,
    validate_target,
)


# --- validate_options ---


class TestValidateOptions:
    """Tests for option string validation."""

    def test_allows_common_scan_flags(self):
        args = validate_options("-A -p- -T4")
        assert args == ["-A", "-p-", "-T4"]

    def test_allows_port_specification(self):
        args = validate_options("-p 22,80,443")
        assert args == ["-p", "22,80,443"]

    def test_allows_ping_scan(self):
        args = validate_options("-sn -PE -PS22,80")
        assert args == ["-sn", "-PE", "-PS22,80"]

    def test_allows_version_detection(self):
        args = validate_options("-sV --version-intensity 5")
        assert args == ["-sV", "--version-intensity", "5"]

    def test_allows_timing_template(self):
        args = validate_options("-T3")
        assert args == ["-T3"]

    def test_allows_safe_script_names(self):
        args = validate_options("--script default")
        assert "--script" in args
        assert "default" in args

    def test_allows_script_with_equals(self):
        args = validate_options("--script=vuln,safe")
        assert "--script=vuln,safe" in args

    def test_allows_script_wildcards(self):
        args = validate_options("--script http-*")
        assert "http-*" in args

    def test_allows_script_categories(self):
        args = validate_options("--script smb-enum-shares,smb-enum-users")
        assert "smb-enum-shares,smb-enum-users" in args

    def test_allows_empty_options(self):
        args = validate_options("")
        assert args == []

    # --- Blocked file-read flags ---

    def test_blocks_iL(self):
        with pytest.raises(ValidationError, match="Blocked flag.*-iL"):
            validate_options("-iL /etc/passwd")

    def test_blocks_excludefile(self):
        with pytest.raises(ValidationError, match="Blocked flag.*--excludefile"):
            validate_options("--excludefile /tmp/exclude.txt")

    def test_blocks_resume(self):
        with pytest.raises(ValidationError, match="Blocked flag.*--resume"):
            validate_options("--resume /tmp/nmap.xml")

    def test_blocks_servicedb(self):
        with pytest.raises(ValidationError, match="Blocked flag.*--servicedb"):
            validate_options("--servicedb /etc/services")

    def test_blocks_versiondb(self):
        with pytest.raises(ValidationError, match="Blocked flag.*--versiondb"):
            validate_options("--versiondb /tmp/probes")

    # --- Blocked file-write flags ---

    def test_blocks_oN(self):
        with pytest.raises(ValidationError, match="Blocked flag.*-oN"):
            validate_options("-oN /tmp/out.txt")

    def test_blocks_oG(self):
        with pytest.raises(ValidationError, match="Blocked flag.*-oG"):
            validate_options("-oG /tmp/out.gnmap")

    def test_blocks_oX(self):
        with pytest.raises(ValidationError, match="Blocked flag.*-oX"):
            validate_options("-oX /tmp/out.xml")

    def test_blocks_oA(self):
        with pytest.raises(ValidationError, match="Blocked flag.*-oA"):
            validate_options("-oA /tmp/out")

    def test_blocks_append_output(self):
        with pytest.raises(ValidationError, match="Blocked flag.*--append-output"):
            validate_options("--append-output -oN /tmp/out.txt")

    # --- Blocked path-override flags ---

    def test_blocks_datadir(self):
        with pytest.raises(ValidationError, match="Blocked flag.*--datadir"):
            validate_options("--datadir /tmp/nmap-data")

    def test_blocks_script_updatedb(self):
        with pytest.raises(ValidationError, match="Blocked flag.*--script-updatedb"):
            validate_options("--script-updatedb")

    def test_blocks_script_path(self):
        with pytest.raises(ValidationError, match="Blocked flag.*--script-path"):
            validate_options("--script-path /tmp/scripts")

    def test_blocks_script_args_file(self):
        with pytest.raises(ValidationError, match="Blocked flag.*--script-args-file"):
            validate_options("--script-args-file /tmp/args.txt")

    # --- Blocked --script paths ---

    def test_blocks_script_with_path(self):
        with pytest.raises(ValidationError, match="Blocked --script value"):
            validate_options("--script /tmp/evil.nse")

    def test_blocks_script_with_relative_path(self):
        with pytest.raises(ValidationError, match="Blocked --script value"):
            validate_options("--script ./evil.nse")

    def test_blocks_script_with_equals_path(self):
        with pytest.raises(ValidationError, match="Blocked --script value"):
            validate_options("--script=/tmp/evil.nse")

    # --- Malformed input ---

    def test_blocks_malformed_quotes(self):
        with pytest.raises(ValidationError, match="Malformed"):
            validate_options('-A "unclosed quote')


# --- validate_target ---


class TestValidateTarget:
    """Tests for target string validation."""

    def test_allows_ipv4(self):
        assert validate_target("10.10.10.5") == "10.10.10.5"

    def test_allows_cidr(self):
        assert validate_target("10.10.10.0/24") == "10.10.10.0/24"

    def test_allows_hostname(self):
        assert validate_target("target.htb") == "target.htb"

    def test_allows_subdomain(self):
        assert validate_target("app.target.htb") == "app.target.htb"

    def test_blocks_empty_target(self):
        with pytest.raises(ValidationError, match="cannot be empty"):
            validate_target("")

    def test_blocks_whitespace_only(self):
        with pytest.raises(ValidationError, match="cannot be empty"):
            validate_target("   ")

    def test_blocks_path_traversal(self):
        with pytest.raises(ValidationError, match="path traversal"):
            validate_target("../../etc/passwd")

    def test_blocks_semicolon(self):
        with pytest.raises(ValidationError, match="shell metacharacters"):
            validate_target("10.10.10.5; rm -rf /")

    def test_blocks_pipe(self):
        with pytest.raises(ValidationError, match="shell metacharacters"):
            validate_target("10.10.10.5 | cat /etc/passwd")

    def test_blocks_ampersand(self):
        with pytest.raises(ValidationError, match="shell metacharacters"):
            validate_target("10.10.10.5 & whoami")

    def test_blocks_backtick(self):
        with pytest.raises(ValidationError, match="shell metacharacters"):
            validate_target("`whoami`")

    def test_blocks_dollar_paren(self):
        with pytest.raises(ValidationError, match="shell metacharacters"):
            validate_target("$(whoami)")

    def test_blocks_braces(self):
        with pytest.raises(ValidationError, match="shell metacharacters"):
            validate_target("{echo,test}")

    def test_blocks_whitespace_injection(self):
        with pytest.raises(ValidationError, match="whitespace"):
            validate_target("10.10.10.5 -iL /etc/passwd")


# --- validate_save_to ---


class TestValidateSaveTo:
    """Tests for save_to path validation."""

    def test_allows_path_under_evidence(self, tmp_path):
        evidence_dir = tmp_path / "engagement" / "evidence"
        evidence_dir.mkdir(parents=True)
        result = validate_save_to("engagement/evidence/scan.xml", tmp_path)
        assert result == evidence_dir / "scan.xml"

    def test_allows_nested_path_under_evidence(self, tmp_path):
        evidence_dir = tmp_path / "engagement" / "evidence" / "nmap"
        evidence_dir.mkdir(parents=True)
        result = validate_save_to("engagement/evidence/nmap/scan.xml", tmp_path)
        assert result == evidence_dir / "scan.xml"

    def test_blocks_path_outside_evidence(self, tmp_path):
        (tmp_path / "engagement" / "evidence").mkdir(parents=True)
        with pytest.raises(ValidationError, match="must be under"):
            validate_save_to("/etc/passwd", tmp_path)

    def test_blocks_traversal_out_of_evidence(self, tmp_path):
        (tmp_path / "engagement" / "evidence").mkdir(parents=True)
        with pytest.raises(ValidationError, match="must be under"):
            validate_save_to("engagement/evidence/../../etc/passwd", tmp_path)

    def test_blocks_empty_save_to(self):
        with pytest.raises(ValidationError, match="cannot be empty"):
            validate_save_to("", Path("/tmp"))

    def test_blocks_engagement_root(self, tmp_path):
        (tmp_path / "engagement" / "evidence").mkdir(parents=True)
        with pytest.raises(ValidationError, match="must be under"):
            validate_save_to("engagement/state.db", tmp_path)


# --- sanitize_target_for_filename ---


class TestSanitizeTargetForFilename:
    """Tests for filename sanitization."""

    def test_ipv4(self):
        assert sanitize_target_for_filename("10.10.10.5") == "10.10.10.5"

    def test_cidr_slash(self):
        result = sanitize_target_for_filename("10.10.10.0/24")
        assert "/" not in result
        assert result == "10.10.10.0_24"

    def test_dotdot_traversal(self):
        result = sanitize_target_for_filename("../../etc/passwd")
        assert ".." not in result
        assert "/" not in result

    def test_hostname(self):
        assert sanitize_target_for_filename("target.htb") == "target.htb"

    def test_shell_metacharacters(self):
        result = sanitize_target_for_filename("10.10.10.5;rm -rf /")
        assert ";" not in result
        assert " " not in result

    def test_empty_string(self):
        assert sanitize_target_for_filename("") == "unknown"

    def test_only_special_chars(self):
        assert sanitize_target_for_filename(";;;") == "unknown"

    def test_backslash(self):
        result = sanitize_target_for_filename("foo\\bar")
        assert "\\" not in result
