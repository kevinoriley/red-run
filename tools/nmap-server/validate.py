"""Input validation for the nmap MCP server.

Blocks dangerous nmap flags, shell metacharacters, and path traversal
attempts. Defense-in-depth against prompt injection — even though nmap runs
inside a Docker container, we validate inputs before they reach subprocess.
"""

from __future__ import annotations

import re
import shlex
from pathlib import Path

# --- Blocked nmap flags ---

# Flags that read arbitrary files from the filesystem
_FILE_READ_FLAGS = frozenset({
    "-iL", "--excludefile", "--resume", "--servicedb", "--versiondb",
})

# Flags that write files (we control output via -oX -)
_FILE_WRITE_FLAGS = frozenset({
    "-oN", "-oG", "-oX", "-oA", "--append-output",
})

# Flags that override data/script paths
_PATH_OVERRIDE_FLAGS = frozenset({
    "--datadir", "--script-updatedb", "--script-path", "--script-args-file",
})

_ALL_BLOCKED_FLAGS = _FILE_READ_FLAGS | _FILE_WRITE_FLAGS | _PATH_OVERRIDE_FLAGS

# Safe pattern for --script arguments: bare script names, wildcards, categories
# e.g. "default", "vuln,safe", "http-*", "smb-enum-shares"
_SAFE_SCRIPT_NAME = re.compile(r"^[a-zA-Z0-9_*?,-]+$")

# Shell metacharacters that should never appear in targets
_SHELL_METACHAR = re.compile(r"[;|&`$(){}\[\]<>!#~]")


class ValidationError(Exception):
    """Raised when input validation fails."""


def validate_options(options: str) -> list[str]:
    """Validate and parse nmap options string.

    Returns the parsed argument list on success. Raises ValidationError if
    dangerous flags are detected.

    Uses shlex.split() for proper quoted-argument handling.
    """
    try:
        args = shlex.split(options)
    except ValueError as e:
        raise ValidationError(f"Malformed options string: {e}") from e

    i = 0
    while i < len(args):
        arg = args[i]

        # Normalize long flags that use = (e.g. --script=vuln)
        flag = arg.split("=", 1)[0] if "=" in arg else arg

        # Check against blocklist
        if flag in _ALL_BLOCKED_FLAGS:
            raise ValidationError(
                f"Blocked flag: {flag} — this flag is not allowed for security reasons"
            )

        # Validate --script arguments
        if flag == "--script":
            if "=" in arg:
                script_value = arg.split("=", 1)[1]
            elif i + 1 < len(args):
                script_value = args[i + 1]
                i += 1
            else:
                raise ValidationError("--script requires an argument")

            if not _SAFE_SCRIPT_NAME.match(script_value):
                raise ValidationError(
                    f"Blocked --script value: {script_value!r} — "
                    f"only bare script names are allowed (no paths or URLs)"
                )

        i += 1

    return args


def validate_target(target: str) -> str:
    """Validate a scan target string.

    Allows IPs, hostnames, CIDR ranges. Blocks shell metacharacters and
    path traversal. Returns the target unchanged on success.
    """
    if not target or not target.strip():
        raise ValidationError("Target cannot be empty")

    if ".." in target:
        raise ValidationError(
            f"Blocked target: {target!r} — path traversal not allowed"
        )

    if _SHELL_METACHAR.search(target):
        raise ValidationError(
            f"Blocked target: {target!r} — contains shell metacharacters"
        )

    # Block whitespace (could inject extra arguments)
    if any(c.isspace() for c in target):
        raise ValidationError(
            f"Blocked target: {target!r} — whitespace not allowed in target"
        )

    return target


def validate_save_to(save_to: str, project_root: Path) -> Path:
    """Validate a save_to path is under engagement/evidence/.

    Returns the resolved Path on success. Raises ValidationError if the
    path escapes the evidence directory.
    """
    if not save_to:
        raise ValidationError("save_to cannot be empty")

    evidence_dir = (project_root / "engagement" / "evidence").resolve()
    resolved = (project_root / save_to).resolve()

    # Must be under engagement/evidence/
    try:
        resolved.relative_to(evidence_dir)
    except ValueError:
        raise ValidationError(
            f"Blocked save_to: {save_to!r} — must be under engagement/evidence/"
        )

    return resolved


def sanitize_target_for_filename(target: str) -> str:
    """Sanitize a target string for use in evidence filenames.

    Replaces slashes, dots-dots, and non-alphanumeric characters (except
    dots, hyphens, and underscores) with underscores.
    """
    # First collapse any .. sequences
    safe = target.replace("..", "_")
    # Replace path separators
    safe = safe.replace("/", "_").replace("\\", "_")
    # Replace any remaining unsafe characters (keep alphanumeric, dot, hyphen, underscore)
    safe = re.sub(r"[^a-zA-Z0-9._-]", "_", safe)
    # Collapse multiple underscores
    safe = re.sub(r"_+", "_", safe)
    # Strip leading/trailing underscores
    safe = safe.strip("_")
    return safe or "unknown"
