"""Convert monolithic skill frontmatter to structured format.

Parses the old single-field description and extracts:
  - description: core "what it does" sentences
  - keywords: trigger phrases, technique names, search terms
  - tools: tool list
  - opsec: low/medium/high

Usage:
    uv run python convert_frontmatter.py [--skills-dir PATH] [--dry-run]
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

import yaml


# Skills that should not be converted
SKIP_DIRS = {"_template", "orchestrator"}


def parse_frontmatter(content: str) -> tuple[dict, str, str]:
    """Extract frontmatter dict, raw frontmatter text, and body from SKILL.md.

    Returns (frontmatter_dict, frontmatter_raw, body_after_closing_dashes).
    """
    match = re.match(r"^(---\s*\n)(.*?)(\n---\n?)", content, re.DOTALL)
    if not match:
        return {}, "", content
    opener = match.group(1)
    raw = match.group(2)
    closer = match.group(3)
    body = content[match.end():]
    try:
        data = yaml.safe_load(raw) or {}
    except yaml.YAMLError:
        data = {}
    return data, content[:match.end()], body


def extract_keywords_from_triggers(text: str) -> list[str]:
    """Extract quoted trigger phrases from the entire description.

    Many skills have trigger phrases both in "Use when" clauses (e.g.,
    'or says "X", "Y"') and in "Also triggers on:" sections. Extract all
    quoted phrases from the full text to catch both.
    """
    # Extract all double-quoted phrases from the full description
    return re.findall(r'"([^"]+)"', text)


def extract_tools(text: str) -> list[str]:
    """Extract tool list from 'Tools:' section."""
    # Match "Tools:" through end of sentence — but handle tool names with dots
    # (secretsdump.py, ntlmrelayx.py). A sentence ends with ". " + uppercase or
    # period at end, or "Do NOT"/"Do not".
    match = re.search(r"Tools?:\s*(.+?)(?:\.\s+Do\s|$)", text, re.DOTALL)
    if not match:
        # Fallback: try matching to end of text
        match = re.search(r"Tools?:\s*(.+)", text, re.DOTALL)
        if not match:
            return []
    tools_str = match.group(1).strip().rstrip(".")
    # Split on commas, clean up
    tools = [t.strip() for t in tools_str.split(",") if t.strip()]
    return tools


def extract_opsec(text: str) -> str:
    """Extract OPSEC level (low, medium, high) from description."""
    match = re.search(r"OPSEC:\s*(low|medium|high)", text, re.IGNORECASE)
    if match:
        return match.group(1).lower()
    # Check for compound levels
    match = re.search(r"OPSEC:\s*(low-medium|medium-high)", text, re.IGNORECASE)
    if match:
        return match.group(1).lower()
    return "medium"


def extract_core_description(text: str) -> str:
    """Extract the core description — everything before trigger/OPSEC/negative markers."""
    # Find the earliest marker that starts the "metadata" portion
    markers = [
        r"Use this skill when\b",
        r"Use when\b",
        r"(?:Also\s+)?[Tt]riggers?\s+on[:\s]",
        r"OPSEC:",
        r"Tools?:",
        r"Do NOT use\b",
        r"Do not use\b",
    ]

    cutoff = len(text)
    for marker in markers:
        match = re.search(marker, text)
        if match and match.start() < cutoff:
            cutoff = match.start()

    core = text[:cutoff].strip()

    # Also grab useful context from "Use when" clause as keywords
    return core


def extract_use_when_keywords(text: str) -> list[str]:
    """Extract meaningful terms from 'Use when/Use this skill when' clauses."""
    keywords = []
    match = re.search(r"Use (?:this skill )?when\s+(.*?)(?:\.\s*(?:Also|Triggers|OPSEC|Tools|Do NOT)|$)", text, re.DOTALL | re.IGNORECASE)
    if not match:
        return keywords

    clause = match.group(1).strip().rstrip(".")
    # Don't add the whole clause — it's too long. But if it has useful noun phrases, extract them.
    # For now, add it as a single keyword if it's short enough
    if len(clause) < 100:
        keywords.append(clause)
    return keywords


def convert_skill(skill_path: Path) -> tuple[bool, str]:
    """Convert a single skill's frontmatter. Returns (changed, message)."""
    content = skill_path.read_text()
    data, raw_fm, body = parse_frontmatter(content)

    if not data:
        return False, "no frontmatter found"

    # Already converted?
    if "keywords" in data:
        return False, "already has keywords field"

    name = data.get("name", skill_path.parent.name)
    old_desc = data.get("description", "").strip()

    if not old_desc:
        return False, "no description"

    # Extract structured fields from monolithic description
    core_desc = extract_core_description(old_desc)
    trigger_keywords = extract_keywords_from_triggers(old_desc)
    use_when_keywords = extract_use_when_keywords(old_desc)
    tools = extract_tools(old_desc)
    opsec = extract_opsec(old_desc)

    # Combine keywords: trigger phrases + use-when terms (deduplicated)
    all_keywords = []
    seen_lower = set()
    for kw in trigger_keywords + use_when_keywords:
        if kw.lower() not in seen_lower:
            all_keywords.append(kw)
            seen_lower.add(kw.lower())

    # Build new frontmatter
    new_fm_lines = ["---"]
    new_fm_lines.append(f"name: {name}")

    # Description — use YAML block scalar
    new_fm_lines.append("description: >")
    # Wrap description to ~78 chars with 2-space indent
    desc_lines = wrap_yaml_text(core_desc, indent=2, width=78)
    new_fm_lines.extend(desc_lines)

    # Keywords
    if all_keywords:
        new_fm_lines.append("keywords:")
        for kw in all_keywords:
            new_fm_lines.append(f"  - {kw}")

    # Tools
    if tools:
        new_fm_lines.append("tools:")
        for tool in tools:
            new_fm_lines.append(f"  - {tool}")

    # OPSEC
    new_fm_lines.append(f"opsec: {opsec}")

    new_fm_lines.append("---")

    new_content = "\n".join(new_fm_lines) + body
    skill_path.write_text(new_content)

    return True, f"converted ({len(all_keywords)} keywords, {len(tools)} tools, opsec={opsec})"


def wrap_yaml_text(text: str, indent: int = 2, width: int = 78) -> list[str]:
    """Wrap text for YAML block scalar with given indent."""
    prefix = " " * indent
    words = text.split()
    lines = []
    current_line = prefix

    for word in words:
        if len(current_line) + len(word) + 1 > width and current_line.strip():
            lines.append(current_line)
            current_line = prefix + word
        else:
            if current_line.strip():
                current_line += " " + word
            else:
                current_line = prefix + word

    if current_line.strip():
        lines.append(current_line)

    return lines


def main() -> None:
    parser = argparse.ArgumentParser(description="Convert skill frontmatter to structured format")
    parser.add_argument(
        "--skills-dir",
        type=Path,
        default=Path(__file__).resolve().parent.parent.parent / "skills",
        help="Path to skills/ directory",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print what would be done without modifying files",
    )
    args = parser.parse_args()

    if not args.skills_dir.is_dir():
        print(f"Error: skills directory not found: {args.skills_dir}", file=sys.stderr)
        sys.exit(1)

    skill_files = sorted(args.skills_dir.rglob("SKILL.md"))
    converted = 0
    skipped = 0
    errors = 0

    for skill_path in skill_files:
        relative = skill_path.relative_to(args.skills_dir)
        # Skip template and orchestrator
        if any(part in SKIP_DIRS for part in relative.parts):
            print(f"  SKIP  {relative} (excluded)")
            skipped += 1
            continue

        if args.dry_run:
            # Just show what we'd do
            content = skill_path.read_text()
            data, _, _ = parse_frontmatter(content)
            old_desc = data.get("description", "").strip()
            if "keywords" in data:
                print(f"  SKIP  {relative} (already converted)")
                skipped += 1
            elif old_desc:
                core = extract_core_description(old_desc)
                triggers = extract_keywords_from_triggers(old_desc)
                tools = extract_tools(old_desc)
                opsec = extract_opsec(old_desc)
                print(f"  WOULD {relative}:")
                print(f"         desc: {core[:80]}...")
                print(f"         keywords: {len(triggers)}, tools: {len(tools)}, opsec: {opsec}")
            else:
                print(f"  SKIP  {relative} (no description)")
                skipped += 1
            continue

        try:
            changed, msg = convert_skill(skill_path)
            if changed:
                print(f"  OK    {relative}: {msg}")
                converted += 1
            else:
                print(f"  SKIP  {relative}: {msg}")
                skipped += 1
        except Exception as e:
            print(f"  ERR   {relative}: {e}")
            errors += 1

    print(f"\nDone: {converted} converted, {skipped} skipped, {errors} errors")


if __name__ == "__main__":
    main()
