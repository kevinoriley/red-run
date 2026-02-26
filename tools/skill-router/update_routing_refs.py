#!/usr/bin/env python3
"""Update discovery skill routing references from Skill tool to MCP get_skill().

Handles multi-line patterns where Markdown wraps at ~80 chars, causing
"Invoke **X** via the Skill tool" to span 2-3 lines.
"""

import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
SKILLS_DIR = REPO_ROOT / "skills"

DISCOVERY_SKILLS = [
    SKILLS_DIR / "web/web-discovery/SKILL.md",
    SKILLS_DIR / "ad/ad-discovery/SKILL.md",
    SKILLS_DIR / "privesc/linux-discovery/SKILL.md",
    SKILLS_DIR / "privesc/windows-discovery/SKILL.md",
    SKILLS_DIR / "network/network-recon/SKILL.md",
]

# Use \s+ for all whitespace to handle line-wrap boundaries.
# [^*]+ for skill name (no asterisks in names, avoids greedy cross-line matching).
# .strip() on captured groups to clean up newlines.


def update_routing_refs(content: str) -> str:
    """Replace old Skill tool routing refs with MCP get_skill() pattern."""

    # 1. Table header: "Invoke via Skill Tool" → "Route To"
    content = re.sub(r"Invoke via Skill Tool", "Route To", content)

    # 2. "Invoke **X** via [the] Skill tool/Tool" (multi-line safe)
    #    → "Route to **X** — call `get_skill("X")` and follow its instructions"
    content = re.sub(
        r"(?<!re-)Invoke\s+\*\*([^*]+?)\*\*\s+via\s+(?:the\s+)?Skill\s+[Tt]ool",
        lambda m: (
            f'Route to **{m.group(1).strip()}** — call '
            f'`get_skill("{m.group(1).strip()}")` and follow its instructions'
        ),
        content,
    )

    # 3. Lowercase "invoke **X** via [the] Skill tool" (multi-line safe)
    content = re.sub(
        r"(?<!re-)invoke\s+\*\*([^*]+?)\*\*\s+via\s+(?:the\s+)?Skill\s+[Tt]ool",
        lambda m: (
            f'route to **{m.group(1).strip()}** — call '
            f'`get_skill("{m.group(1).strip()}")` and follow its instructions'
        ),
        content,
    )

    # 4. "re-invoke **X** via the Skill tool"
    content = re.sub(
        r"re-invoke\s+\*\*([^*]+?)\*\*\s+via\s+(?:the\s+)?Skill\s+[Tt]ool",
        lambda m: (
            f'route to **{m.group(1).strip()}** again — call '
            f'`get_skill("{m.group(1).strip()}")`'
        ),
        content,
    )

    # 5. "Invoke the named skill via the Skill tool" (multi-line safe)
    content = re.sub(
        r"Invoke\s+the\s+named\s+skill\s+via\s+the\s+Skill\s+[Tt]ool",
        'Load the skill — call `get_skill("skill-name")` and follow its instructions',
        content,
    )
    content = re.sub(
        r"invoke\s+the\s+named\s+skill\s+via\s+the\s+Skill\s+[Tt]ool",
        'load the skill — call `get_skill("skill-name")` and follow its instructions',
        content,
    )

    # 6. "invoking a technique skill via the Skill tool" (multi-line safe)
    content = re.sub(
        r"[Ii]nvoking\s+a\s+technique\s+skill\s+via\s+the\s+Skill\s+[Tt]ool",
        lambda m: (
            ("Loading" if m.group(0)[0] == "I" else "loading")
            + " a technique skill via `get_skill()`"
        ),
        content,
    )

    # 7. "invoke that skill using the Skill tool" (multi-line safe)
    content = re.sub(
        r"invoke\s+that\s+skill\s+using\s+the\s+Skill\s+[Tt]ool",
        'load and follow that skill using `get_skill("skill-name")`',
        content,
    )

    return content


def main():
    dry_run = "--dry-run" in sys.argv

    for skill_path in DISCOVERY_SKILLS:
        if not skill_path.exists():
            print(f"MISSING: {skill_path}")
            continue

        content = skill_path.read_text()
        updated = update_routing_refs(content)

        if content != updated:
            # Count actual character-level changes
            orig_lines = content.splitlines()
            new_lines = updated.splitlines()

            if dry_run:
                print(f"\n{'=' * 60}")
                print(f"FILE: {skill_path}")
                print(f"{'=' * 60}")

                # When multi-line matches collapse to single line, line counts differ.
                # Show a unified-diff-style output instead.
                import difflib

                diff = list(
                    difflib.unified_diff(
                        orig_lines,
                        new_lines,
                        lineterm="",
                        n=0,
                    )
                )
                for line in diff[2:]:  # skip --- and +++
                    if line.startswith("@@"):
                        print(f"  {line}")
                    elif line.startswith("-"):
                        print(f"  {line}")
                    elif line.startswith("+"):
                        print(f"  {line}")
                print(f"  (orig: {len(orig_lines)} lines → new: {len(new_lines)} lines)")
            else:
                skill_path.write_text(updated)
                print(f"Updated: {skill_path}")
        else:
            print(f"No changes: {skill_path}")


if __name__ == "__main__":
    main()
