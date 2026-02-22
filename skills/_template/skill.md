---
name: skill-name
description: "One-line description shown in skill list"
category: web | ad | privesc | cloud | network | containers | c2 | redteam
tools: [tool1, tool2]
opsec: low | medium | high
references:
  - source: public-security-references
    path: docs/path/to/file.md
  - source: public-security-references
    path: Topic/file.md
  - source: public-security-references
    path: src/path/to/file.md
---

# Skill Name

<skill-name>skill-name</skill-name>

One-paragraph overview: what this technique does, when to use it, and what access/position it requires.

## Prerequisites

- Required access level or position
- Required tools (with install commands)
- Required conditions (e.g., "target must have X enabled")

## Enumeration

How to detect whether the target is vulnerable or the technique applies.

```bash
# Check if vulnerable
command --check target
```

## Exploitation

Step-by-step exploitation, each step commented.

### Variant A: [Description]

```bash
# Step 1: Explanation
command arg1 arg2

# Step 2: Explanation
command arg1 arg2
```

### Variant B: [Description]

```bash
# Alternative approach when Variant A doesn't apply
command arg1 arg2
```

## Post-Exploitation

What to do after successful exploitation (collect evidence, pivot, persist).

## Cleanup

How to remove artifacts and restore original state.

## Detection

What defenders look for — IOCs, log entries, alerts. Useful for OPSEC awareness.

## Troubleshooting

Common failure modes and how to resolve them.
