# Changelog

## Unreleased

### Breaking Changes

- **Default orchestrator is now `/red-run-ctf`** (agent teams). The original subagent-based orchestrator has moved to `/red-run-legacy` and no longer auto-triggers from natural language. If you rely on the old orchestrator, invoke it manually with `/red-run-legacy`.
- **Skill directory renamed**: `skills/orchestrator/` → `skills/legacy/`, `skills/ctf/` is the new default. Run `./install.sh` to update installed skill symlinks.
- **agentsee removed** from project settings and `.mcp.json`. Agent teams provides native operator visibility via tmux split panes. agentsee hooks (`PreToolUse`, `PostToolUse`) are no longer configured by default.
- **`.claude/settings.json` now includes `CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS=1`**. This enables the experimental agent teams feature for all sessions in this project.

### Added

- **Agent teams orchestrator** (`/red-run-ctf`) — uses Claude Code agent teams instead of ephemeral subagents. Persistent teammates accumulate domain context across tasks, communicate via peer-to-peer messaging, and are visible in tmux split panes.
- **Teammate spawn templates** (`teammates/`) — 10 templates (5 persistent domain teammates, 5 on-demand specialists) that the orchestrator reads at runtime to spawn teammates.
- **Multi-orchestrator architecture** — multiple orchestrator variants coexist in the same repo, sharing state.db, MCP servers, and technique skills. Planned variants: `/red-run-notouch` (DLP-safe), `/red-run-train` (training mode).
- **`startup_delay` parameter for `start_process`** in shell-server — prevents prompt probe race condition with slow-connecting tools like evil-winrm (use `startup_delay=30`).

### Fixed

- **SQLite "database is locked" under concurrent writes** — all state-server database connections now use context managers, preventing leaked connections from holding the write lock indefinitely. `busy_timeout` increased from 5s to 30s.
- **Pivot-first logic** in orchestrator decision flow — the orchestrator now acts immediately when a pivot path and host access are both available, instead of deferring to lower-priority checks.

### Changed

- Dashboard and monitoring docs rewritten for agent teams as primary visibility mechanism.
- README restructured: added orchestrators table, agent teams section, removed skills table (lives in docs only), removed agentsee references.
