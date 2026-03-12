# Operator Templates

Reusable scripts that the orchestrator copies into the engagement directory
when needed. The orchestrator fills in target-specific values at copy time.

| Template | Purpose | Usage |
|----------|---------|-------|
| `clock-sync.sh` | Sync attackbox clock to DC via ntpdate | Copied when Kerberos clock skew is detected |
| `hosts-update.sh` | Add hostname entries to `/etc/hosts` | Copied when discovered hostnames don't resolve |
| `dump-state.sh` | Export `state.db` as readable markdown | Run manually from `engagement/` to view or back up state |

## dump-state.sh

```bash
# From the engagement directory (default: ./state.db)
bash dump-state.sh

# Specify a different database
bash dump-state.sh --db /path/to/state.db

# Save a snapshot
bash dump-state.sh > state-snapshot.md
```

Produces the same sections as `get_state_summary()` but without truncation
limits, plus a Timeline section showing all `state_events` rows.
