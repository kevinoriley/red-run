# Operator Templates

Reusable scripts that the orchestrator copies into the engagement directory
when needed. The orchestrator fills in target-specific values at copy time.

| Template | Purpose | Usage |
|----------|---------|-------|
| `config.yaml` | Engagement config with all keys and comments | Base template for config wizard output |
| `web-proxy-enabled.sh` | Web proxy env vars (enabled mode) | Copied to `engagement/web-proxy.sh`; `PROXY_URL` replaced with actual URL |
| `web-proxy-disabled.sh` | Web proxy env vars (disabled mode) | Copied to `engagement/web-proxy.sh` when operator skips proxying |
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
