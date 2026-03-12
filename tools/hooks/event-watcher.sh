#!/usr/bin/env bash
# Event watcher — polls state_events, exits on new findings
# Spawned by orchestrator with run_in_background: true
# Uses python3 sqlite3 module (stdlib) — no sqlite3 CLI dependency
set -euo pipefail

CURSOR=${1:?usage: event-watcher.sh <cursor> <db_path>}
DB=${2:?usage: event-watcher.sh <cursor> <db_path>}
DEBOUNCE=60  # seconds to wait after detecting events (batch coalescing)
POLL=5       # seconds between polls
TIMEOUT=1800 # max lifetime (30 min) — long technique chains can take 15-25 min

elapsed=0
while [ "$elapsed" -lt "$TIMEOUT" ]; do
    count=$(python3 -c "
import sqlite3, sys
conn = sqlite3.connect(sys.argv[1])
print(conn.execute('SELECT count(*) FROM state_events WHERE id > ?', (int(sys.argv[2]),)).fetchone()[0])
conn.close()
" "$DB" "$CURSOR")
    if [ "$count" -gt 0 ]; then
        sleep "$DEBOUNCE"  # let the agent finish its batch
        python3 -c "
import sqlite3, json, sys
conn = sqlite3.connect(sys.argv[1])
conn.row_factory = sqlite3.Row
rows = conn.execute(
    'SELECT id, event_type, record_id, summary, agent, created_at FROM state_events WHERE id > ? ORDER BY id',
    (int(sys.argv[2]),)
).fetchall()
print(json.dumps([dict(r) for r in rows]))
conn.close()
" "$DB" "$CURSOR"
        exit 0
    fi
    sleep "$POLL"
    elapsed=$((elapsed + POLL))
done

echo '{"timeout": true, "cursor": '"$CURSOR"'}'
exit 0
