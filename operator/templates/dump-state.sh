#!/usr/bin/env bash
set -euo pipefail

# dump-state.sh — Export engagement state.db as readable markdown.
# Usage: ./dump-state.sh [--db PATH]
# Default DB: ./state.db (run from engagement/ directory)

DB="./state.db"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --db)
            DB="$2"
            shift 2
            ;;
        -h|--help)
            echo "Usage: $0 [--db PATH]"
            echo "  Export engagement state.db as markdown."
            echo "  Default DB: ./state.db"
            exit 0
            ;;
        *)
            echo "Unknown option: $1" >&2
            exit 1
            ;;
    esac
done

if [[ ! -f "$DB" ]]; then
    echo "Error: database not found: $DB" >&2
    exit 1
fi

sql() { sqlite3 -separator '|' "$DB" "$1"; }
sql_count() { sqlite3 "$DB" "$1"; }

# --- Engagement metadata ---
echo "# Engagement State"
echo

meta=$(sql "SELECT name, mode, status, created_at FROM engagement WHERE id = 1" 2>/dev/null || true)
if [[ -n "$meta" ]]; then
    IFS='|' read -r name mode status created_at <<< "$meta"
    echo "**${name:-unnamed}** | Mode: ${mode} | Status: ${status} | Created: ${created_at}"
    echo
fi

# --- Targets ---
echo "## Targets"
echo
count=$(sql_count "SELECT COUNT(*) FROM targets")
if [[ "$count" -eq 0 ]]; then
    echo "_(none)_"
else
    sql "SELECT t.id, t.host, t.os, t.role FROM targets t ORDER BY t.id" | while IFS='|' read -r tid host os role; do
        ports=$(sql "SELECT port || '/' || protocol FROM ports WHERE target_id = ${tid} ORDER BY port" | paste -sd, -)
        services=$(sql "SELECT service FROM ports WHERE target_id = ${tid} AND service != '' ORDER BY port" | paste -sd, -)
        parts="$host"
        [[ -n "$os" ]] && parts="$parts | $os"
        [[ -n "$role" ]] && parts="$parts | $role"
        [[ -n "$ports" ]] && parts="$parts | $ports"
        [[ -n "$services" ]] && parts="$parts | ($services)"
        echo "- $parts"
    done
fi
echo

# --- Credentials ---
echo "## Credentials"
echo
count=$(sql_count "SELECT COUNT(*) FROM credentials")
if [[ "$count" -eq 0 ]]; then
    echo "_(none)_"
else
    sql "SELECT c.id, c.username, c.secret, c.secret_type, c.domain, c.cracked, c.notes,
         COALESCE((SELECT GROUP_CONCAT(t.host || ':' || ca.service, ', ')
                   FROM credential_access ca JOIN targets t ON ca.target_id = t.id
                   WHERE ca.credential_id = c.id AND ca.works = 1), '') AS works_on,
         COALESCE((SELECT GROUP_CONCAT(t.host || ':' || ca.service, ', ')
                   FROM credential_access ca JOIN targets t ON ca.target_id = t.id
                   WHERE ca.credential_id = c.id AND ca.works = 0), '') AS fails_on
         FROM credentials c ORDER BY c.id" | while IFS='|' read -r _cid username secret secret_type domain cracked notes works_on fails_on; do
        # Mask non-password secrets longer than 32 chars
        if [[ "$secret_type" != "password" ]] && [[ "${#secret}" -gt 32 ]]; then
            secret="${secret:0:32}..."
        fi
        parts=""
        if [[ -n "$domain" ]]; then
            parts="${domain}\\${username}"
        else
            parts="$username"
        fi
        parts="$parts | $secret ($secret_type)"
        [[ "$cracked" -eq 1 ]] && parts="$parts | [cracked]"
        [[ -n "$works_on" ]] && parts="$parts | works: $works_on"
        [[ -n "$fails_on" ]] && parts="$parts | fails: $fails_on"
        [[ -n "$notes" ]] && parts="$parts | $notes"
        echo "- $parts"
    done
fi
echo

# --- Access ---
echo "## Access"
echo
active_count=$(sql_count "SELECT COUNT(*) FROM access WHERE active = 1")
revoked_count=$(sql_count "SELECT COUNT(*) FROM access WHERE active = 0")
if [[ "$active_count" -eq 0 ]] && [[ "$revoked_count" -eq 0 ]]; then
    echo "_(none)_"
else
    if [[ "$active_count" -gt 0 ]]; then
        sql "SELECT a.id, t.host, a.username, a.access_type, a.privilege, a.method, a.session_ref, a.notes
             FROM access a JOIN targets t ON a.target_id = t.id
             WHERE a.active = 1 ORDER BY a.id" | while IFS='|' read -r _aid host username access_type privilege method session_ref notes; do
            parts="$host | $username via $access_type | [$privilege]"
            [[ -n "$method" ]] && parts="$parts | from $method"
            [[ -n "$session_ref" ]] && parts="$parts | session:$session_ref"
            [[ -n "$notes" ]] && parts="$parts | $notes"
            echo "- $parts"
        done
    fi
    if [[ "$revoked_count" -gt 0 ]]; then
        sql "SELECT t.host, a.username, a.access_type
             FROM access a JOIN targets t ON a.target_id = t.id
             WHERE a.active = 0 ORDER BY a.id" | while IFS='|' read -r host username access_type; do
            echo "- ~~$host | $username via $access_type~~ [revoked]"
        done
    fi
fi
echo

# --- Vulns ---
echo "## Vulns"
echo
count=$(sql_count "SELECT COUNT(*) FROM vulns")
if [[ "$count" -eq 0 ]]; then
    echo "_(none)_"
else
    sql "SELECT v.title, v.status, v.severity, COALESCE(t.host, 'unknown'), v.endpoint, v.details
         FROM vulns v LEFT JOIN targets t ON v.target_id = t.id
         ORDER BY v.id" | while IFS='|' read -r title status severity host endpoint details; do
        parts="$title [$status] | [$severity] | $host"
        [[ -n "$endpoint" ]] && parts="$parts | $endpoint"
        [[ -n "$details" ]] && parts="$parts | $details"
        echo "- $parts"
    done
fi
echo

# --- Pivot Map ---
echo "## Pivot Map"
echo
count=$(sql_count "SELECT COUNT(*) FROM pivot_map")
if [[ "$count" -eq 0 ]]; then
    echo "_(none)_"
else
    sql "SELECT source, destination, method, status, notes FROM pivot_map ORDER BY id" | while IFS='|' read -r source destination method status notes; do
        parts="$source -> $destination"
        [[ -n "$method" ]] && parts="$parts | via $method"
        parts="$parts | [$status]"
        [[ -n "$notes" ]] && parts="$parts | $notes"
        echo "- $parts"
    done
fi
echo

# --- Tunnels ---
echo "## Tunnels"
echo
has_tunnels=$(sql_count "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='tunnels'")
if [[ "$has_tunnels" -eq 0 ]]; then
    echo "_(none)_"
else
    count=$(sql_count "SELECT COUNT(*) FROM tunnels WHERE status != 'closed'")
    if [[ "$count" -eq 0 ]]; then
        echo "_(none)_"
    else
        sql "SELECT tunnel_type, pivot_host, target_subnet, local_endpoint, status, requires_proxychains, notes
             FROM tunnels WHERE status != 'closed' ORDER BY id" | while IFS='|' read -r tunnel_type pivot_host target_subnet local_endpoint status requires_proxychains notes; do
            if [[ "$requires_proxychains" -eq 1 ]]; then
                proxy_note="(proxychains required)"
            else
                proxy_note="(transparent)"
            fi
            parts="$tunnel_type"
            [[ -n "$pivot_host" ]] && parts="$parts | via $pivot_host"
            if [[ -n "$target_subnet" ]]; then
                parts="$parts | -> $target_subnet"
            else
                parts="$parts | -> *"
            fi
            [[ -n "$local_endpoint" ]] && parts="$parts | $local_endpoint"
            parts="$parts | [$status] | $proxy_note"
            [[ -n "$notes" ]] && parts="$parts | $notes"
            echo "- $parts"
        done
    fi
fi
echo

# --- Blocked ---
echo "## Blocked"
echo
count=$(sql_count "SELECT COUNT(*) FROM blocked")
if [[ "$count" -eq 0 ]]; then
    echo "_(none)_"
else
    sql "SELECT b.technique, COALESCE(t.host, ''), b.reason, b.retry, b.notes
         FROM blocked b LEFT JOIN targets t ON b.target_id = t.id
         ORDER BY b.id" | while IFS='|' read -r technique host reason retry notes; do
        parts="$technique"
        [[ -n "$host" ]] && parts="$parts | $host"
        parts="$parts | $reason | [$retry]"
        [[ -n "$notes" ]] && parts="$parts | $notes"
        echo "- $parts"
    done
fi
echo

# --- Timeline (state_events) ---
echo "## Timeline"
echo
count=$(sql_count "SELECT COUNT(*) FROM state_events")
if [[ "$count" -eq 0 ]]; then
    echo "_(none)_"
else
    sql "SELECT id, created_at, event_type, agent, summary FROM state_events ORDER BY id" | while IFS='|' read -r _eid created_at event_type agent summary; do
        parts="[$created_at] $event_type"
        [[ -n "$agent" ]] && parts="$parts ($agent)"
        parts="$parts: $summary"
        echo "- $parts"
    done
fi
