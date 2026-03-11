#!/usr/bin/env bash
set -euo pipefail
# Sync attackbox clock with DC for Kerberos authentication.
# Fill in DC_IP, run with sudo in background: sudo bash clock-sync.sh &

DC_IP="FILL_IN"

# Disable VirtualBox time sync if running (it fights ntpdate)
if pgrep -x VBoxService >/dev/null 2>&1; then
    echo "[*] Disabling VirtualBox time sync..."
    killall VBoxService 2>/dev/null
    VBoxService --disable-timesync &
    sleep 1
fi

echo "[*] Syncing clock with $DC_IP every 5s (Ctrl-C to stop)..."
while true; do
    ntpdate "$DC_IP" || rdate -n "$DC_IP"
    sleep 5
done
