#!/usr/bin/env bash
set -euo pipefail
# Add target hostnames to /etc/hosts
# Copy to engagement dir, fill in TARGET_IP and entries, run with sudo.

TARGET_IP="FILL_IN"

entries=(
    "$TARGET_IP  FILL_IN_HOSTNAME"
)

for entry in "${entries[@]}"; do
    hostname=$(echo "$entry" | awk '{print $2}')
    if grep -qP "\\b${hostname}\\b" /etc/hosts 2>/dev/null; then
        echo "[=] Already in /etc/hosts: $hostname"
    else
        echo "$entry" | sudo tee -a /etc/hosts
        echo "[+] Added: $entry"
    fi
done

echo ""
echo "Verification:"
for entry in "${entries[@]}"; do
    hostname=$(echo "$entry" | awk '{print $2}')
    if getent hosts "$hostname" > /dev/null 2>&1; then
        echo "[OK] $hostname -> $(getent hosts "$hostname" | awk '{print $1}')"
    else
        echo "[FAIL] $hostname does not resolve"
        exit 1
    fi
done
