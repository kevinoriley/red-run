#!/usr/bin/env bash
if [ "$(id -u)" -ne 0 ]; then
    echo "[!] This script requires root. Run: sudo bash $0"
    exit 1
fi

nft delete table inet redrun 2>/dev/null \
    && echo "[+] Engagement firewall removed" \
    || echo "[=] No engagement firewall active"
