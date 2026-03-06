#!/usr/bin/env bash
nft delete table inet redrun 2>/dev/null \
    && echo "[+] Engagement firewall removed" \
    || echo "[=] No engagement firewall active"
