#!/usr/bin/env bash
set -euo pipefail

# ============================================================
# EDIT THIS — add all in-scope targets (IPs, CIDRs)
# ============================================================
SCOPE=(
    # "10.10.10.1"
    # "10.10.10.0/24"
)

# Anthropic API — published at:
# https://platform.claude.com/docs/en/api/ip-addresses
# "These addresses will not change without notice."
ANTHROPIC_V4="160.79.104.0/23"
ANTHROPIC_V6="2607:6bc0::/48"

# DNS resolver (auto-detected from /etc/resolv.conf)
DNS_SERVER="$(grep -m1 '^nameserver' /etc/resolv.conf | awk '{print $2}')"
# ============================================================

if [ "$(id -u)" -ne 0 ]; then
    echo "[!] This script requires root. Run: sudo bash $0"
    exit 1
fi

if [ ${#SCOPE[@]} -eq 0 ]; then
    echo "[!] SCOPE array is empty. Edit this script first."
    exit 1
fi

# Flush existing redrun table if present (idempotent)
nft list tables 2>/dev/null | grep -q 'inet redrun' && nft delete table inet redrun

nft -f - <<EOF
table inet redrun {
    set scope {
        type ipv4_addr
        flags interval
    }
    set api4 {
        type ipv4_addr
        flags interval
        elements = { $ANTHROPIC_V4 }
    }
    set api6 {
        type ipv6_addr
        flags interval
        elements = { $ANTHROPIC_V6 }
    }

    chain output {
        type filter hook output priority 0; policy drop;

        # Loopback (MCP servers, listeners, local tools)
        oif lo accept

        # Established/related connections
        ct state established,related accept

        # DNS (to system resolver only)
        ip daddr $DNS_SERVER udp dport 53 accept
        ip daddr $DNS_SERVER tcp dport 53 accept

        # Anthropic API (Claude Code functionality)
        ip daddr @api4 accept
        ip6 daddr @api6 accept

        # In-scope targets
        ip daddr @scope accept

        # Log + drop everything else
        counter comment "redrun-dropped"
    }
}
EOF

# Populate scope set
for ip in "${SCOPE[@]}"; do
    nft add element inet redrun scope "{ $ip }"
done

echo "[+] Engagement firewall active"
echo "    Scope: ${SCOPE[*]}"
echo "    Anthropic: $ANTHROPIC_V4, $ANTHROPIC_V6"
echo "    DNS: $DNS_SERVER"
echo "    All other outbound traffic BLOCKED"
echo ""
echo "    Add targets:  sudo nft add element inet redrun scope '{ IP }'"
echo "    Edit & reload: sudo bash $0"
echo "    Teardown:      sudo bash $(dirname $0)/teardown.sh"
