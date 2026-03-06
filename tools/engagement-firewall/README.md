# Engagement Firewall

nftables firewall that restricts all outbound traffic to:

- **Anthropic API** (`160.79.104.0/23`, `2607:6bc0::/48`) — so Claude Code keeps working
- **In-scope targets** — IPs/CIDRs you define in the SCOPE array
- **DNS** — system resolver only (auto-detected from `/etc/resolv.conf`)
- **Loopback** — MCP servers, local listeners, tools

Everything else is dropped. This prevents accidental traffic to out-of-scope systems during an engagement.

## Prerequisites

- `nftables` installed (`apt install nftables` / `pacman -S nftables`)
- `sudo` access (nftables requires root)

## Usage

### 1. Edit the SCOPE array

Open `firewall.sh` and uncomment/add your in-scope targets:

```bash
SCOPE=(
    "10.10.10.5"
    "10.10.10.0/24"
)
```

### 2. Activate

```bash
sudo bash tools/engagement-firewall/firewall.sh
```

### 3. Add targets live (no restart needed)

```bash
sudo nft add element inet redrun scope '{ 10.10.10.20 }'
sudo nft add element inet redrun scope '{ 172.16.0.0/16 }'
```

### 4. Teardown

```bash
sudo bash tools/engagement-firewall/teardown.sh
```

This removes the `inet redrun` table entirely, restoring normal outbound traffic.

## Engagement modes

- **Pentest mode**: Required. Prevents accidental out-of-scope traffic.
- **CTF mode**: Optional. CTF targets are isolated by design, but the firewall adds an extra safety layer.

## Anthropic IP addresses

The allowed Anthropic API ranges are published at:
https://platform.claude.com/docs/en/api/ip-addresses

Per Anthropic: "These addresses will not change without notice."
