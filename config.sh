#!/usr/bin/env bash
# Pre-engagement configuration wizard.
# Writes engagement/config.yaml so the orchestrator skips its built-in wizard.
# Run before ./run.sh to pre-configure scan type, proxy, spray, cracking, and C2.
set -euo pipefail
cd "$(dirname "$0")"

CONFIG="engagement/config.yaml"
TEMPLATE="operator/templates/config.yaml"

if [[ -f "$CONFIG" ]]; then
    echo "Config already exists: $CONFIG"
    read -rp "Overwrite? [y/N] " ow
    [[ "${ow,,}" == "y" ]] || { echo "Keeping existing config."; exit 0; }
fi

mkdir -p engagement

echo ""
echo "=== red-run engagement setup ==="
echo ""

# --- Q1: Scan type ---
echo "Q1 — Default network scan type"
echo "  1) quick  (top 1000 ports)"
echo "  2) full   (all 65535 ports)"
read -rp "  Choice [1]: " q1
case "${q1:-1}" in
    2) scan_type="full" ;;
    *) scan_type="quick" ;;
esac

# --- Q2: Web proxy ---
echo ""
echo "Q2 — Web proxy for HTTP traffic"
echo "  1) Burp 127.0.0.1:8080 (recommended)"
echo "  2) Custom URL"
echo "  3) No proxy"
read -rp "  Choice [1]: " q2
case "${q2:-1}" in
    2) read -rp "  Proxy URL (e.g., http://10.0.0.1:8080): " proxy_url
       proxy_enabled="true" ;;
    3) proxy_enabled="false"; proxy_url="" ;;
    *) proxy_enabled="true"; proxy_url="http://127.0.0.1:8080" ;;
esac

# --- Q3: Spray tier ---
echo ""
echo "Q3 — Password spray default tier"
echo "  1) light   (~30 passwords)"
echo "  2) medium  (~10k passwords)"
echo "  3) heavy   (~100k passwords)"
echo "  4) skip    (no spraying)"
read -rp "  Choice [1]: " q3
case "${q3:-1}" in
    2) spray_tier="medium" ;;
    3) spray_tier="heavy" ;;
    4) spray_tier="skip" ;;
    *) spray_tier="light" ;;
esac

# --- Q4: Hash recovery ---
echo ""
echo "Q4 — Hash recovery method"
echo "  1) local    (hashcat/john on this machine)"
echo "  2) export   (save hashes for external rig)"
echo "  3) skip     (no recovery)"
read -rp "  Choice [1]: " q4
case "${q4:-1}" in
    2) cracking_method="export" ;;
    3) cracking_method="skip" ;;
    *) cracking_method="local" ;;
esac

# --- Q5: Shell backend ---
echo ""
echo "Q5 — Shell backend"
echo "  1) shell-server  (raw TCP/PTY, always available)"
if command -v sliver-server &>/dev/null || command -v sliver &>/dev/null; then
    echo "  2) sliver        (Sliver C2 — detected)"
    has_sliver=1
else
    echo "  2) sliver        (not installed)"
    has_sliver=0
fi
echo "  3) custom        (your own C2 + MCP server)"
read -rp "  Choice [1]: " q5

shell_backend="shell-server"
sliver_config=""
custom_mcp=""
custom_ref=""

case "${q5:-1}" in
    2)
        if [[ "$has_sliver" -eq 0 ]]; then
            echo "  Sliver not detected. Install sliver-server first."
            echo "  Falling back to shell-server."
        else
            shell_backend="sliver"
            default_cfg="engagement/sliver.cfg"
            echo ""
            # Unpack Sliver assets (Go toolchain, implant templates) on first run
            if [[ ! -d "${HOME}/.sliver" ]] || [[ ! -d "${HOME}/.sliver/go" ]]; then
                echo "  Unpacking Sliver assets (first run, may take a moment)..."
                sliver-server unpack --force 2>/dev/null
            fi
            echo "  Sliver operator config setup:"
            if [[ -f "$default_cfg" ]]; then
                echo "  Found existing config: $default_cfg"
                read -rp "  Use this config? [Y/n] " use_existing
                if [[ "${use_existing,,}" != "n" ]]; then
                    sliver_config="$default_cfg"
                fi
            fi
            if [[ -z "$sliver_config" ]]; then
                echo "  Generating operator config..."
                rm -f "$default_cfg"
                if sliver-server operator --name red-run --lhost 127.0.0.1 --permissions all --save "$default_cfg" 2>/dev/null; then
                    sliver_config="$default_cfg"
                    echo "  Config saved to $default_cfg"
                    # Restart daemon so new mTLS certs take effect
                    echo "  Restarting Sliver daemon for new config..."
                    pkill -f "sliver-server daemon" 2>/dev/null
                    sleep 2
                    sliver-server daemon &>/dev/null &
                    sleep 2
                    # Import config into sliver client
                    if command -v sliver &>/dev/null; then
                        sliver import "$default_cfg" 2>/dev/null
                    fi
                else
                    echo "  Failed to generate config. Is sliver-server running?"
                    echo "  Start it with: sliver-server daemon &"
                    echo "  Then re-run this setup."
                    echo "  Falling back to shell-server."
                    shell_backend="shell-server"
                fi
            fi
            # Pre-compile implant cache
            if [[ "$shell_backend" == "sliver" ]] && command -v sliver &>/dev/null; then
                echo ""
                echo "  Pre-compile implant cache?"
                echo "  Skipping means waiting 1-3 minutes per OS/arch on first use during an engagement."
                echo "  1) Yes — select architectures to pre-compile"
                echo "  2) No  — compile on demand"
                read -rp "  Choice [1]: " pre_choice
                if [[ "${pre_choice:-1}" == "1" ]]; then
                    # Show available targets with cache status
                    echo ""
                    echo "  Select targets to pre-compile (comma-separated, e.g., 1,2):"
                    has_cache() { find "${HOME}/.sliver/slivers/$1/$2" -path '*/bin/*' -type f 2>/dev/null | grep -q .; }
                    targets=("linux/amd64" "windows/amd64" "linux/arm64" "windows/arm64")
                    labels=("Linux x86_64 (servers, containers)" "Windows x86_64 (most Windows targets)" "Linux ARM64 (cloud, IoT)" "Windows ARM64 (Surface, ARM VMs)")
                    for i in "${!targets[@]}"; do
                        IFS='/' read -r t_os t_arch <<< "${targets[$i]}"
                        if has_cache "$t_os" "$t_arch"; then
                            echo "    $((i+1))) ${targets[$i]} — ${labels[$i]} [cached]"
                        else
                            echo "    $((i+1))) ${targets[$i]} — ${labels[$i]}"
                        fi
                    done
                    read -rp "  Targets [1,2]: " target_sel
                    target_sel="${target_sel:-1,2}"

                    # Parse selection
                    build_list=()
                    IFS=',' read -ra selections <<< "$target_sel"
                    for sel in "${selections[@]}"; do
                        sel="${sel// /}"
                        idx=$((sel - 1))
                        if [[ $idx -ge 0 && $idx -lt ${#targets[@]} ]]; then
                            IFS='/' read -r t_os t_arch <<< "${targets[$idx]}"
                            if ! has_cache "$t_os" "$t_arch"; then
                                build_list+=("${targets[$idx]}")
                            else
                                echo "  ${targets[$idx]} already cached, skipping"
                            fi
                        fi
                    done

                    if [[ ${#build_list[@]} -gt 0 ]]; then
                        echo ""
                        echo "  Building ${#build_list[@]} target(s)..."
                        for target in "${build_list[@]}"; do
                            IFS='/' read -r t_os t_arch <<< "$target"
                            rc=$(mktemp)
                            out=$(mktemp)
                            printf "generate --mtls 127.0.0.1:4444 --os %s --arch %s --skip-symbols --save %s\nexit\n" "$t_os" "$t_arch" "$out" > "$rc"
                            timeout 600 sliver console --rc "$rc" &>/dev/null &
                            build_pid=$!
                            seconds=0
                            while kill -0 "$build_pid" 2>/dev/null; do
                                sleep 1
                                seconds=$((seconds + 1))
                                printf "\r  Building ${target}... %ds " "$seconds"
                            done
                            wait "$build_pid" 2>/dev/null
                            if [[ -f "$out" && -s "$out" ]]; then
                                printf "\r  Building ${target}... done (%ds, %s)\n" "$seconds" "$(du -h "$out" | cut -f1)"
                            else
                                printf "\r  Building ${target}... failed (%ds, non-critical)\n" "$seconds"
                            fi
                            rm -f "$rc" "$out"
                        done
                    else
                        echo "  All selected targets already cached."
                    fi
                fi
            fi
        fi
        ;;
    3)
        shell_backend="custom"
        read -rp "  MCP server name (as registered in .mcp.json): " custom_mcp
        read -rp "  Reference doc path (markdown): " custom_ref
        if [[ -n "$custom_ref" && ! -f "$custom_ref" ]]; then
            echo "  Warning: $custom_ref not found. shell-mgr will need it at runtime."
        fi
        ;;
esac

# --- Write config ---
cat > "$CONFIG" << YAML
# red-run engagement configuration
# Generated by config.sh. Edit at any time.

scan_type: ${scan_type}
YAML

if [[ "$proxy_enabled" == "true" ]]; then
    cat >> "$CONFIG" << YAML

web_proxy:
  enabled: true
  url: "${proxy_url}"
YAML
fi

cat >> "$CONFIG" << YAML

spray:
  default_tier: ${spray_tier}

cracking:
  default_method: ${cracking_method}

shell:
  backend: ${shell_backend}
YAML

if [[ "$shell_backend" == "sliver" && -n "$sliver_config" ]]; then
    echo "  sliver_config: \"${sliver_config}\"" >> "$CONFIG"
fi

if [[ "$shell_backend" == "custom" ]]; then
    [[ -n "$custom_mcp" ]] && echo "  custom_mcp: \"${custom_mcp}\"" >> "$CONFIG"
    [[ -n "$custom_ref" ]] && echo "  custom_ref: \"${custom_ref}\"" >> "$CONFIG"
fi

# --- Patch .mcp.json for C2 backends ---
MCP_JSON=".mcp.json"
if [[ "$shell_backend" == "sliver" && -f "$MCP_JSON" ]]; then
    if ! grep -q '"sliver-server"' "$MCP_JSON"; then
        echo ""
        echo "Adding sliver-server to .mcp.json..."
        # Insert sliver-server SSE entry after shell-server
        python3 -c "
import json, sys
with open('$MCP_JSON') as f:
    cfg = json.load(f)
cfg['mcpServers']['sliver-server'] = {'type': 'sse', 'url': 'http://127.0.0.1:8023/sse'}
with open('$MCP_JSON', 'w') as f:
    json.dump(cfg, f, indent=2)
    f.write('\n')
print('  sliver-server added to .mcp.json')
" 2>&1
        echo "  Note: restart Claude Code session for MCP changes to take effect."
    else
        echo "  sliver-server already in .mcp.json"
    fi
fi

echo ""
echo "Config written to $CONFIG"
echo "Run ./run.sh to start the engagement."
