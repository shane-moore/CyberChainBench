#!/bin/bash
# Network whitelist for CyberChainBench containers.
# Only allows outbound HTTP/HTTPS to RPC endpoints and block explorers.
# Must run as root with NET_ADMIN capability.
set -euo pipefail

# Allowed domains (resolved to IPs at container start)
ALLOWED_DOMAINS=(
    # Etherscan and block explorers
    api.etherscan.io
    api-goerli.etherscan.io
    api.bscscan.com
    api.polygonscan.com
    api.arbiscan.io
    api-optimistic.etherscan.io
    api.basescan.org
    api.snowtrace.io
    api.ftmscan.com
    api.gnosisscan.io
    api.blastscan.io
    api.mantlescan.xyz
    api.lineascan.build
    # Alchemy RPC
    eth-mainnet.g.alchemy.com
    bsc-mainnet.g.alchemy.com
    polygon-mainnet.g.alchemy.com
    arb-mainnet.g.alchemy.com
    opt-mainnet.g.alchemy.com
    base-mainnet.g.alchemy.com
    # Infura RPC
    mainnet.infura.io
    # QuickNode (wildcard not possible, add specific endpoints as needed)
    # LLM API endpoints
    api.anthropic.com
    api.openai.com
    api.example.com
)

echo "[network_whitelist] Resolving allowed domains..."

# Flush existing OUTPUT rules
iptables -F OUTPUT 2>/dev/null || true

# Allow loopback
iptables -A OUTPUT -o lo -j ACCEPT

# Allow DNS (needed to resolve domains)
iptables -A OUTPUT -p udp --dport 53 -j ACCEPT
iptables -A OUTPUT -p tcp --dport 53 -j ACCEPT

# Allow established connections
iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Resolve each domain and allow its IPs
for domain in "${ALLOWED_DOMAINS[@]}"; do
    ips=$(getent hosts "$domain" 2>/dev/null | awk '{print $1}' | sort -u)
    if [ -z "$ips" ]; then
        echo "  WARNING: could not resolve $domain"
        continue
    fi
    for ip in $ips; do
        iptables -A OUTPUT -d "$ip" -p tcp --dport 443 -j ACCEPT
        iptables -A OUTPUT -d "$ip" -p tcp --dport 80 -j ACCEPT
    done
    echo "  $domain -> $(echo $ips | tr '\n' ' ')"
done

# Also allow any RPC URLs from environment (in case they use custom endpoints)
for var in ETH_RPC_URL BSC_RPC_URL POLYGON_RPC_URL ARBITRUM_RPC_URL OPTIMISM_RPC_URL \
           BASE_RPC_URL AVALANCHE_RPC_URL FANTOM_RPC_URL GNOSIS_RPC_URL BLAST_RPC_URL \
           MOONRIVER_RPC_URL LINEA_RPC_URL MANTLE_RPC_URL SEI_RPC_URL \
           BSC_TRACE_RPC_URL ETH_TRACE_RPC_URL POLYGON_TRACE_RPC_URL \
           ARBITRUM_TRACE_RPC_URL OPTIMISM_TRACE_RPC_URL BASE_TRACE_RPC_URL \
           FANTOM_TRACE_RPC_URL; do
    url="${!var:-}"
    if [ -n "$url" ]; then
        # Extract hostname from URL
        host=$(echo "$url" | sed -E 's|^https?://||' | cut -d/ -f1 | cut -d: -f1)
        ips=$(getent hosts "$host" 2>/dev/null | awk '{print $1}' | sort -u)
        for ip in $ips; do
            iptables -A OUTPUT -d "$ip" -p tcp --dport 443 -j ACCEPT
            iptables -A OUTPUT -d "$ip" -p tcp --dport 80 -j ACCEPT
        done
        if [ -n "$ips" ]; then
            echo "  $var ($host) -> $(echo $ips | tr '\n' ' ')"
        fi
    fi
done

# Drop everything else
iptables -A OUTPUT -p tcp --dport 80 -j DROP
iptables -A OUTPUT -p tcp --dport 443 -j DROP

echo "[network_whitelist] Done. Only whitelisted domains accessible."
