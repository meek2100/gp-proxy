#!/bin/bash
# File: backend/vpnc-wrapper.sh

# 1. Execute original script to initialize tun0 and standard IP allocations
/usr/share/vpnc-scripts/vpnc-script-orig "$@"

# Single Source of Truth: Prefer environment variables exported by entrypoint.sh
: "${SERVICE_LOG:=/tmp/gp-logs/gp-service.log}"
: "${CLIENT_LOG:=/tmp/gp-logs/gp-client.log}"

# OpenConnect dynamically injects the lowercase $reason variable into the environment
# shellcheck disable=SC2154
if [[ "$reason" == "connect" ]]; then
    # 2. Prevent vpnc-script from overriding our container resolver
    echo "nameserver 127.0.0.1" >/etc/resolv.conf

    # 3. Detect VPN DNS Servers
    IFS=' ' read -ra VPN_DNS_SERVERS <<<"$INTERNAL_IP4_DNS"

    # 4. Smart Auto-Detect VPN Domains
    DOMAINS=()

    # Handle both comma-separated and space-separated payloads robustly
    if [[ -n "$CISCO_DEF_DOMAIN" ]]; then
        for i in ${CISCO_DEF_DOMAIN//,/ }; do DOMAINS+=("$i"); done
    fi

    if [[ -n "$CISCO_SPLIT_DNS" ]]; then
        for i in ${CISCO_SPLIT_DNS//,/ }; do DOMAINS+=("$i"); done
    fi

    # Fallback: Parse the raw client log to catch GlobalProtect-specific XML split-domains that
    # 4. Refine Domain Extraction and Sanitization (V5)
    # Strip ANSI codes, extract XML content, filter out log metadata, and sanitize.
    # We use a robust pipeline to handle log-prefixes and noise.
    GP_LOG_DOMAINS=$(sed 's/\x1b\[[0-9;]*m//g' "$CLIENT_LOG" |
        awk '/include-split-tunneling-domain/,/<\/include-split-tunneling-domain>/' |
        sed 's/<[^>]*>//g' |
        tr -s '[:space:]' '\n' |
        grep '\.' |
        grep -vE '\[|\]|INFO|DEBUG|WARN|ERROR|Mar|202[4-9]|HTTP' |
        sed 's/^\*//; s/^\.//' |
        sort -u |
        tr '\n' ' ')

    # Collect ALL potential domains from logs, split-dns, and search domains
    # Aggressively strip leading '*', '.', and trailing whitespace.
    mapfile -t UNIQUE_DOMAINS < <(echo "$GP_LOG_DOMAINS" "$CISCO_DEF_DOMAIN" "$CISCO_SPLIT_DNS" | sed 's/[,[:space:]]/\n/g' | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' -e 's/^\*[.]*//' -e 's/^\.//' | sort -u | grep -v '^$')

    if [[ ${#UNIQUE_DOMAINS[@]} -gt 0 ]]; then
        echo "[vpnc-wrapper] Extraction Success. Resolved VPN Domains: ${UNIQUE_DOMAINS[*]}" >>"$SERVICE_LOG"
    fi

    # 5. Dynamically configure Split-DNS (High Priority)
    rm -f /etc/dnsmasq.d/10-vpn.conf
    if [[ ${#VPN_DNS_SERVERS[@]} -gt 0 ]]; then
        # Ensure we can reach these DNS servers with the correct source IP (tun0 IP)
        # Internal DNS servers often reject queries from local 192.168.x.x IPs.
        TUN0_IP=$(ip -4 addr show tun0 | awk '/inet / {print $2}' | cut -d/ -f1)

        # If full-tunnel is active, set all VPN DNS servers as catch-all upstreams in the high-priority file
        if [[ "$SPLIT_TUNNEL" != "true" ]]; then
            for ip in "${VPN_DNS_SERVERS[@]}"; do
                echo "server=$ip" >>/etc/dnsmasq.d/10-vpn.conf
                # Force source IP for DNS queries to this upstream
                ip route replace "$ip" dev tun0 src "$TUN0_IP" 2>/dev/null || true
            done
            echo "[vpnc-wrapper] Full-Tunnel DNS upstreams configured (Priority 10): ${VPN_DNS_SERVERS[*]}" >>"$SERVICE_LOG"
        fi

        if [[ ${#UNIQUE_DOMAINS[@]} -gt 0 ]]; then
            for d in "${UNIQUE_DOMAINS[@]}"; do
                # Validate domain to prevent dnsmasq config corruption (allow letters, numbers, hyphens, and dots)
                if [[ ! "$d" =~ ^[\.a-zA-Z0-9-]+$ ]]; then
                    echo "[vpnc-wrapper] Skipping invalid split-domain value: $d" >>"$SERVICE_LOG"
                    continue
                fi
                for ip in "${VPN_DNS_SERVERS[@]}"; do
                    echo "server=/$d/$ip" >>/etc/dnsmasq.d/10-vpn.conf
                    # Ensure route to DNS exists with correct source
                    ip route replace "$ip" dev tun0 src "$TUN0_IP" 2>/dev/null || true
                done
                echo "ipset=/$d/vpn_domains" >>/etc/dnsmasq.d/10-vpn.conf
            done
            echo "[vpnc-wrapper] Auto-Detected Split-DNS configured for domains: ${UNIQUE_DOMAINS[*]} -> ${VPN_DNS_SERVERS[*]}" >>"$SERVICE_LOG"
        fi
        # Restart dnsmasq to apply /etc/dnsmasq.d/ changes (SIGHUP is insufficient for directory configs)
        pkill dnsmasq || true
        # Restart with the same settings as entrypoint.sh (verbose logging if enabled)
        LOG_FLAGS=""
        [[ "$LOG_LEVEL" == "DEBUG" || "$LOG_LEVEL" == "TRACE" ]] && LOG_FLAGS="--log-queries --log-facility=-"
        # shellcheck disable=SC2086
        dnsmasq --conf-file=/etc/dnsmasq.conf $LOG_FLAGS >>"$SERVICE_LOG" 2>&1 &

    fi

    # 6. Smart Split Routing Implementation
    if [[ "$SPLIT_TUNNEL" == "true" ]]; then
        echo "[vpnc-wrapper] Enforcing Split-Tunnel: Stripping default route (0.0.0.0/0) from tun0" >>"$SERVICE_LOG"
        ip route del default dev tun0 2>/dev/null || true
        # OpenConnect often installs 0.0.0.0/1 and 128.0.0.0/1 to override the default route without deleting it
        ip route del 0.0.0.0/1 dev tun0 2>/dev/null || true
        ip route del 128.0.0.0/1 dev tun0 2>/dev/null || true
    else
        # Enforce Full-Tunnel: Ensure the default route points to tun0
        # vpnc-script-orig usually handles this, but we force it here to be certain in macvlan/bridge mixed environments
        echo "[vpnc-wrapper] Enforcing Full-Tunnel: Ensuring default route points to tun0" >>"$SERVICE_LOG"
        ip route replace default dev tun0 2>/dev/null || true
    fi

    # Note: Standard vpnc-script already auto-routes CISCO_SPLIT_INC_... subnets provided by the VPN.
    # We only need to add manual overrides if the user provided them.
    if [[ -n "$VPN_SUBNETS" ]]; then
        IFS=',' read -ra SUBNETS <<<"$VPN_SUBNETS"
        for sub in "${SUBNETS[@]}"; do
            sub="$(echo "$sub" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
            [[ -z "$sub" ]] && continue
            ip route add "$sub" dev tun0 2>/dev/null || true
            echo "[vpnc-wrapper] Added explicit manual split route: $sub -> tun0" >>"$SERVICE_LOG"
        done
    fi

    # 7. Enable IPSet routing for dynamic domains so resolved targets bypass the local network
    if ipset list vpn_domains >/dev/null 2>&1; then
        echo "[vpnc-wrapper] Enabling dynamic policy routing for auto-detected VPN domains" >>"$SERVICE_LOG"

        # Make rules idempotent
        ip rule show | grep -q "fwmark 0x10 lookup 100" || ip rule add fwmark 0x10 lookup 100 2>/dev/null || true
        ip route replace default dev tun0 table 100 2>/dev/null || true

        iptables -t mangle -C OUTPUT -m set --match-set vpn_domains dst -j MARK --set-mark 0x10 2>/dev/null ||
            iptables -t mangle -A OUTPUT -m set --match-set vpn_domains dst -j MARK --set-mark 0x10 2>/dev/null || true

        iptables -t mangle -C PREROUTING -m set --match-set vpn_domains dst -j MARK --set-mark 0x10 2>/dev/null ||
            iptables -t mangle -A PREROUTING -m set --match-set vpn_domains dst -j MARK --set-mark 0x10 2>/dev/null || true
    fi

elif [[ "$reason" == "disconnect" ]]; then
    rm -f /etc/dnsmasq.d/10-vpn.conf
    # Reload dnsmasq configuration (restart is safer to ensure cleanup)
    pkill dnsmasq || true
    LOG_FLAGS=""
    [[ "$LOG_LEVEL" == "DEBUG" || "$LOG_LEVEL" == "TRACE" ]] && LOG_FLAGS="--log-queries --log-facility=-"
    # shellcheck disable=SC2086
    dnsmasq --conf-file=/etc/dnsmasq.conf $LOG_FLAGS >>"$SERVICE_LOG" 2>&1 &

    # Safely clear dynamic policy routing to prevent state-bloat on rapid disconnects
    iptables -t mangle -D OUTPUT -m set --match-set vpn_domains dst -j MARK --set-mark 0x10 2>/dev/null || true
    iptables -t mangle -D PREROUTING -m set --match-set vpn_domains dst -j MARK --set-mark 0x10 2>/dev/null || true
    ip rule del fwmark 0x10 lookup 100 2>/dev/null || true
    ip route flush table 100 2>/dev/null || true

    ipset flush vpn_domains 2>/dev/null || true
fi
