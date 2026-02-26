#!/bin/bash
# File: backend/vpnc-wrapper.sh

# 1. Execute original script to initialize tun0 and standard IP allocations
/usr/share/vpnc-scripts/vpnc-script-orig "$@"

# OpenConnect dynamically injects the lowercase $reason variable into the environment
# shellcheck disable=SC2154
if [[ "$reason" == "connect" ]]; then
    # 2. Prevent vpnc-script from overriding our container resolver
    echo "options ndots:0" >/etc/resolv.conf
    echo "nameserver 127.0.0.1" >>/etc/resolv.conf

    # 3. Detect VPN DNS Servers
    IFS=' ' read -ra VPN_DNS_SERVERS <<<"$INTERNAL_IP4_DNS"

    # 4. Smart Auto-Detect VPN Domains
    DOMAINS=()
    if [[ -n "$CISCO_DEF_DOMAIN" ]]; then DOMAINS+=("$CISCO_DEF_DOMAIN"); fi
    if [[ -n "$CISCO_SPLIT_DNS" ]]; then
        IFS=',' read -ra ADDR <<<"$CISCO_SPLIT_DNS"
        for i in "${ADDR[@]}"; do DOMAINS+=("$i"); done
    fi

    # Fallback: Parse the raw client log to catch GlobalProtect-specific XML split-domains that
    # OpenConnect marks as "Unknown" and fails to export to standard env variables.
    if grep -q "<include-split-tunneling-domain>" /tmp/gp-logs/gp-client.log 2>/dev/null; then
        EXTRA_DOMAINS=$(awk '/<include-split-tunneling-domain>:/ {flag=1; next} /</ {flag=0} flag {print}' /tmp/gp-logs/gp-client.log | tr -d '\t\r ' | sed 's/^[*.]*//')
        for d in $EXTRA_DOMAINS; do
            if [[ -n "$d" ]]; then DOMAINS+=("$d"); fi
        done
    fi

    # Manual Override support
    if [[ -n "$VPN_DOMAINS" ]]; then
        IFS=',' read -ra ADDR <<<"$VPN_DOMAINS"
        for i in "${ADDR[@]}"; do DOMAINS+=("$i"); done
    fi

    mapfile -t UNIQUE_DOMAINS < <(printf "%s\n" "${DOMAINS[@]}" | sort -u | grep -v "^$")

    # 5. Dynamically configure Split-DNS
    rm -f /etc/dnsmasq.d/vpn.conf
    if [[ ${#UNIQUE_DOMAINS[@]} -gt 0 && ${#VPN_DNS_SERVERS[@]} -gt 0 ]]; then
        PRIMARY_VPN_DNS="${VPN_DNS_SERVERS[0]}"
        for d in "${UNIQUE_DOMAINS[@]}"; do
            # Validate domain to prevent dnsmasq config corruption (allow letters, numbers, hyphens, and dots)
            if [[ ! "$d" =~ ^[\.a-zA-Z0-9-]+$ ]]; then
                echo "[vpnc-wrapper] Skipping invalid split-domain value: $d" >>/tmp/gp-logs/gp-service.log
                continue
            fi
            echo "server=/$d/$PRIMARY_VPN_DNS" >>/etc/dnsmasq.d/vpn.conf
            echo "ipset=/$d/vpn_domains" >>/etc/dnsmasq.d/vpn.conf
        done
        echo "[vpnc-wrapper] Auto-Detected Split-DNS configured for: ${UNIQUE_DOMAINS[*]} -> $PRIMARY_VPN_DNS" >>/tmp/gp-logs/gp-service.log
        pkill -HUP dnsmasq || true
    fi

    # 6. Smart Split Routing Implementation
    if [[ "$SPLIT_TUNNEL" == "true" ]]; then
        echo "[vpnc-wrapper] Enforcing Split-Tunnel: Stripping default route (0.0.0.0/0) from tun0" >>/tmp/gp-logs/gp-service.log
        ip route del default dev tun0 2>/dev/null || true
    fi

    # Note: Standard vpnc-script already auto-routes CISCO_SPLIT_INC_... subnets provided by the VPN.
    # We only need to add manual overrides if the user provided them.
    if [[ -n "$VPN_SUBNETS" ]]; then
        IFS=',' read -ra SUBNETS <<<"$VPN_SUBNETS"
        for sub in "${SUBNETS[@]}"; do
            sub="$(echo "$sub" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
            [[ -z "$sub" ]] && continue
            ip route add "$sub" dev tun0 2>/dev/null || true
            echo "[vpnc-wrapper] Added explicit manual split route: $sub -> tun0" >>/tmp/gp-logs/gp-service.log
        done
    fi

    # 7. Enable IPSet routing for dynamic domains so resolved targets bypass the local network
    if ipset list vpn_domains >/dev/null 2>&1; then
        echo "[vpnc-wrapper] Enabling dynamic policy routing for auto-detected VPN domains" >>/tmp/gp-logs/gp-service.log

        # Make rules idempotent
        ip rule show | grep -q "fwmark 0x10 lookup 100" || ip rule add fwmark 0x10 lookup 100 2>/dev/null || true
        ip route replace default dev tun0 table 100 2>/dev/null || true

        iptables -t mangle -C OUTPUT -m set --match-set vpn_domains dst -j MARK --set-mark 0x10 2>/dev/null ||
            iptables -t mangle -A OUTPUT -m set --match-set vpn_domains dst -j MARK --set-mark 0x10 2>/dev/null || true

        iptables -t mangle -C PREROUTING -m set --match-set vpn_domains dst -j MARK --set-mark 0x10 2>/dev/null ||
            iptables -t mangle -A PREROUTING -m set --match-set vpn_domains dst -j MARK --set-mark 0x10 2>/dev/null || true
    fi

elif [[ "$reason" == "disconnect" ]]; then
    rm -f /etc/dnsmasq.d/vpn.conf
    pkill -HUP dnsmasq || true

    # Safely clear dynamic policy routing to prevent state-bloat on rapid disconnects
    iptables -t mangle -D OUTPUT -m set --match-set vpn_domains dst -j MARK --set-mark 0x10 2>/dev/null || true
    iptables -t mangle -D PREROUTING -m set --match-set vpn_domains dst -j MARK --set-mark 0x10 2>/dev/null || true
    ip rule del fwmark 0x10 lookup 100 2>/dev/null || true
    ip route flush table 100 2>/dev/null || true

    ipset flush vpn_domains 2>/dev/null || true
fi
