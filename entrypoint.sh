#!/bin/bash
# File: entrypoint.sh
set -e

# --- FIX: Ensure administrative commands (ip, iptables, ipset) are in PATH ---
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH"

# ==============================================================================
# 1. ROBUST CONFIGURATION PARSING
# ==============================================================================

# Helper: Find env var value case-insensitively
get_env_value() {
    local val=""
    for key in "$@"; do
        if [[ -n "${!key}" ]]; then
            val="${!key}"
            break
        fi
        local match_line
        match_line=$(env | grep -i "^${key}=" | head -n 1)
        if [[ -n "$match_line" ]]; then
            val="${match_line#*=}"
            break
        fi
    done
    echo "$val"
}

# Helper: Strip quotes and trim whitespace safely without collapsing internal spaces
clean_val() {
    local val="$1"
    # Remove all single and double quotes
    val="${val//[\"\']/}"
    # Safely trim leading and trailing spaces only
    echo "$val" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//'
}

# Helper: Strip outer quotes and trim leading/trailing whitespace ONLY
# Preserves inner quotes and spaces required for 'eval' parsing and authentication secrets.
clean_val_preserve_inner() {
    local val="$1"
    # Repeatedly strip matching outer quote pairs (" or ') in a loop
    while [[ ${#val} -ge 2 ]] && { [[ "${val:0:1}" == '"' && "${val: -1}" == '"' ]] || [[ "${val:0:1}" == "'" && "${val: -1}" == "'" ]]; }; do
        val="${val:1:-1}"
    done
    echo "$val" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//'
}

# --- Resolve & Normalize Variables ---

# 1. LOG_LEVEL
RAW_LOG_LEVEL=$(get_env_value "LOG_LEVEL" "log_level")
CLEAN_LOG_LEVEL=$(clean_val "$RAW_LOG_LEVEL")
LOG_LEVEL="${CLEAN_LOG_LEVEL^^}"
[[ -z "$LOG_LEVEL" ]] && LOG_LEVEL="INFO"
export LOG_LEVEL

# 2. VPN_MODE
RAW_VPN_MODE=$(get_env_value "VPN_MODE" "vpn_mode")
CLEAN_VPN_MODE=$(clean_val "$RAW_VPN_MODE")
VPN_MODE="${CLEAN_VPN_MODE,,}"
[[ -z "$VPN_MODE" ]] && VPN_MODE="standard"
export VPN_MODE

# 3. VPN_PORTAL (Required)
RAW_VPN_PORTAL=$(get_env_value "VPN_PORTAL" "vpn_portal")
VPN_PORTAL=$(clean_val "$RAW_VPN_PORTAL")
export VPN_PORTAL

# 4. VPN_GATEWAY (Optional)
RAW_VPN_GATEWAY=$(get_env_value "VPN_GATEWAY" "vpn_gateway" "gateway")
VPN_GATEWAY=$(clean_val "$RAW_VPN_GATEWAY")
export VPN_GATEWAY

# 5. DNS_SERVERS
RAW_DNS=$(get_env_value "DNS_SERVERS" "dns_servers" "VPN_DNS" "vpn_dns")
CLEAN_DNS=$(clean_val "$RAW_DNS")
# Translate commas to spaces natively before stripping edge whitespace
CLEAN_DNS="${CLEAN_DNS//,/ }"
DNS_SERVERS=$(echo "$CLEAN_DNS" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')
export DNS_SERVERS

# 6. GP_ARGS (Custom)
RAW_GP_ARGS=$(get_env_value "GP_ARGS" "gp_args")
GP_ARGS=$(clean_val_preserve_inner "$RAW_GP_ARGS")
export GP_ARGS

# 7. TIMEZONE
RAW_TZ=$(get_env_value "TZ" "tz" "timezone")
CLEAN_TZ=$(clean_val "$RAW_TZ")
TZ="${CLEAN_TZ:-UTC}"
export TZ

# 8. PUID/PGID
RAW_PUID=$(get_env_value "PUID" "puid")
PUID=$(clean_val "$RAW_PUID")
export PUID

RAW_PGID=$(get_env_value "PGID" "pgid")
PGID=$(clean_val "$RAW_PGID")
export PGID

# --- NEW: Advanced GP Options ---

# 9. HIP Report (--hip)
RAW_HIP=$(get_env_value "VPN_HIP_REPORT" "hip_report" "HIP")
CLEAN_HIP=$(clean_val "$RAW_HIP")
if [[ "${CLEAN_HIP,,}" == "true" || "${CLEAN_HIP}" == "1" ]]; then
    VPN_HIP_REPORT="true"
else
    VPN_HIP_REPORT="false"
fi
export VPN_HIP_REPORT

# 10. Client OS (--os)
RAW_OS=$(get_env_value "VPN_OS" "os")
VPN_OS=$(clean_val "$RAW_OS")
export VPN_OS

# 11. Client OS Version (--os-version)
RAW_OS_VER=$(get_env_value "VPN_OS_VERSION" "os_version")
VPN_OS_VERSION=$(clean_val "$RAW_OS_VER")
export VPN_OS_VERSION

# 12. Client Version (--client-version)
RAW_CLIENT_VER=$(get_env_value "VPN_CLIENT_VERSION" "client_version")
VPN_CLIENT_VERSION=$(clean_val "$RAW_CLIENT_VER")
export VPN_CLIENT_VERSION

# 13. No DTLS (--no-dtls)
RAW_DTLS=$(get_env_value "VPN_NO_DTLS" "no_dtls")
CLEAN_DTLS=$(clean_val "$RAW_DTLS")
if [[ "${CLEAN_DTLS,,}" == "true" || "${CLEAN_DTLS}" == "1" ]]; then
    VPN_NO_DTLS="true"
else
    VPN_NO_DTLS="false"
fi
export VPN_NO_DTLS

# 14. Disable IPv6 (--disable-ipv6)
RAW_IPV6=$(get_env_value "VPN_DISABLE_IPV6" "disable_ipv6")
CLEAN_IPV6=$(clean_val "$RAW_IPV6")
if [[ "${CLEAN_IPV6,,}" == "true" || "${CLEAN_IPV6}" == "1" ]]; then
    VPN_DISABLE_IPV6="true"
else
    VPN_DISABLE_IPV6="false"
fi
export VPN_DISABLE_IPV6

# 15. Allowed Subnets
RAW_SUBNETS=$(get_env_value "ALLOWED_SUBNETS" "allowed_subnets")
ALLOWED_SUBNETS=$(clean_val "$RAW_SUBNETS")
export ALLOWED_SUBNETS

# 16. Proxy Auth
RAW_PROXY_AUTH=$(get_env_value "PROXY_AUTH" "proxy_auth")
PROXY_AUTH=$(clean_val_preserve_inner "$RAW_PROXY_AUTH")
export PROXY_AUTH

# 17. Shadowsocks Auth
RAW_SS_AUTH=$(get_env_value "SS_AUTH" "ss_auth")
SS_AUTH=$(clean_val_preserve_inner "$RAW_SS_AUTH")
export SS_AUTH

# 18. API Token (Optional Legacy Override)
RAW_API_TOKEN=$(get_env_value "API_TOKEN" "api_token")
API_TOKEN=$(clean_val_preserve_inner "$RAW_API_TOKEN")
if [[ -n "$API_TOKEN" ]]; then
    export API_TOKEN
fi

# 19. Proxy Mode (Multi-Protocol Support)
RAW_PROXY_MODE=$(get_env_value "PROXY_MODE" "proxy_mode")
CLEAN_PROXY_MODE=$(clean_val "$RAW_PROXY_MODE")
PROXY_MODE="${CLEAN_PROXY_MODE,,}"
[[ -z "$PROXY_MODE" ]] && PROXY_MODE="socks5"
export PROXY_MODE

# 20. Split Tunneling
RAW_SPLIT_TUNNEL=$(get_env_value "SPLIT_TUNNEL" "split_tunnel")
CLEAN_SPLIT=$(clean_val "$RAW_SPLIT_TUNNEL")
if [[ "${CLEAN_SPLIT,,}" == "true" || "${CLEAN_SPLIT}" == "1" ]]; then
    SPLIT_TUNNEL="true"
else
    SPLIT_TUNNEL="false"
fi
export SPLIT_TUNNEL

# Optional Manual Overrides (Auto-detected if left empty)
RAW_LOCAL_DNS=$(get_env_value "LOCAL_DNS" "local_dns")
LOCAL_DNS=$(clean_val "$RAW_LOCAL_DNS")
export LOCAL_DNS

RAW_VPN_DOMAINS=$(get_env_value "VPN_DOMAINS" "vpn_domains")
VPN_DOMAINS=$(clean_val "$RAW_VPN_DOMAINS")
export VPN_DOMAINS

RAW_VPN_SUBNETS=$(get_env_value "VPN_SUBNETS" "vpn_subnets")
VPN_SUBNETS=$(clean_val "$RAW_VPN_SUBNETS")
export VPN_SUBNETS

# ==============================================================================
# 2. RUNTIME SETUP
# ==============================================================================

RUNTIME_DIR="/tmp/gp-runtime"
CLIENT_LOG="/tmp/gp-logs/gp-client.log"
SERVICE_LOG="/tmp/gp-logs/gp-service.log"
MODE_FILE="$RUNTIME_DIR/gp-mode"

# Disable ANSI colors in Rust binaries
export RUST_LOG_STYLE=never

# Apply Timezone
if [[ -f "/usr/share/zoneinfo/$TZ" ]]; then
    ln -snf "/usr/share/zoneinfo/$TZ" /etc/localtime && echo "$TZ" >/etc/timezone
fi

# --- LOGGING HELPER ---
log() {
    local level="$1"
    local msg="$2"
    local should_log=false
    case "$LOG_LEVEL" in
        TRACE) should_log=true ;;
        DEBUG) [[ "$level" != "TRACE" ]] && should_log=true ;;
        INFO) [[ "$level" == "INFO" || "$level" == "WARN" || "$level" == "ERROR" ]] && should_log=true ;;
        *) [[ "$level" == "INFO" || "$level" == "WARN" || "$level" == "ERROR" ]] && should_log=true ;;
    esac

    if [[ "$should_log" == true ]]; then
        local timestamp
        timestamp=$(date +'%Y-%m-%dT%H:%M:%SZ')
        echo "[$timestamp] [$level] $msg" >>"$SERVICE_LOG"
        echo "[$timestamp] [$level] $msg" >&2
    fi
}

# --- VERBOSITY MAPPING ---
GP_VERBOSITY=""
if [[ "$LOG_LEVEL" == "DEBUG" ]]; then
    GP_VERBOSITY="-v"
elif [[ "$LOG_LEVEL" == "TRACE" ]]; then
    GP_VERBOSITY="-vv"
fi

# --- STARTUP SUMMARY ---
log "INFO" "=========================================="
log "INFO" "          GP Proxy Startup               "
log "INFO" "=========================================="
log "INFO" "Mode:        $VPN_MODE"
if [[ "$VPN_MODE" == "proxy" || "$VPN_MODE" == "standard" ]]; then
    log "INFO" "Proxy Types: $PROXY_MODE"
fi
log "INFO" "Log Level:   $LOG_LEVEL"
log "INFO" "Verbosity:   ${GP_VERBOSITY:-None}"
log "INFO" "Portal:      ${VPN_PORTAL:-[Not Set]}"
log "INFO" "Split Route: ${SPLIT_TUNNEL} (Smart Auto-Detection)"
if [[ -n "$VPN_GATEWAY" ]]; then
    log "INFO" "Gateway:     $VPN_GATEWAY"
fi
if [[ -n "$DNS_SERVERS" ]]; then
    log "INFO" "Custom DNS:  $DNS_SERVERS"
fi

if [[ -n "$API_TOKEN" ]]; then
    log "WARN" "------------------------------------------"
    log "WARN" " API_TOKEN Provided. TOFU Pairing Disabled."
else
    log "INFO" "API Token:   [Optional - TOFU Pairing Active]"
fi
log "INFO" "------------------------------------------"

# --- GRACEFUL SHUTDOWN ---
cleanup() {
    log "WARN" "Received Shutdown Signal"
    sudo pkill -x gpclient || true
    sudo pkill -x gpservice || true
    sudo pkill -x gost || true
    sudo pkill -x dnsmasq || true
    kill "$(jobs -p)" 2>/dev/null || true
    exit 0
}
trap cleanup SIGTERM SIGINT

# --- LOG ROTATION ---
check_log_size() {
    local max_size=10485760
    for logfile in "$CLIENT_LOG" "$SERVICE_LOG"; do
        if [[ -f "$logfile" ]]; then
            local size
            size=$(stat -c%s "$logfile")
            if [[ "$size" -gt "$max_size" ]]; then
                echo "[$(date)] Log truncated due to size limit." >"$logfile"
            fi
        fi
    done
}

# --- DYNAMIC PROCESS MANAGEMENT ---
start_proxies() {
    if [[ "$VPN_MODE" == "proxy" || "$VPN_MODE" == "standard" ]]; then
        if ! pgrep -x gost >/dev/null; then
            log "INFO" "Starting proxy handlers..."
            local proxy_args=""
            local auth_prefix=""
            local ss_auth_prefix=""

            if [[ -n "$PROXY_AUTH" ]]; then
                if [[ "$PROXY_AUTH" =~ ^[^:@/?#]+:[^@/?#]+$ ]]; then
                    log "INFO" "Standard Proxy Authentication Enabled."
                    auth_prefix="${PROXY_AUTH}@"
                else
                    log "ERROR" "PROXY_AUTH must be in 'user:password' format with no special URL characters. Ignoring."
                fi
            fi

            if [[ -n "$SS_AUTH" ]]; then
                if [[ "$SS_AUTH" =~ ^[^:@/?#]+:[^@/?#]+$ ]]; then
                    log "INFO" "Shadowsocks Authentication Enabled."
                    ss_auth_prefix="${SS_AUTH}@"
                else
                    log "ERROR" "SS_AUTH must be in 'cipher:password' format with no special URL characters. Ignoring."
                fi
            fi

            # Dynamically attach multiple listeners based on PROXY_MODE
            IFS=',' read -ra PROXIES <<<"$PROXY_MODE"
            for p in "${PROXIES[@]}"; do
                p="$(echo "$p" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' | tr '[:upper:]' '[:lower:]')"
                case "$p" in
                    socks5) proxy_args="$proxy_args -L=socks5://${auth_prefix}:1080?udp=true" ;;
                    socks4) proxy_args="$proxy_args -L=socks4://${auth_prefix}:1084" ;;
                    socks4a) proxy_args="$proxy_args -L=socks4a://${auth_prefix}:1085" ;;
                    http) proxy_args="$proxy_args -L=http://${auth_prefix}:8080" ;;
                    https) proxy_args="$proxy_args -L=https://${auth_prefix}:8443" ;;
                    ss)
                        if [[ -z "$ss_auth_prefix" ]]; then
                            SS_DEFAULT_PASS=$(head -c 16 /dev/urandom | base64 | tr -dc 'a-zA-Z0-9' | head -c 16)
                            log "WARN" "Shadowsocks requires authentication. Auto-generated password: $SS_DEFAULT_PASS"
                            proxy_args="$proxy_args -L=ss://chacha20:${SS_DEFAULT_PASS}@:8388"
                        else
                            proxy_args="$proxy_args -L=ss://${ss_auth_prefix}:8388"
                        fi
                        ;;
                    *) log "WARN" "Unknown proxy mode: $p" ;;
                esac
            done

            if [[ -n "$proxy_args" ]]; then
                runuser -u gpuser -- bash -c "gost $proxy_args" >>"$SERVICE_LOG" 2>&1 &
            else
                log "WARN" "No valid proxy modes matched. Proxy engine will not start."
            fi
        fi
    fi
}

# --- WATCHDOG ---
check_services() {
    if ! pgrep -f server.py >/dev/null; then
        log "ERROR" "CRITICAL: Web UI (server.py) died."
        exit 1
    fi

    # Liveness check for control listener to prevent pipe deadlocks
    if ! pgrep -f control_listener.py >/dev/null; then
        log "ERROR" "CRITICAL: Control listener died. Restarting..."
        runuser -u gpuser -- python3 -u /opt/gp-proxy/control_listener.py >&3 2>>"$SERVICE_LOG" &
    fi

    local mode
    mode=$(cat "$MODE_FILE" 2>/dev/null || echo "idle")

    if [[ "$mode" == "active" ]]; then
        if [[ "$VPN_MODE" == "proxy" || "$VPN_MODE" == "standard" ]]; then
            if ! pgrep -x gost >/dev/null; then
                log "ERROR" "CRITICAL: proxy engine died while VPN was active. Restarting..."
                start_proxies
            fi
        fi

        if ! pgrep -f "gpservice" >/dev/null; then
            log "ERROR" "CRITICAL: gpservice died while VPN was active."
            log "ERROR" "--- PROCESS LIST (DEBUG) ---"

            # Safely escape credentials and redact from the process dump
            local process_dump
            process_dump=$(ps aux)

            if [[ -n "$PROXY_AUTH" ]]; then
                process_dump="${process_dump//"$PROXY_AUTH"/***REDACTED***}"
            fi

            if [[ -n "$SS_AUTH" ]]; then
                process_dump="${process_dump//"$SS_AUTH"/***REDACTED***}"
            fi

            echo "$process_dump" >&2
            log "ERROR" "--- DUMPING LOGS (Last 50 lines) ---"
            tail -n 50 "$SERVICE_LOG" >&2
        fi
    fi
}

# --- 1. SETUP ---
if [[ -n "$PUID" ]]; then usermod -u "$PUID" gpuser; fi
if [[ -n "$PGID" ]]; then groupmod -g "$PGID" gpuser; fi

# Verify backend translation layer
if ! command -v iptables &>/dev/null; then
    log "WARN" "iptables command not found. Ensure iptables-nft translation is installed for correct container routing."
fi

# --- 2. NETWORK & MODE DETECTION ---
log "INFO" "Inspecting network environment..."
IS_MACVLAN=false
if ip -d link show eth0 | grep -q "macvlan"; then
    IS_MACVLAN=true
    log "DEBUG" "Network detection: MACVLAN interface detected."
else
    log "DEBUG" "Network detection: Standard/Bridge interface detected."
fi

if [[ "$VPN_MODE" == "gateway" || "$VPN_MODE" == "standard" ]]; then
    if [[ "$IS_MACVLAN" == false ]]; then
        log "WARN" "Configuration Mismatch: '$VPN_MODE' mode requested but no Macvlan interface found."
        log "WARN" "Gateway features require a direct routable IP (Macvlan)."
        log "WARN" ">>> REVERTING TO 'proxy' MODE to ensure functionality. <<<"
        VPN_MODE="proxy"
    fi
fi

# --- 3. BASE DNSMASQ CONFIGURATION ---
DNS_TO_APPLY=""
if [[ -n "$LOCAL_DNS" ]]; then
    DNS_TO_APPLY="$LOCAL_DNS"
elif [[ -n "$DNS_SERVERS" ]]; then
    DNS_TO_APPLY="$DNS_SERVERS"
elif [[ "$IS_MACVLAN" == true ]]; then
    log "INFO" "Macvlan detected. Applying fallback defaults."
    DNS_TO_APPLY="8.8.8.8 1.1.1.1"
else
    # Extract the original docker container DNS to use as the local fallback
    DNS_TO_APPLY=$(awk '/^nameserver/ {print $2}' /etc/resolv.conf | grep -v "127.0.0.1" | head -n 2 | paste -sd " " || echo "8.8.8.8 1.1.1.1")
fi

log "INFO" "Base Upstream Local DNS identified as: $DNS_TO_APPLY"

mkdir -p /etc/dnsmasq.d
cat <<EOF >/etc/dnsmasq.conf
port=53
listen-address=0.0.0.0
bind-interfaces
keep-in-foreground
conf-dir=/etc/dnsmasq.d/,*.conf
EOF

if [[ -n "$DNS_TO_APPLY" ]]; then
    # Using read -ra to safely split by spaces to appease shellcheck SC2086
    read -ra DNS_ARRAY <<<"$DNS_TO_APPLY"
    for ip in "${DNS_ARRAY[@]}"; do
        echo "server=$ip" >>/etc/dnsmasq.conf
    done
fi

# Initialize ipset for Dynamic DNS-based Policy Routing
ipset create vpn_domains hash:ip 2>/dev/null || true

# Instruct local container apps (like Gost) to use the dnsmasq split-router natively
echo "options ndots:0" >/etc/resolv.conf
echo "nameserver 127.0.0.1" >>/etc/resolv.conf

# Run dnsmasq as root so it can modify the ipsets dynamically
dnsmasq --user=root &

# --- VPNC SMART ROUTING WRAPPER ---
# This wrapper intercepts the connection sequence to dynamically configure Split-DNS and Subnets
# based directly on the payloads provided by the GlobalProtect server.
if [[ ! -f "/usr/share/vpnc-scripts/vpnc-script-orig" ]]; then
    mv /usr/share/vpnc-scripts/vpnc-script /usr/share/vpnc-scripts/vpnc-script-orig
fi

cat <<'EOF' >/usr/share/vpnc-scripts/vpnc-script
#!/bin/bash
# 1. Execute original script to initialize tun0 and standard IP allocations
/usr/share/vpnc-scripts/vpnc-script-orig "$@"

if [[ "$reason" == "connect" ]]; then
    # 2. Prevent vpnc-script from overriding our container resolver
    echo "options ndots:0" > /etc/resolv.conf
    echo "nameserver 127.0.0.1" >> /etc/resolv.conf

    # 3. Detect VPN DNS Servers
    VPN_DNS_SERVERS=($INTERNAL_IP4_DNS)

    # 4. Smart Auto-Detect VPN Domains
    DOMAINS=()
    if [[ -n "$CISCO_DEF_DOMAIN" ]]; then DOMAINS+=("$CISCO_DEF_DOMAIN"); fi
    if [[ -n "$CISCO_SPLIT_DNS" ]]; then
        IFS=',' read -ra ADDR <<< "$CISCO_SPLIT_DNS"
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
        IFS=',' read -ra ADDR <<< "$VPN_DOMAINS"
        for i in "${ADDR[@]}"; do DOMAINS+=("$i"); done
    fi

    mapfile -t UNIQUE_DOMAINS < <(printf "%s\n" "${DOMAINS[@]}" | sort -u | grep -v "^$")

    # 5. Dynamically configure Split-DNS
    rm -f /etc/dnsmasq.d/vpn.conf
    if [[ ${#UNIQUE_DOMAINS[@]} -gt 0 && ${#VPN_DNS_SERVERS[@]} -gt 0 ]]; then
        PRIMARY_VPN_DNS="${VPN_DNS_SERVERS[0]}"
        for d in "${UNIQUE_DOMAINS[@]}"; do
            echo "server=/$d/$PRIMARY_VPN_DNS" >> /etc/dnsmasq.d/vpn.conf
            echo "ipset=/$d/vpn_domains" >> /etc/dnsmasq.d/vpn.conf
        done
        echo "[vpnc-wrapper] Auto-Detected Split-DNS configured for: ${UNIQUE_DOMAINS[*]} -> $PRIMARY_VPN_DNS" >> /tmp/gp-logs/gp-service.log
        pkill -HUP dnsmasq || true
    fi

    # 6. Smart Split Routing Implementation
    if [[ "$SPLIT_TUNNEL" == "true" ]]; then
        echo "[vpnc-wrapper] Enforcing Split-Tunnel: Stripping default route (0.0.0.0/0) from tun0" >> /tmp/gp-logs/gp-service.log
        ip route del default dev tun0 2>/dev/null || true
    fi

    # Note: Standard vpnc-script already auto-routes CISCO_SPLIT_INC_... subnets provided by the VPN.
    # We only need to add manual overrides if the user provided them.
    if [[ -n "$VPN_SUBNETS" ]]; then
        IFS=',' read -ra SUBNETS <<< "$VPN_SUBNETS"
        for sub in "${SUBNETS[@]}"; do
            sub="$(echo "$sub" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
            [[ -z "$sub" ]] && continue
            ip route add "$sub" dev tun0 2>/dev/null || true
            echo "[vpnc-wrapper] Added explicit manual split route: $sub -> tun0" >> /tmp/gp-logs/gp-service.log
        done
    fi

    # 7. Enable IPSet routing for dynamic domains so resolved targets bypass the local network
    if ipset list vpn_domains >/dev/null 2>&1; then
        echo "[vpnc-wrapper] Enabling dynamic policy routing for auto-detected VPN domains" >> /tmp/gp-logs/gp-service.log
        ip rule add fwmark 0x10 lookup 100 2>/dev/null || true
        ip route add default dev tun0 table 100 2>/dev/null || true
        iptables -t mangle -A OUTPUT -m set --match-set vpn_domains dst -j MARK --set-mark 0x10 2>/dev/null || true
        iptables -t mangle -A PREROUTING -m set --match-set vpn_domains dst -j MARK --set-mark 0x10 2>/dev/null || true
    fi

elif [[ "$reason" == "disconnect" ]]; then
    rm -f /etc/dnsmasq.d/vpn.conf
    pkill -HUP dnsmasq || true
    ipset flush vpn_domains 2>/dev/null || true
fi
EOF
chmod +x /usr/share/vpnc-scripts/vpnc-script

# --- 4. NETWORK SETUP ---
iptables -F
iptables -t nat -F
iptables -A INPUT -p tcp --dport 8001 -j ACCEPT

if [[ "$VPN_MODE" == "gateway" || "$VPN_MODE" == "standard" ]]; then
    # Dynamically enable IP forwarding for routing functionality
    if [[ "$(cat /proc/sys/net/ipv4/ip_forward)" != "1" ]]; then
        echo 1 >/proc/sys/net/ipv4/ip_forward
    fi
    iptables -t nat -A POSTROUTING -o tun0 -j MASQUERADE

    if [[ -n "$ALLOWED_SUBNETS" ]]; then
        log "INFO" "Restricting routing to ALLOWED_SUBNETS: $ALLOWED_SUBNETS"
        IFS=',' read -ra SUBNETS <<<"$ALLOWED_SUBNETS"
        for subnet_raw in "${SUBNETS[@]}"; do
            # Trim whitespace safely
            subnet="$(echo "$subnet_raw" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
            [[ -z "$subnet" ]] && continue

            # Secure CIDR Validation enforcing 0-255 octets and 0-32 prefix
            if [[ "$subnet" =~ ^((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])/(3[0-2]|[12]?[0-9])$ ]]; then
                iptables -A FORWARD -s "$subnet" -o tun0 -j ACCEPT
            else
                log "ERROR" "Invalid subnet CIDR format ignored: $subnet"
            fi
        done
        iptables -A FORWARD -o tun0 -j DROP
    else
        iptables -A FORWARD -i eth0 -o tun0 -j ACCEPT
    fi

    iptables -A FORWARD -i tun0 -o eth0 -m state --state RELATED,ESTABLISHED -j ACCEPT
elif [[ "$VPN_MODE" == "proxy" ]]; then
    # Explicitly disable IP forwarding to maintain a locked-down posture on container restart
    if [[ "$(cat /proc/sys/net/ipv4/ip_forward)" != "0" ]]; then
        echo 0 >/proc/sys/net/ipv4/ip_forward
    fi
fi

if [[ "$VPN_MODE" == "proxy" || "$VPN_MODE" == "standard" ]]; then
    IFS=',' read -ra PROXIES <<<"$PROXY_MODE"
    for p in "${PROXIES[@]}"; do
        p="$(echo "$p" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' | tr '[:upper:]' '[:lower:]')"
        case "$p" in
            socks5)
                iptables -A INPUT -p tcp --dport 1080 -j ACCEPT
                iptables -A INPUT -p udp --dport 1080 -j ACCEPT
                ;;
            socks4) iptables -A INPUT -p tcp --dport 1084 -j ACCEPT ;;
            socks4a) iptables -A INPUT -p tcp --dport 1085 -j ACCEPT ;;
            http) iptables -A INPUT -p tcp --dport 8080 -j ACCEPT ;;
            https) iptables -A INPUT -p tcp --dport 8443 -j ACCEPT ;;
            ss)
                iptables -A INPUT -p tcp --dport 8388 -j ACCEPT
                iptables -A INPUT -p udp --dport 8388 -j ACCEPT
                ;;
        esac
    done
fi

# --- 5. INIT ENVIRONMENT ---
rm -rf "$RUNTIME_DIR"
mkdir -p "$RUNTIME_DIR" /tmp/gp-logs

# Harden permissions immediately to prevent logs from being broadly readable
chmod 700 "$RUNTIME_DIR" /tmp/gp-logs
touch "$CLIENT_LOG" "$SERVICE_LOG"
chmod 600 "$CLIENT_LOG" "$SERVICE_LOG"

chown -R gpuser:gpuser /tmp/gp-logs /var/www/html "$RUNTIME_DIR"

echo "idle" >"$MODE_FILE"
chmod 644 "$MODE_FILE"

# --- 6. START SERVICES ---
log "INFO" "Starting Services..."

# Setup persistent control pipe to eliminate Python interpreter startup overhead in the polling loop
# Note: The FIFO is intentionally created and opened as root before chown so child processes
# inherit the already-open fd 3. The chown ensures later path-based opens use gpuser.
mkfifo "$RUNTIME_DIR/gp_control_pipe"
exec 3<>"$RUNTIME_DIR/gp_control_pipe"
chown gpuser:gpuser "$RUNTIME_DIR/gp_control_pipe"

# Ensure API_TOKEN and PROXY_AUTH states are definitively passed down to the server context
runuser -u gpuser -- env VPN_MODE="$VPN_MODE" PROXY_MODE="$PROXY_MODE" LOG_LEVEL="$LOG_LEVEL" API_TOKEN="$API_TOKEN" PROXY_AUTH="$PROXY_AUTH" SS_AUTH="$SS_AUTH" \
    python3 -u /opt/gp-proxy/server.py >>"$SERVICE_LOG" 2>&1 &

# Start persistent control listener directly bound to the pipe descriptor
runuser -u gpuser -- python3 -u /opt/gp-proxy/control_listener.py >&3 2>>"$SERVICE_LOG" &

tail -F "$SERVICE_LOG" "$CLIENT_LOG" &

sleep 3

# --- 7. MAIN LOOP ---
while true; do
    check_services
    check_log_size

    # Listen on local TCP socket via persistent background pipe (2-second timeout)
    CMD=""
    read -r -t 2 CMD <&3 || true
    if [[ "$CMD" == "START" ]]; then
        log "INFO" "Signal received. Starting Connection Sequence..."
        echo "active" >"$MODE_FILE"

        start_proxies

        # 1. Start gpservice
        log "INFO" "Starting gpservice..."
        runuser -u gpuser -- bash -c "
            /usr/bin/gpservice 2>&1 | \
            grep --line-buffered -v -E 'Failed to start WS server|Error: No such file or directory \(os error 2\)' \
            >> \"$SERVICE_LOG\"
        " &

        sleep 2

        # 2. Start gpclient using environment variables to avoid outer shell interpolation
        # shellcheck disable=SC2016
        runuser -u gpuser -- env VPN_PORTAL="$VPN_PORTAL" VPN_GATEWAY="$VPN_GATEWAY" \
            VPN_HIP_REPORT="$VPN_HIP_REPORT" VPN_NO_DTLS="$VPN_NO_DTLS" VPN_DISABLE_IPV6="$VPN_DISABLE_IPV6" \
            VPN_OS="$VPN_OS" VPN_OS_VERSION="$VPN_OS_VERSION" VPN_CLIENT_VERSION="$VPN_CLIENT_VERSION" \
            GP_ARGS="$GP_ARGS" GP_VERBOSITY="$GP_VERBOSITY" CLIENT_LOG="$CLIENT_LOG" SERVICE_LOG="$SERVICE_LOG" \
            BASH_NL=$'\n' BASH_CR=$'\r' SPLIT_TUNNEL="$SPLIT_TUNNEL" VPN_SUBNETS="$VPN_SUBNETS" VPN_DOMAINS="$VPN_DOMAINS" \
            bash -c '
            set -o pipefail
            > "$CLIENT_LOG"

            declare -a args=(sudo gpclient)

            [[ -n "$GP_VERBOSITY" ]] && args+=("$GP_VERBOSITY")
            args+=(--fix-openssl connect "$VPN_PORTAL" --browser remote)

            if [[ -n "$VPN_GATEWAY" ]]; then
                args+=("--gateway" "$VPN_GATEWAY")
            else
                args+=(--as-gateway)
            fi

            [[ "$VPN_HIP_REPORT" == "true" ]]   && args+=(--hip)
            [[ "$VPN_NO_DTLS" == "true" ]]      && args+=(--no-dtls)
            [[ "$VPN_DISABLE_IPV6" == "true" ]] && args+=(--disable-ipv6)

            [[ -n "$VPN_OS" ]]             && args+=(--os "$VPN_OS")
            [[ -n "$VPN_OS_VERSION" ]]     && args+=(--os-version "$VPN_OS_VERSION")
            [[ -n "$VPN_CLIENT_VERSION" ]] && args+=(--client-version "$VPN_CLIENT_VERSION")

            if [[ -n "$GP_ARGS" ]]; then
                # Trust boundary: GP_ARGS is operator-controlled. Reject dangerous shell metacharacters before eval.
                if [[ "$GP_ARGS" == *"$BASH_NL"* || "$GP_ARGS" == *"$BASH_CR"* || "$GP_ARGS" =~ [\$\(\)\;\&\|\<\>\`\\*?\{\}] ]]; then
                    echo "[Entrypoint] CRITICAL: Unsafe shell metacharacters detected. GP_ARGS rejected." >> "$SERVICE_LOG"
                else
                    eval "set -- $GP_ARGS"
                    for arg in "$@"; do
                        args+=("$arg")
                    done
                fi
            fi

            SAFE_CMD=$(printf "%q " "${args[@]}")

            echo "[Entrypoint] Executing: $SAFE_CMD" >> "$SERVICE_LOG"
            python3 /opt/gp-proxy/stdin_proxy.py | script -q -c "$SAFE_CMD" /dev/null >> "$CLIENT_LOG" 2>&1
        '

        # 3. Cleanup after disconnect
        log "WARN" "gpclient pipeline resolved. Cleaning up services..."
        echo "idle" >"$MODE_FILE"
        sudo pkill -x gpservice || true
        pkill -x gost || true
        log "INFO" "Services stopped. System Idle."
    fi
done
