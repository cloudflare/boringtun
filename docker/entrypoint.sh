#!/usr/bin/env bash
set -euo pipefail

PROXY_BIN="${PROXY_BIN:-/app/ssl-proxy}"
COREDNS_CONFIG="${COREDNS_CONFIG:-/config/coredns/Corefile}"
WG_INTERFACE_NAME="${WG_INTERFACE_NAME:-wg0}"
WG_CONFIG_PATH="${WG_CONFIG_PATH:-/run/wireguard/${WG_INTERFACE_NAME}.conf}"
WG_TEMPLATE_PATH="${WG_TEMPLATE_PATH:-/config/templates/server.conf}"
WG_SERVER_PRIVATE_KEY_FILE="${WG_SERVER_PRIVATE_KEY_FILE:-/config/server/privatekey-server}"
WG_SERVER_PUBLIC_KEY_FILE="${WG_SERVER_PUBLIC_KEY_FILE:-/config/server/publickey-server}"
WG_PEER_CONFIG_PATH="${WG_PEER_CONFIG_PATH:-/config/peer1/peer1.conf}"
WG_PEER_PUBLIC_KEY_FILE="${WG_PEER_PUBLIC_KEY_FILE:-/config/peer1/publickey-peer1}"
WG_PEER_PRESHARED_KEY_FILE="${WG_PEER_PRESHARED_KEY_FILE:-/config/peer1/presharedkey-peer1}"
WG_SERVER_ADDRESS="${WG_SERVER_ADDRESS:-10.13.13.1/24}"
WG_LISTEN_PORT="${WG_LISTEN_PORT:-443}"
WG_MTU="${WG_MTU:-1280}"
WG_PEER_ALLOWED_IPS="${WG_PEER_ALLOWED_IPS:-}"
WG_WAN_INTERFACE="${WG_WAN_INTERFACE:-auto}"
WG_SYSCTL_RETRIES="${WG_SYSCTL_RETRIES:-3}"
WG_SYSCTL_RETRY_DELAY_MS="${WG_SYSCTL_RETRY_DELAY_MS:-200}"

cmd() {
    echo "[#] $*"
    "$@"
}

trim() {
    local value="$1"
    value="${value#"${value%%[![:space:]]*}"}"
    value="${value%"${value##*[![:space:]]}"}"
    printf '%s' "$value"
}

read_trimmed_file() {
    local path="$1"
    if [ ! -f "$path" ]; then
        echo "missing required file: $path" >&2
        exit 1
    fi
    tr -d '\r' <"$path" | sed -e 's/[[:space:]]*$//' | tail -n 1
}

try_read_trimmed_file() {
    local path="$1"
    if [ ! -f "$path" ]; then
        return 1
    fi
    tr -d '\r' <"$path" | sed -e 's/[[:space:]]*$//' | tail -n 1
}

write_trimmed_file() {
    local path="$1"
    local value="$2"
    local mode="${3:-600}"
    mkdir -p "$(dirname "$path")"
    printf '%s\n' "$value" >"$path"
    chmod "$mode" "$path"
}

extract_ini_value() {
    local file="$1"
    local section="$2"
    local key="$3"
    awk -F= -v section="$section" -v key="$key" '
        BEGIN { in_section = 0 }
        /^\[/ {
            in_section = ($0 == "[" section "]")
            next
        }
        in_section {
            lhs = $1
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", lhs)
            if (lhs == key) {
                rhs = substr($0, index($0, "=") + 1)
                gsub(/^[[:space:]]+|[[:space:]]+$/, "", rhs)
                print rhs
                exit
            }
        }
    ' "$file"
}

normalize_allowed_ips() {
    local address
    address="$(trim "${1%%,*}")"
    if [ -z "$address" ]; then
        echo "unable to derive peer tunnel address" >&2
        exit 1
    fi
    if [[ "$address" == */* ]]; then
        printf '%s' "$address"
    elif [[ "$address" == *:* ]]; then
        printf '%s/128' "$address"
    else
        printf '%s/32' "$address"
    fi
}

detect_wan_interface() {
    ip route show default 2>/dev/null | awk '/default/ {print $5; exit}'
}

resolve_wan_interface() {
    local resolved
    if [ "$WG_WAN_INTERFACE" != "auto" ] && [ -n "$WG_WAN_INTERFACE" ]; then
        resolved="$WG_WAN_INTERFACE"
    else
        resolved="$(detect_wan_interface)"
    fi

    resolved="$(trim "$resolved")"
    if [ -z "$resolved" ]; then
        echo "unable to determine WAN interface: set WG_WAN_INTERFACE explicitly" >&2
        exit 1
    fi

    WG_WAN_INTERFACE="$resolved"
}

normalize_csv_unique() {
    local input="$1"
    awk -v input="$input" '
        function trim(s) {
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", s)
            return s
        }
        BEGIN {
            n = split(input, parts, ",")
            out = ""
            for (i = 1; i <= n; i++) {
                item = trim(parts[i])
                if (item == "") {
                    continue
                }
                if (!(item in seen)) {
                    seen[item] = 1
                    out = (out == "" ? item : out "," item)
                }
            }
            print out
        }
    '
}

resolve_peer_public_key() {
    local peer_public_key=""
    local legacy_peer_public_key_file=""
    local peer_private_key=""

    peer_public_key="$(try_read_trimmed_file "$WG_PEER_PUBLIC_KEY_FILE" || true)"
    if [ -n "$peer_public_key" ]; then
        printf '%s' "$peer_public_key"
        return 0
    fi

    legacy_peer_public_key_file="$(dirname "$WG_PEER_PUBLIC_KEY_FILE")/pubickey-peer1"
    peer_public_key="$(try_read_trimmed_file "$legacy_peer_public_key_file" || true)"
    if [ -n "$peer_public_key" ]; then
        echo "[#] Using legacy peer public key file: $legacy_peer_public_key_file" >&2
        write_trimmed_file "$WG_PEER_PUBLIC_KEY_FILE" "$peer_public_key" 644
        echo "[#] Synced peer public key to $WG_PEER_PUBLIC_KEY_FILE" >&2
        printf '%s' "$peer_public_key"
        return 0
    fi

    peer_private_key="$(trim "$(extract_ini_value "$WG_PEER_CONFIG_PATH" "Interface" "PrivateKey")")"
    if [ -n "$peer_private_key" ]; then
        peer_public_key="$(printf '%s\n' "$peer_private_key" | wg pubkey)"
        echo "[#] Derived peer public key from $WG_PEER_CONFIG_PATH" >&2
        write_trimmed_file "$WG_PEER_PUBLIC_KEY_FILE" "$peer_public_key" 644
        echo "[#] Wrote derived peer public key to $WG_PEER_PUBLIC_KEY_FILE" >&2
        printf '%s' "$peer_public_key"
        return 0
    fi

    echo "missing peer public key: set WG_PEER_PUBLIC_KEY_FILE or include Interface.PrivateKey in $WG_PEER_CONFIG_PATH" >&2
    exit 1
}

format_handshake_timestamp() {
    local epoch="$1"
    local rendered
    if [ -z "$epoch" ] || [ "$epoch" = "0" ]; then
        printf '%s' "never"
        return
    fi

    # Prefer GNU date formatting when available, fall back to raw epoch.
    rendered="$(date -u -d "@$epoch" '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || true)"
    if [ -n "$rendered" ]; then
        printf '%s' "$rendered"
    else
        printf '%s' "epoch:$epoch"
    fi
}

log_wireguard_peer_status() {
    local dump
    local peer_count
    local public_key
    local _preshared_key
    local endpoint
    local allowed_ips
    local latest_handshake
    local transfer_rx
    local transfer_tx
    local persistent_keepalive
    local handshake_readable

    if ! dump="$(wg show "$WG_INTERFACE_NAME" dump 2>/dev/null)"; then
        echo "[wg] warning: unable to read peer status for interface $WG_INTERFACE_NAME" >&2
        return 0
    fi

    peer_count="$(printf '%s\n' "$dump" | awk 'NR > 1 {count++} END {print count + 0}')"
    echo "[wg] interface $WG_INTERFACE_NAME is up; peer_count=$peer_count"

    if [ "$peer_count" -eq 0 ]; then
        echo "[wg] no peers configured on $WG_INTERFACE_NAME"
        return 0
    fi

    while IFS=$'\t' read -r public_key _preshared_key endpoint allowed_ips latest_handshake transfer_rx transfer_tx persistent_keepalive; do
        [ -n "$public_key" ] || continue
        handshake_readable="$(format_handshake_timestamp "$latest_handshake")"
        [ -n "$endpoint" ] || endpoint="(none)"
        [ -n "$allowed_ips" ] || allowed_ips="(none)"
        [ -n "$persistent_keepalive" ] || persistent_keepalive="off"

        echo "[wg] peer=$public_key endpoint=$endpoint allowed_ips=$allowed_ips last_handshake=$handshake_readable rx_bytes=$transfer_rx tx_bytes=$transfer_tx keepalive_s=$persistent_keepalive"
    done < <(printf '%s\n' "$dump" | awk 'NR > 1')
}

sync_peer_server_public_key() {
    local public_key="$1"
    local peer_config="$2"
    local tmp_file

    if [ ! -f "$peer_config" ]; then
        return
    fi

    tmp_file="$(mktemp)"
    awk -v public_key="$public_key" '
        BEGIN { in_peer = 0 }
        /^\[Peer\]/ { in_peer = 1; print; next }
        /^\[/ { in_peer = 0; print; next }
        in_peer {
            line = $0
            stripped = line
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", stripped)
            if (stripped ~ /^PublicKey[[:space:]]*=/) {
                print "PublicKey = " public_key
                next
            }
        }
        { print }
    ' "$peer_config" >"$tmp_file"
    mv "$tmp_file" "$peer_config"
}

ensure_wireguard_server_keys() {
    local server_private_key
    local server_public_key
    local current_public_key

    mkdir -p "$(dirname "$WG_SERVER_PRIVATE_KEY_FILE")"
    mkdir -p "$(dirname "$WG_SERVER_PUBLIC_KEY_FILE")"

    if [ ! -f "$WG_SERVER_PRIVATE_KEY_FILE" ]; then
        echo "[#] Generating WireGuard server keypair at $WG_SERVER_PRIVATE_KEY_FILE"
        umask 077
        server_private_key="$(wg genkey)"
        write_trimmed_file "$WG_SERVER_PRIVATE_KEY_FILE" "$server_private_key" 600
    else
        server_private_key="$(read_trimmed_file "$WG_SERVER_PRIVATE_KEY_FILE")"
    fi

    server_public_key="$(printf '%s\n' "$server_private_key" | wg pubkey)"

    if [ -f "$WG_SERVER_PUBLIC_KEY_FILE" ]; then
        current_public_key="$(read_trimmed_file "$WG_SERVER_PUBLIC_KEY_FILE")"
    else
        current_public_key=""
    fi

    if [ "$current_public_key" != "$server_public_key" ]; then
        echo "[#] Syncing WireGuard server public key to $WG_SERVER_PUBLIC_KEY_FILE"
        write_trimmed_file "$WG_SERVER_PUBLIC_KEY_FILE" "$server_public_key" 644
    fi

    if [ -f "$WG_PEER_CONFIG_PATH" ]; then
        echo "[#] Syncing server public key into $WG_PEER_CONFIG_PATH"
        sync_peer_server_public_key "$server_public_key" "$WG_PEER_CONFIG_PATH"
    fi
}

render_wireguard_config() {
    local server_private_key
    local peer_public_key
    local peer_preshared_key
    local peer_address
    local normalized_server_address
    local escaped_server_private_key
    local escaped_peer_public_key
    local escaped_peer_preshared_key
    local escaped_server_address
    local escaped_listen_port
    local escaped_mtu
    local escaped_peer_allowed_ips
    local escaped_wan_interface
    local escaped_sysctl_retries
    local escaped_sysctl_retry_delay_ms

    if [ ! -f "$WG_TEMPLATE_PATH" ]; then
        echo "missing WireGuard template: $WG_TEMPLATE_PATH" >&2
        exit 1
    fi

    server_private_key="$(read_trimmed_file "$WG_SERVER_PRIVATE_KEY_FILE")"
    peer_public_key="$(resolve_peer_public_key)"

    normalized_server_address="$(normalize_csv_unique "$WG_SERVER_ADDRESS")"
    if [ -z "$normalized_server_address" ]; then
        echo "WG_SERVER_ADDRESS resolved to empty value after normalization" >&2
        exit 1
    fi
    if [ "$normalized_server_address" != "$WG_SERVER_ADDRESS" ]; then
        echo "[#] Normalized WG_SERVER_ADDRESS: $WG_SERVER_ADDRESS -> $normalized_server_address"
    fi
    WG_SERVER_ADDRESS="$normalized_server_address"

    if [ -f "$WG_PEER_PRESHARED_KEY_FILE" ]; then
        peer_preshared_key="$(read_trimmed_file "$WG_PEER_PRESHARED_KEY_FILE")"
    else
        peer_preshared_key="$(extract_ini_value "$WG_PEER_CONFIG_PATH" "Peer" "PresharedKey")"
        peer_preshared_key="$(trim "$peer_preshared_key")"
    fi

    if [ -z "$peer_preshared_key" ]; then
        echo "missing peer preshared key; set WG_PEER_PRESHARED_KEY_FILE or populate $WG_PEER_CONFIG_PATH" >&2
        exit 1
    fi

    if [ -z "$WG_PEER_ALLOWED_IPS" ]; then
        peer_address="$(extract_ini_value "$WG_PEER_CONFIG_PATH" "Interface" "Address")"
        WG_PEER_ALLOWED_IPS="$(normalize_allowed_ips "$peer_address")"
    fi

    mkdir -p "$(dirname "$WG_CONFIG_PATH")"

    escaped_server_private_key="${server_private_key//\\/\\\\}"
    escaped_server_private_key="${escaped_server_private_key//&/\\&}"
    escaped_peer_public_key="${peer_public_key//\\/\\\\}"
    escaped_peer_public_key="${escaped_peer_public_key//&/\\&}"
    escaped_peer_preshared_key="${peer_preshared_key//\\/\\\\}"
    escaped_peer_preshared_key="${escaped_peer_preshared_key//&/\\&}"
    escaped_server_address="${WG_SERVER_ADDRESS//\\/\\\\}"
    escaped_server_address="${escaped_server_address//&/\\&}"
    escaped_listen_port="${WG_LISTEN_PORT//\\/\\\\}"
    escaped_listen_port="${escaped_listen_port//&/\\&}"
    escaped_mtu="${WG_MTU//\\/\\\\}"
    escaped_mtu="${escaped_mtu//&/\\&}"
    escaped_peer_allowed_ips="${WG_PEER_ALLOWED_IPS//\\/\\\\}"
    escaped_peer_allowed_ips="${escaped_peer_allowed_ips//&/\\&}"
    escaped_wan_interface="${WG_WAN_INTERFACE//\\/\\\\}"
    escaped_wan_interface="${escaped_wan_interface//&/\\&}"
    escaped_sysctl_retries="${WG_SYSCTL_RETRIES//\\/\\\\}"
    escaped_sysctl_retries="${escaped_sysctl_retries//&/\\&}"
    escaped_sysctl_retry_delay_ms="${WG_SYSCTL_RETRY_DELAY_MS//\\/\\\\}"
    escaped_sysctl_retry_delay_ms="${escaped_sysctl_retry_delay_ms//&/\\&}"

    sed \
        -e "s|__WG_SERVER_ADDRESS__|$escaped_server_address|g" \
        -e "s|__WG_LISTEN_PORT__|$escaped_listen_port|g" \
        -e "s|__WG_MTU__|$escaped_mtu|g" \
        -e "s|__WG_SERVER_PRIVATE_KEY__|$escaped_server_private_key|g" \
        -e "s|__WG_PEER_PUBLIC_KEY__|$escaped_peer_public_key|g" \
        -e "s|__WG_PEER_PRESHARED_KEY__|$escaped_peer_preshared_key|g" \
        -e "s|__WG_PEER_ALLOWED_IPS__|$escaped_peer_allowed_ips|g" \
        -e "s|__WG_WAN_INTERFACE__|$escaped_wan_interface|g" \
        -e "s|__WG_SYSCTL_RETRIES__|$escaped_sysctl_retries|g" \
        -e "s|__WG_SYSCTL_RETRY_DELAY_MS__|$escaped_sysctl_retry_delay_ms|g" \
        "$WG_TEMPLATE_PATH" >"$WG_CONFIG_PATH"

    chmod 600 "$WG_CONFIG_PATH"
}

cleanup() {
    set +e

    # Signal processes first (in correct order)
    if [ -n "${PROXY_PID:-}" ]; then
        kill -TERM "$PROXY_PID" 2>/dev/null || true
    fi
    if [ -n "${COREDNS_PID:-}" ]; then
        kill -TERM "$COREDNS_PID" 2>/dev/null || true
    fi
    if [ -n "${WG_UP:-}" ]; then
        wg-quick down "$WG_CONFIG_PATH" 2>/dev/null || true
    fi
}

trap cleanup EXIT INT TERM

if [ ! -f "$COREDNS_CONFIG" ]; then
    echo "missing CoreDNS config: $COREDNS_CONFIG" >&2
    exit 1
fi

# Signal handler for graceful shutdown
shutdown() {
    echo "Received shutdown signal, terminating children..."
    if [ -n "${PROXY_PID:-}" ]; then
        kill -TERM "$PROXY_PID" 2>/dev/null || true
    fi
    if [ -n "${COREDNS_PID:-}" ]; then
        kill -TERM "$COREDNS_PID" 2>/dev/null || true
    fi
    exit 0
}

trap shutdown TERM

ensure_wireguard_server_keys
resolve_wan_interface
echo "[#] Using WAN interface: $WG_WAN_INTERFACE"
render_wireguard_config
echo "starting WireGuard interface $WG_INTERFACE_NAME: $WG_CONFIG_PATH"
cmd wg-quick up "$WG_CONFIG_PATH"
WG_UP=1
log_wireguard_peer_status

echo "starting CoreDNS: $COREDNS_CONFIG"
cmd /usr/local/bin/coredns -conf "$COREDNS_CONFIG" &
COREDNS_PID=$!

# Auto-generate self-signed TLS certificate only when explicit proxy mode is enabled.
if [ "${EXPLICIT_PROXY_ENABLED:-false}" = "true" ] && [ "${DISABLE_TLS:-false}" != "true" ] && [ -z "${TLS_CERT_PATH:-}" ] && [ -z "${TLS_KEY_PATH:-}" ]; then
    if [ ! -f "/ssl/tls.crt" ] || [ ! -f "/ssl/tls.key" ]; then
        echo "[#] Generating self-signed TLS certificate for proxy listener"
        mkdir -p /ssl
        if ! openssl req -x509 -nodes -days 365 -newkey rsa:4096 \
            -keyout /ssl/tls.key \
            -out /ssl/tls.crt \
            -subj "/CN=ssl-proxy.local" \
            -addext "subjectAltName=DNS:ssl-proxy.local,DNS:localhost,IP:127.0.0.1"; then
            echo "[!] Failed to generate TLS certificate" >&2
            exit 1
        fi
        chmod 600 /ssl/tls.key
        export TLS_CERT_PATH="/ssl/tls.crt"
        export TLS_KEY_PATH="/ssl/tls.key"
        echo "[#] TLS certificate generated at /ssl/tls.crt"
    else
        export TLS_CERT_PATH="/ssl/tls.crt"
        export TLS_KEY_PATH="/ssl/tls.key"
    fi
fi

# Force plaintext mode when DISABLE_TLS is set or explicit proxy mode is disabled.
if [ "${DISABLE_TLS:-false}" = "true" ] || [ "${EXPLICIT_PROXY_ENABLED:-false}" != "true" ]; then
    unset TLS_CERT_PATH
    unset TLS_KEY_PATH
    echo "[#] Explicit proxy TLS disabled"
fi

echo "starting ssl-proxy"
"$PROXY_BIN" &
PROXY_PID=$!

# Monitor critical child processes
while true; do
    # Wait for any child to exit
    wait -n
    exit_code=$?

    if ! kill -0 "$COREDNS_PID" 2>/dev/null; then
        echo "coredns exited unexpectedly, restarting container"
        exit 1
    fi

    # If ssl-proxy died, restart it
    if ! kill -0 "$PROXY_PID" 2>/dev/null; then
        echo "ssl-proxy exited, restarting..."
        "$PROXY_BIN" &
        PROXY_PID=$!
    fi
done
