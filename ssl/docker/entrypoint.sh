#!/usr/bin/env bash
set -euo pipefail

WG_CONFIG_PATH="${WG_CONFIG_PATH:-/config/wg_confs/wg0.conf}"
PROXY_BIN="${PROXY_BIN:-/app/ssl-proxy}"
COREDNS_CONFIG="${COREDNS_CONFIG:-/config/coredns/Corefile}"
INTERFACE_NAME="$(basename "${WG_CONFIG_PATH%.conf}")"

# Source the WireGuard setup script
source /usr/local/bin/wg_up.sh

cmd() {
    echo "[#] $*"
    "$@"
}

run_hooks() {
    local key="$1"
    awk -F= -v key="$key" '
        BEGIN { in_if = 0 }
        /^\[Interface\]/ { in_if = 1; next }
        /^\[/ { in_if = 0 }
        in_if {
            lhs = $1
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", lhs)
            if (lhs == key) {
                rhs = substr($0, index($0, "=") + 1)
                gsub(/^[[:space:]]+|[[:space:]]+$/, "", rhs)
                print rhs
            }
        }
    ' "$WG_CONFIG_PATH" | while IFS= read -r line; do
        [ -n "$line" ] || continue
        line="${line//%i/$INTERFACE_NAME}"
        cmd bash -lc "$line"
    done
}

cleanup() {
    set +e
    if ip link show dev "$INTERFACE_NAME" >/dev/null 2>&1; then
        run_hooks PostDown || true
        ip link delete dev "$INTERFACE_NAME" || true
    fi
    if [ -n "${COREDNS_PID:-}" ]; then
        kill "$COREDNS_PID" 2>/dev/null || true
    fi
    if [ -n "${BORINGTUN_PID:-}" ]; then
        kill "$BORINGTUN_PID" 2>/dev/null || true
    fi
}

trap cleanup EXIT INT TERM

if [ ! -c /dev/net/tun ]; then
    echo "missing /dev/net/tun; run the container with the tun device attached" >&2
    exit 1
fi

if [ ! -f "$WG_CONFIG_PATH" ]; then
    echo "missing WireGuard config: $WG_CONFIG_PATH" >&2
    exit 1
fi

if [ ! -f "$COREDNS_CONFIG" ]; then
    echo "missing CoreDNS config: $COREDNS_CONFIG" >&2
    exit 1
fi

# Health check function for boringtun-cli
health_check_boringtun() {
    while true; do
        sleep 5
        if ! kill -0 "$BORINGTUN_PID" 2>/dev/null; then
            echo "boringtun-cli (PID $BORINGTUN_PID) died, restarting..."
            cmd /usr/local/bin/boringtun-cli --disable-drop-privileges --foreground "$INTERFACE_NAME" &
            BORINGTUN_PID=$!
        fi
    done
}

# Signal handler for graceful shutdown
shutdown() {
    echo "Received shutdown signal, terminating children..."
    if [ -n "${PROXY_PID:-}" ]; then
        kill -TERM "$PROXY_PID" 2>/dev/null || true
    fi
    if [ -n "${BORINGTUN_PID:-}" ]; then
        kill -TERM "$BORINGTUN_PID" 2>/dev/null || true
    fi
    if [ -n "${COREDNS_PID:-}" ]; then
        kill -TERM "$COREDNS_PID" 2>/dev/null || true
    fi
    exit 0
}

trap shutdown TERM

echo "starting CoreDNS: $COREDNS_CONFIG"
cmd /usr/local/bin/coredns -conf "$COREDNS_CONFIG" &
COREDNS_PID=$!

echo "bringing up WireGuard via boringtun: $WG_CONFIG_PATH"
configure_interface

# Start health check in background
health_check_boringtun &

echo "starting ssl-proxy"
"$PROXY_BIN" &
PROXY_PID=$!

# Monitor child processes with wait -n
while true; do
    if ! wait -n; then
        echo "A child process exited unexpectedly"
        exit 1
    fi
done
