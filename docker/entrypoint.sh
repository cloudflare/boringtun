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

    # Signal processes first (in correct order)
    if [ -n "${PROXY_PID:-}" ]; then
        kill -TERM "$PROXY_PID" 2>/dev/null || true
    fi
    if [ -n "${COREDNS_PID:-}" ]; then
        kill -TERM "$COREDNS_PID" 2>/dev/null || true
    fi

    # Safely delete network interface
    if ip link show dev "$INTERFACE_NAME" >/dev/null 2>&1; then
        run_hooks PostDown || true
        ip link delete dev "$INTERFACE_NAME" || true
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

echo "starting CoreDNS: $COREDNS_CONFIG"
cmd /usr/local/bin/coredns -conf "$COREDNS_CONFIG" &
COREDNS_PID=$!

echo "bringing up WireGuard (kernel module): $WG_CONFIG_PATH"
configure_interface

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
