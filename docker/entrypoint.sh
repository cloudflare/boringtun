#!/usr/bin/env bash
set -euo pipefail

PROXY_BIN="${PROXY_BIN:-/app/ssl-proxy}"
COREDNS_CONFIG="${COREDNS_CONFIG:-/config/coredns/Corefile}"

cmd() {
    echo "[#] $*"
    "$@"
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

echo "starting CoreDNS: $COREDNS_CONFIG"
cmd /usr/local/bin/coredns -conf "$COREDNS_CONFIG" &
COREDNS_PID=$!

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