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

# Auto-generate self-signed TLS certificate only if explicitly enabled
if [ "${DISABLE_TLS:-false}" != "true" ] && [ -z "${TLS_CERT_PATH:-}" ] && [ -z "${TLS_KEY_PATH:-}" ]; then
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

# Force plaintext mode when DISABLE_TLS is set
if [ "${DISABLE_TLS:-false}" = "true" ]; then
    unset TLS_CERT_PATH
    unset TLS_KEY_PATH
    echo "[#] TLS disabled - proxy will run in PLAINTEXT mode only"
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