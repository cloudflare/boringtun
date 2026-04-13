#!/usr/bin/env bash
set -euo pipefail

WG_CONFIG_PATH="${WG_CONFIG_PATH:-/config/wg_confs/wg0.conf}"
PROXY_BIN="${PROXY_BIN:-/app/ssl-proxy}"
COREDNS_CONFIG="${COREDNS_CONFIG:-/config/coredns/Corefile}"
INTERFACE_NAME="$(basename "${WG_CONFIG_PATH%.conf}")"

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

configure_interface() {
    local mtu

    cmd /usr/local/bin/boringtun-cli --disable-drop-privileges --foreground "$INTERFACE_NAME" &
    BORINGTUN_PID=$!

    for _ in $(seq 1 50); do
        if ip link show dev "$INTERFACE_NAME" >/dev/null 2>&1; then
            break
        fi
        if ! kill -0 "$BORINGTUN_PID" 2>/dev/null; then
            echo "boringtun-cli (PID $BORINGTUN_PID) exited unexpectedly before $INTERFACE_NAME appeared" >&2
            exit 1
        fi
        sleep 0.1
    done
    if ! ip link show dev "$INTERFACE_NAME" >/dev/null 2>&1; then
        echo "WireGuard interface $INTERFACE_NAME failed to appear" >&2
        exit 1
    fi

    cmd wg setconf "$INTERFACE_NAME" <(wg-quick strip "$WG_CONFIG_PATH")

    awk -F= '
        BEGIN { in_if = 0 }
        /^\[Interface\]/ { in_if = 1; next }
        /^\[/ { in_if = 0 }
        in_if {
            lhs = $1
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", lhs)
            if (lhs == "Address") {
                rhs = substr($0, index($0, "=") + 1)
                gsub(/^[[:space:]]+|[[:space:]]+$/, "", rhs)
                gsub(/,/, "\n", rhs)
                print rhs
            }
        }
    ' "$WG_CONFIG_PATH" | while IFS= read -r addr; do
        [ -n "$addr" ] || continue
        if [[ "$addr" == *:* ]]; then
            cmd ip -6 address add "$addr" dev "$INTERFACE_NAME"
        else
            cmd ip -4 address add "$addr" dev "$INTERFACE_NAME"
        fi
    done

    mtu="$(awk -F= '
        BEGIN { in_if = 0 }
        /^\[Interface\]/ { in_if = 1; next }
        /^\[/ { in_if = 0 }
        in_if {
            lhs = $1
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", lhs)
            if (lhs == "MTU") {
                rhs = substr($0, index($0, "=") + 1)
                gsub(/^[[:space:]]+|[[:space:]]+$/, "", rhs)
                print rhs
                exit
            }
        }
    ' "$WG_CONFIG_PATH")"

    if [ -n "$mtu" ]; then
        cmd ip link set mtu "$mtu" up dev "$INTERFACE_NAME"
    else
        cmd ip link set up dev "$INTERFACE_NAME"
    fi

    run_hooks PostUp
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

echo "starting CoreDNS: $COREDNS_CONFIG"
cmd /usr/local/bin/coredns -conf "$COREDNS_CONFIG" &
COREDNS_PID=$!

echo "bringing up WireGuard via boringtun: $WG_CONFIG_PATH"
configure_interface
echo "starting ssl-proxy"
"$PROXY_BIN" &
PROXY_PID=$!
wait "$PROXY_PID"
