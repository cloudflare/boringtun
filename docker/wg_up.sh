#!/usr/bin/env bash
set -euo pipefail

# WireGuard interface setup script (kernel module)
# Extracted from entrypoint.sh for testability

cmd() {
    echo "[#] $*"
    "$@"
}

configure_interface() {
    local mtu

    # Load the WireGuard kernel module (ignore failure — it may already be loaded
    # or built-in to the kernel)
    modprobe wireguard 2>/dev/null || true

    # Create the WireGuard interface using the kernel module
    cmd ip link add dev "$INTERFACE_NAME" type wireguard

    if ! ip link show dev "$INTERFACE_NAME" >/dev/null 2>&1; then
        echo "WireGuard interface $INTERFACE_NAME failed to appear" >&2
        exit 1
    fi

    # Apply WireGuard configuration via wg setconf (sets ListenPort, keys, peers)
    cmd wg setconf "$INTERFACE_NAME" <(wg-quick strip "$WG_CONFIG_PATH")

    # Wait for WireGuard interface to report a listening port before starting ssl-proxy
    for _ in $(seq 1 50); do
        if wg show "$INTERFACE_NAME" 2>/dev/null | grep -q "listening port"; then
            break
        fi
        sleep 0.1
    done
    if ! wg show "$INTERFACE_NAME" 2>/dev/null | grep -q "listening port"; then
        echo "WireGuard interface $INTERFACE_NAME failed to start listening" >&2
        exit 1
    fi

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
