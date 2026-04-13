#!/usr/bin/env bash
set -euo pipefail

# WireGuard interface setup script
# Extracted from entrypoint.sh for testability

cmd() {
    echo "[#] $*"
    "$@"
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

    # Apply WireGuard configuration via UAPI (sets ListenPort and other interface parameters)
    # Command: wg setconf <interface> <(wg-quick strip <config_file>)
    # This configures the listening port (WG_PORT) through the UAPI socket
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