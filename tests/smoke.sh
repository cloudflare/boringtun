#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

echo "🧪 Starting SSL Proxy smoke test"
CURRENT_VCS_REF="$(git rev-parse --short HEAD)"
CURRENT_BUILD_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

cleanup() {
    echo "🧹 Cleaning up"
    docker compose down -v --remove-orphans >/dev/null 2>&1 || true
}

restore_template() {
    if [ -n "${TEMPLATE_BACKUP_PATH:-}" ] && [ -f "${TEMPLATE_BACKUP_PATH:-}" ]; then
        mv "$TEMPLATE_BACKUP_PATH" config/templates/server.conf
        TEMPLATE_BACKUP_PATH=""
    fi
}

cleanup_all() {
    restore_template
    cleanup
}

trap cleanup_all EXIT INT TERM

wait_for_health() {
    echo "⏳ Waiting for admin liveness and WireGuard health (timeout 60s)"
    for i in {1..60}; do
        if curl -f -s http://127.0.0.1:3002/health >/dev/null 2>&1 \
            && docker compose exec -T ssl-proxy wg show wg0 >/dev/null 2>&1; then
            echo "✅ Admin liveness and WireGuard checks passed"
            return 0
        fi
        if [ "$i" = 60 ]; then
            echo "❌ Timeout waiting for service to become healthy"
            docker compose logs
            exit 1
        fi
        sleep 1
    done
}

expected_ready_status() {
    if [ -f wallet/tnsnames.ora ] \
        && grep -Eiq '^[[:space:]]*mainerc_tp[[:space:]]*=' wallet/tnsnames.ora \
        && { [ -f wallet/cwallet.sso ] || [ -f wallet/ewallet.p12 ] || [ -f wallet/sqlnet.ora ]; }; then
        echo "200"
    else
        echo "503"
    fi
}

assert_ready_status() {
    local expected="$1"
    local ready_body
    local ready_code

    ready_body="$(mktemp)"
    ready_code="$(curl -s -o "$ready_body" -w "%{http_code}" http://127.0.0.1:3002/ready || true)"

    if [ "$ready_code" != "$expected" ]; then
        echo "❌ Unexpected /ready status: expected $expected got $ready_code"
        echo "Body:"
        cat "$ready_body"
        rm -f "$ready_body"
        docker compose logs
        exit 1
    fi

    echo "✅ /ready returned expected status $ready_code"
    rm -f "$ready_body"
}

assert_wg_interface() {
    local wg_output

    echo "🔍 Checking WireGuard interface status"
    wg_output="$(docker compose exec -T ssl-proxy wg show wg0)"
    echo "$wg_output"

    if echo "$wg_output" | grep -q "interface: wg0"; then
        echo "✅ WireGuard interface is active"
    else
        echo "❌ WireGuard interface output was unexpected"
        exit 1
    fi
}

assert_unique_server_address() {
    local count

    count="$(docker compose exec -T ssl-proxy sh -lc "grep -c '^Address = 10.13.13.1/24$' /run/wireguard/wg0.conf")"
    if [ "$count" -ne 1 ]; then
        echo "❌ Expected exactly one rendered server address, found $count"
        docker compose exec -T ssl-proxy sh -lc 'nl -ba /run/wireguard/wg0.conf'
        exit 1
    fi

    if docker compose logs ssl-proxy | grep -q "Address already assigned"; then
        echo "❌ Duplicate address regression detected in container logs"
        docker compose logs ssl-proxy
        exit 1
    fi

    echo "✅ Rendered WireGuard config contains one unique server address"
}

assert_startup_fingerprint() {
    local raw_address="$1"
    local normalized_address="$2"
    local logs

    logs="$(docker compose logs ssl-proxy)"

    if ! echo "$logs" | grep -Eq "\\[startup-fingerprint\\] revision=${CURRENT_VCS_REF} build_date=.* entrypoint_sha256=[0-9a-f]{64}"; then
        echo "❌ Startup fingerprint revision or entrypoint checksum missing from logs"
        echo "$logs"
        exit 1
    fi

    if ! echo "$logs" | grep -Fq "[startup-fingerprint] raw_wg_server_address=${raw_address} normalized_wg_server_address=${normalized_address} wg_config_path=/run/wireguard/wg0.conf"; then
        echo "❌ Startup fingerprint address normalization details missing from logs"
        echo "$logs"
        exit 1
    fi

    echo "✅ Startup fingerprint is present in container logs"
}

inject_duplicate_template_address() {
    TEMPLATE_BACKUP_PATH="$(mktemp)"
    cp config/templates/server.conf "$TEMPLATE_BACKUP_PATH"
    python3 - <<'PY'
from pathlib import Path
path = Path("config/templates/server.conf")
lines = path.read_text().splitlines()
for idx, line in enumerate(lines):
    if line.strip() == "Address = __WG_SERVER_ADDRESS__":
        lines.insert(idx + 1, line)
        break
else:
    raise SystemExit("missing Address placeholder in config/templates/server.conf")
path.write_text("\n".join(lines) + "\n")
PY
}

run_default_scenario() {
    echo "🚀 Bringing up default stack"
    cleanup
    VCS_REF="$CURRENT_VCS_REF" BUILD_DATE="$CURRENT_BUILD_DATE" docker compose up -d --build
    wait_for_health
    assert_ready_status "$(expected_ready_status)"
    assert_startup_fingerprint "10.13.13.1/24" "10.13.13.1/24"
    assert_wg_interface
    assert_unique_server_address
}

run_duplicate_address_scenario() {
    echo "🚀 Re-running with duplicated WG_SERVER_ADDRESS input"
    cleanup
    VCS_REF="$CURRENT_VCS_REF" BUILD_DATE="$CURRENT_BUILD_DATE" \
        WG_SERVER_ADDRESS="10.13.13.1/24,10.13.13.1/24" docker compose up -d --build
    wait_for_health
    assert_ready_status "$(expected_ready_status)"
    assert_startup_fingerprint "10.13.13.1/24,10.13.13.1/24" "10.13.13.1/24"
    assert_wg_interface
    assert_unique_server_address
}

run_duplicate_template_scenario() {
    echo "🚀 Re-running with drifted template containing duplicate Address lines"
    cleanup
    inject_duplicate_template_address
    VCS_REF="$CURRENT_VCS_REF" BUILD_DATE="$CURRENT_BUILD_DATE" docker compose up -d --build
    wait_for_health
    assert_ready_status "$(expected_ready_status)"
    assert_startup_fingerprint "10.13.13.1/24" "10.13.13.1/24"
    assert_wg_interface
    assert_unique_server_address
    restore_template
}

run_default_scenario
run_duplicate_address_scenario
run_duplicate_template_scenario

echo ""
echo "ℹ️ Skipping explicit proxy request test because default compose uses transparent-only mode."
echo "✅ All smoke tests passed successfully!"
