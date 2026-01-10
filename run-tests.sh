#!/bin/bash
set -e

echo "=== BORINGTUN COMPREHENSIVE TEST EXECUTION ==="
echo "Date: $(date)"
echo "Rust version: $(rustc --version)"
echo "Cargo version: $(cargo --version)"
echo

# Setup comprehensive test environment
echo "🔧 Setting up comprehensive test environment..."

# Setup TUN interface
sudo modprobe tun || echo "TUN module already loaded or not needed"
sudo mkdir -p /dev/net
sudo mknod /dev/net/tun c 10 200 2>/dev/null || echo "TUN device already exists"
sudo chmod 666 /dev/net/tun

# Setup WireGuard runtime directory
sudo mkdir -p /var/run/wireguard
sudo chown -R testuser:testuser /var/run/wireguard
sudo chmod 755 /var/run/wireguard

# Enable IP forwarding for network tests
echo "net.ipv4.ip_forward=1" | sudo tee -a /etc/sysctl.conf >/dev/null
echo "net.ipv6.conf.all.forwarding=1" | sudo tee -a /etc/sysctl.conf >/dev/null
sudo sysctl -p >/dev/null 2>&1

# Start Docker daemon for container tests (if available)
if command -v dockerd >/dev/null 2>&1; then
    sudo dockerd --storage-driver=vfs >/dev/null 2>&1 &
    DOCKER_PID=$!
    sleep 2
    echo "Docker daemon started for container-based tests"
fi

echo "✅ Comprehensive test environment setup complete"
echo

# Build tests first
echo "🔨 Building tests with device feature..."
cd /app/boringtun
cargo build --tests --features device
echo "✅ All tests built successfully"
echo

# Count tests
echo "📊 Counting tests..."
UNIT_TESTS=$(find src -name "*.rs" -exec grep -c "#\[test\]" {} \; | paste -sd+ - | bc)
INTEGRATION_TESTS=$(find tests -name "*.rs" -exec grep -c "#\[test\]" {} \; | paste -sd+ - | bc) 
PROP_TESTS=$(find tests -name "*.rs" -exec grep -c "prop_\|proptest!" {} \; | paste -sd+ - | bc)

echo "Unit tests found: $UNIT_TESTS"
echo "Integration tests found: $INTEGRATION_TESTS" 
echo "Property-based tests found: $PROP_TESTS"
echo "Total tests: $((UNIT_TESTS + INTEGRATION_TESTS))"
echo

# Run unit tests with coverage (including previously ignored ones)
echo "🧪 Running all unit tests with coverage measurement..."
cargo llvm-cov --features device --lib --lcov --output-path coverage-unit.lcov --ignore-run-fail -- --include-ignored || {
    echo "⚠️ Some unit tests failed, capturing what we can"
}
echo

# Run integration tests with coverage (including previously ignored ones)
echo "🔬 Running all integration tests with coverage measurement..."
cargo llvm-cov --features device --tests --lcov --output-path coverage-integration.lcov --ignore-run-fail -- --include-ignored || {
    echo "⚠️ Some integration tests failed, capturing what we can"
}
echo

# Attempt to run just integration_tests module separately for better isolation
echo "🌐 Running network integration tests separately..."
cargo test --features device --lib device::integration_tests:: --include-ignored --nocapture || {
    echo "⚠️ Network integration tests require additional setup - checking individual test requirements"
}

# Check specific test requirements
echo "🔍 Testing individual integration test requirements..."
sudo ip tuntap add mode tun name utun100 || echo "TUN interface creation test"
sudo ip link show utun100 >/dev/null 2>&1 && echo "✅ TUN interface utun100 available" || echo "⚠️ TUN interface creation failed"
sudo ip tuntap del mode tun name utun100 2>/dev/null || true

# Test Docker availability for peer container tests
if command -v docker >/dev/null 2>&1; then
    echo "✅ Docker available for peer container tests"
    docker ps >/dev/null 2>&1 && echo "✅ Docker daemon accessible" || echo "⚠️ Docker daemon not running"
else
    echo "⚠️ Docker not available for peer container tests"
fi
echo

# Generate combined coverage report
echo "📊 Generating comprehensive coverage reports..."
cargo llvm-cov --features device --all-targets --html --output-dir coverage-html --ignore-run-fail || {
    echo "⚠️ Generating partial coverage report"
    cargo llvm-cov --features device --no-run --html --output-dir coverage-html
}
echo

# Generate detailed coverage summary
echo "📈 Generating detailed test and coverage summary..."
{
    echo "=== BORINGTUN TEST EXECUTION REPORT ==="
    echo "Generated: $(date)"
    echo "Environment: Docker container with TUN interface support"
    echo
    echo "=== TEST COUNT SUMMARY ==="
    echo "Unit tests: $UNIT_TESTS"
    echo "Integration tests: $INTEGRATION_TESTS"
    echo "Property-based tests: $PROP_TESTS"
    echo "Total tests: $((UNIT_TESTS + INTEGRATION_TESTS))"
    echo
    echo "=== TEST FILES ==="
    find tests -name "*.rs" -exec basename {} \;
    echo
    echo "=== COVERAGE ANALYSIS ==="
    
    # Extract coverage from LCOV files if available
    if [ -f coverage-unit.lcov ]; then
        echo "Unit test coverage data generated: $(wc -l < coverage-unit.lcov) lines"
    fi
    
    if [ -f coverage-integration.lcov ]; then
        echo "Integration test coverage data generated: $(wc -l < coverage-integration.lcov) lines"
    fi
    
    # Try to extract coverage percentage from HTML report
    if [ -f coverage-html/index.html ]; then
        COVERAGE_PERCENT=$(grep -o "[0-9]*\.[0-9]*%" coverage-html/index.html | head -1 || echo "N/A")
        echo "Overall coverage percentage: $COVERAGE_PERCENT"
    else
        echo "HTML coverage report not generated"
    fi
    
    echo
    echo "=== MODULE BREAKDOWN ==="
    echo "Source files with tests:"
    find src -name "*.rs" -exec sh -c 'count=$(grep -c "#\[test\]" "$1"); if [ $count -gt 0 ]; then echo "  $(echo "$1" | sed "s|src/||"): $count tests"; fi' _ {} \;
    
} > /app/test-summary.txt

echo "✅ Test execution complete!"
echo
echo "📋 RESULTS SUMMARY:"
cat /app/test-summary.txt

echo
echo "📁 Generated files:"
echo "  • Detailed report: /app/test-summary.txt"
echo "  • Coverage HTML: /app/boringtun/coverage-html/index.html" 
echo "  • Unit coverage: /app/boringtun/coverage-unit.lcov"
echo "  • Integration coverage: /app/boringtun/coverage-integration.lcov"
