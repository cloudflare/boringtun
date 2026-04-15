# SSL Proxy

A privacy-first WireGuard gateway with transparent policy enforcement, legacy opt-in explicit proxy support, and Oracle database analytics.

## Features

- **WireGuard VPN** — primary client ingress for encrypted full-tunnel transport
- **Transparent Proxy** — intercepts WireGuard traffic via `iptables REDIRECT` without client proxy configuration
- **HTTP/HTTPS Forward Proxy** — legacy opt-in explicit proxy mode for controlled debugging
- **TLS Interception** — SNI-based hostname extraction without decryption
- **Traffic Obfuscation** — header normalization profiles to mimic standard browser traffic
- **Blocklist Engine** — domain-based filtering with heuristic threat scoring
- **Dashboard & WebSocket API** — real-time stats, host snapshots, and event streaming
- **Oracle DB Integration** — optional audit event persistence (feature-gated behind `oracle-db`)
- **QUIC/H3 Support** — secondary explicit-proxy transport when that mode is enabled
- **CoreDNS** — embedded VPN resolver with encrypted upstream DNS

## Quick Start

### Prerequisites

- Docker and Docker Compose

### Running

```bash
# Start the privacy-first WireGuard stack
docker compose up -d --build

# Verify the internal admin surface locally
curl -i http://127.0.0.1:3002/health

# Or use the setup script (installs Docker if needed)
sudo ./setup-ubuntu.sh
```

Supported client onboarding is WireGuard profile import from `config/peer1/peer1.conf`. Manual Wi-Fi or MDM HTTP proxy configuration is a legacy debugging path and is not privacy-preserving.
The container renders its runtime server config to `/run/wireguard/wg0.conf` from `config/templates/server.conf`, the server keypair under `config/server/`, and the checked-in peer metadata.
If `config/server/privatekey-server` is missing on first boot, the entrypoint generates a new server keypair and syncs the derived public key into `config/server/publickey-server` and `config/peer1/peer1.conf`.

```mermaid
flowchart LR
    C["Client imports `peer1.conf`\n`10.13.13.2/32`\nDNS `10.13.13.1`"] -->|"WireGuard UDP `443`"| H["Docker host endpoint\n`192.168.1.166:443`"]
    H --> E["Container entrypoint renders\n`/run/wireguard/wg0.conf`\nand runs `wg-quick up`"]
    E --> W["`wg0`\nserver `10.13.13.1/24`"]
    W --> D["CoreDNS\nserves VPN DNS on `10.13.13.1`\nforwards upstream via Cloudflare DoT"]
    W --> R["`iptables REDIRECT`\nTCP `80/443` -> `3001`"]
    R --> T["Transparent proxy\n`src/tunnel.rs`\nresolves upstream with DoH"]
    T --> O["Origin servers on the Internet"]
```

### Building from Source

```bash
# Build the binary
cargo build --release

# Build with Oracle DB support
cargo build --release --features oracle-db
```

### Testing

```bash
cargo test
```

## Project Structure

```text
├── src/                  # Rust source code
│   ├── main.rs           # Application entry point
│   ├── proxy.rs          # Legacy explicit HTTP/HTTPS proxy handler
│   ├── tunnel.rs         # CONNECT tunnel + transparent WireGuard proxy
│   ├── blocklist.rs      # Domain blocklist engine
│   ├── obfuscation.rs    # Traffic obfuscation profiles
│   ├── dashboard.rs      # REST API & WebSocket endpoints
│   ├── quic.rs           # QUIC/H3 explicit-proxy listener
│   ├── config.rs         # Environment-based configuration
│   ├── state.rs          # Shared application state
│   └── db.rs             # Oracle DB integration (optional)
├── config/               # WireGuard + CoreDNS configuration
├── docker/               # Container entrypoint scripts
├── static/               # Dashboard web assets
├── sql/                  # Database schema + migrations
├── Dockerfile            # Container build definition
└── docker-compose.yaml   # Container orchestration
```

## Configuration

All configuration is via environment variables. Key settings:

| Variable | Default | Description |
|----------|---------|-------------|
| `PROXY_PORT` | `3000` | Legacy explicit proxy listener port when `EXPLICIT_PROXY_ENABLED=true` |
| `TPROXY_PORT` | `3001` | Internal transparent proxy listener for redirected WireGuard traffic |
| `WG_PORT` | `443` | WireGuard UDP port |
| `ADMIN_PORT` | `3002` | Internal admin API and dashboard port |
| `EXPLICIT_PROXY_ENABLED` | `false` | Enables legacy explicit proxy listeners for debugging or controlled local use |
| `WG_CONFIG_PATH` | `/run/wireguard/wg0.conf` | Rendered WireGuard runtime config inside the container |
| `RUST_LOG` | — | Log level filter |
| `LOG_FORMAT` | `text` | `json` for structured logging |
| `TLS_CERT_PATH` | — | TLS certificate for explicit proxy listener |
| `TLS_KEY_PATH` | — | TLS private key for explicit proxy listener |
| `ADMIN_API_KEY` | — | API key for admin endpoints |
| `CORS_ALLOWED_ORIGINS` | — | Comma-separated allowed origins |

## WireGuard Config Layout

- `config/server/privatekey-server` is optional on first boot. If it is missing, the container generates a new server keypair automatically.
- The generated or existing server public key is written to `config/server/publickey-server`.
- The compose stack renders the server interface config from `config/templates/server.conf` at startup.
- The checked-in peer config `config/peer1/peer1.conf` uses tunnel IP `10.13.13.2/32`, DNS `10.13.13.1`, and endpoint `192.168.1.166:443`.
- When a new server keypair is generated, redistribute the updated `config/peer1/peer1.conf` to clients before connecting.
- The peer endpoint must be the Docker host’s LAN or public IP, not the container’s bridge IP.

## Legacy Explicit Proxy Mode

Explicit proxy support remains available for controlled debugging, but it is disabled by default and is not the recommended client path.

```bash
EXPLICIT_PROXY_ENABLED=true \
PROXY_USERNAME=debug-user \
PROXY_PASSWORD=debug-pass \
docker compose up -d --build
```

If this mode is enabled without TLS, the client-to-proxy `CONNECT host:443` request is plaintext and will expose destination hostnames on that leg.

## License

The project is licensed under the [3-Clause BSD License](https://opensource.org/licenses/BSD-3-Clause).

---
<sub><sub><sub><sub>WireGuard is a registered trademark of Jason A. Donenfeld.</sub></sub></sub></sub>
