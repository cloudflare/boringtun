# SSL Proxy

A high-performance Rust HTTP/HTTPS forward proxy with transparent TCP/TLS interception, WireGuard VPN integration, and Oracle database analytics.

## Features

- **HTTP/HTTPS Forward Proxy** — full CONNECT tunnel support with SNI sniffing
- **Transparent Proxy** — intercepts traffic via `iptables REDIRECT` without client configuration
- **WireGuard VPN** — kernel WireGuard module integration for encrypted tunneling
- **TLS Interception** — SNI-based hostname extraction without decryption
- **Traffic Obfuscation** — header normalization profiles to mimic standard browser traffic
- **Blocklist Engine** — domain-based filtering with heuristic threat scoring
- **Dashboard & WebSocket API** — real-time stats, host snapshots, and event streaming
- **Oracle DB Integration** — optional audit event persistence (feature-gated behind `oracle-db`)
- **QUIC/H3 Support** — HTTP/3 listener for modern clients
- **CoreDNS** — embedded DNS resolver for the VPN network

## Quick Start

### Prerequisites

- Docker and Docker Compose
- WireGuard configuration in `config/wg_confs/wg0.conf`

### Running

```bash
# Start the proxy stack
docker compose up -d --build

# Or use the setup script (installs Docker if needed)
sudo ./setup-ubuntu.sh
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

```
├── src/                  # Rust source code
│   ├── main.rs           # Application entry point
│   ├── proxy.rs          # HTTP/HTTPS forward proxy handler
│   ├── tunnel.rs         # CONNECT tunnel & transparent proxy
│   ├── blocklist.rs      # Domain blocklist engine
│   ├── obfuscation.rs    # Traffic obfuscation profiles
│   ├── dashboard.rs      # REST API & WebSocket endpoints
│   ├── quic.rs           # QUIC/H3 listener
│   ├── config.rs         # Environment-based configuration
│   ├── state.rs          # Shared application state
│   └── db.rs             # Oracle DB integration (optional)
├── config/               # WireGuard & CoreDNS configuration
├── docker/               # Container entrypoint scripts
├── static/               # Dashboard web assets
├── sql/                  # Database schema & migrations
├── Dockerfile            # Container build definition
└── docker-compose.yaml   # Container orchestration
```

## Configuration

All configuration is via environment variables. Key settings:

| Variable | Default | Description |
|----------|---------|-------------|
| `PROXY_PORT` | `3000` | Dashboard + REST API port |
| `TPROXY_PORT` | `3001` | Transparent proxy port |
| `WG_PORT` | `443` | WireGuard UDP port |
| `WG_CONFIG_PATH` | `/config/wg_confs/wg0.conf` | WireGuard config file path |
| `RUST_LOG` | — | Log level filter |
| `LOG_FORMAT` | `text` | `json` for structured logging |
| `TLS_CERT_PATH` | — | TLS certificate for proxy listener |
| `TLS_KEY_PATH` | — | TLS private key for proxy listener |
| `ADMIN_API_KEY` | — | API key for admin endpoints |
| `CORS_ALLOWED_ORIGINS` | — | Comma-separated allowed origins |

## License

The project is licensed under the [3-Clause BSD License](https://opensource.org/licenses/BSD-3-Clause).

---
<sub><sub><sub><sub>WireGuard is a registered trademark of Jason A. Donenfeld.</sub></sub></sub></sub>
