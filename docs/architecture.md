# System Architecture

## Traffic Flow Diagram

```mermaid
flowchart LR
    C[WireGuard Client] -->|UDP 443| WG[WireGuard Kernel Module]
    WG --> TUN[TUN Interface wg0]
    TUN --> DNS[CoreDNS Resolver]
    DNS --> PROXY[ssl-proxy]
    PROXY -->|Normalized Traffic| ORIGIN[Upstream Origin Servers]
    
    style C fill:#6366f1,color:white
    style WG fill:#10b981,color:white
    style DNS fill:#f59e0b,color:white
    style PROXY fill:#ef4444,color:white
    style ORIGIN fill:#8b5cf6,color:white
```

## Port Assignments

| Service       | Port  | Protocol | Purpose                          |
|---------------|-------|----------|----------------------------------|
| WireGuard VPN | 443   | UDP      | External tunnel endpoint         |
| Admin API     | 3000  | TCP      | Health checks, metrics, status   |
| Dashboard     | 3001  | TCP      | Management web interface         |

## Component Startup Order

1.  **CoreDNS** - Initializes DNS resolver with filtering rules
2.  **WireGuard** - Creates `wg0` TUN interface via kernel module, establishes encryption layer
3.  **ssl-proxy** - Starts HTTP/S interception, obfuscation engine, and audit logging

## Obfuscation Profiles

Traffic is normalized per domain classification to prevent fingerprinting:

### Active Profiles:
- **fox-news**: Fox News domain family
- **fox-sports**: Fox Sports domain family

### Applied Modifications:

**Request Headers:**
✅ Removes `X-Forwarded-For`, `Via`, `Forwarded` proxy headers
✅ Strips `DNT`, `Sec-GPC` privacy signals
✅ Normalizes User-Agent to configured standard value

**Response Headers:**
✅ Removes `X-Cache`, `X-Edge-IP`, `X-Served-By` CDN leak headers
✅ Preserves security headers (CSP, HSTS)

Domain matching supports wildcard subdomains and is case-insensitive.

---

## Quick Start

1.  **Setup secrets:**
    ```bash
    mkdir -p secrets
    echo "your-oracle-password" > secrets/oracle_password.txt
    ```

2.  **Start stack:**
    ```bash
    docker compose up -d
    ```

3.  **WireGuard Client Configuration:**
    Use the generated client config at `config/peer1/peer1.conf`. This configuration uses standard WireGuard parameters and can be imported directly into any WireGuard client application.

    Verify connection:
    ```bash
    curl -i http://10.0.0.1:3000/health
