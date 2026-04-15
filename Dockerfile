FROM coredns/coredns:1.12.3 AS coredns

FROM rust:1.86-slim AS builder
ARG CARGO_FEATURES=""
WORKDIR /app

# Install build dependencies required for openssl-sys
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

COPY src ./src
COPY Cargo.toml Cargo.lock ./
RUN if [ -n "$CARGO_FEATURES" ]; then \
      OCI_LIB_DIR=/opt/instantclient cargo build --release --features "$CARGO_FEATURES"; \
    else \
      cargo build --release; \
    fi

# debian:bookworm-slim is required (not alpine) because Oracle Instant Client
# depends on libaio1, which is glibc-only and unavailable on musl/alpine.
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y \
        bash \
        ca-certificates \
        curl \
        iproute2 \
        iptables \
        kmod \
        libaio1 \
        openssl \
        procps \
        wireguard-tools \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=coredns /coredns /usr/local/bin/coredns
COPY --from=builder /app/target/release/ssl-proxy .
COPY static ./static
# Oracle Instant Client libs (empty unless oracle-db feature was built with lib-linux/)
RUN mkdir -p /app/lib
# Wallet directory is optional; create empty dir if not present
RUN mkdir -p /app/wallet
COPY docker/wg_up.sh /usr/local/bin/wg_up.sh
COPY docker/entrypoint.sh /usr/local/bin/start-proxy-wg
RUN ldconfig && chmod +x /usr/local/bin/start-proxy-wg /usr/local/bin/wg_up.sh \
 && groupadd -r proxyuser && useradd -r -g proxyuser proxyuser \
 && chown -R proxyuser:proxyuser /app /usr/local/bin/start-proxy-wg /usr/local/bin/wg_up.sh \
 && setcap cap_net_admin+eip /usr/local/bin/coredns \
 && setcap cap_net_admin+eip /app/ssl-proxy
ENV LD_LIBRARY_PATH=/app/lib \
    WG_CONFIG_PATH=/run/wireguard/wg0.conf \
    WG_TEMPLATE_PATH=/config/templates/server.conf \
    WG_SUDO=1 \
    COREDNS_CONFIG=/config/coredns/Corefile
EXPOSE 3000/tcp 3001/tcp 3002/tcp 443/udp
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:3002/health || exit 1
# Running as root temporarily until entrypoint can drop privileges after network setup
# USER proxyuser
ENTRYPOINT ["/usr/local/bin/start-proxy-wg"]
