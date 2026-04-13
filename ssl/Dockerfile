FROM coredns/coredns:1.12.3 AS coredns

FROM rust:1.86-slim AS builder
ARG CARGO_FEATURES="oracle-db"
WORKDIR /app
COPY lib-linux /opt/instantclient
COPY Cargo.toml Cargo.lock ./
RUN mkdir src \
 && echo "fn main(){}" > src/main.rs \
 && OCI_LIB_DIR=/opt/instantclient cargo build --release --features "$CARGO_FEATURES" \
 && rm -rf src
COPY src ./src
RUN touch src/main.rs \
 && OCI_LIB_DIR=/opt/instantclient cargo build --release --features "$CARGO_FEATURES"
RUN cargo install boringtun-cli --version 0.7.0 --locked --root /opt/boringtun

# debian:bookworm-slim is required (not alpine) because Oracle Instant Client
# depends on libaio1, which is glibc-only and unavailable on musl/alpine.
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y \
        bash \
        ca-certificates \
        curl \
        iproute2 \
        iptables \
        libaio1 \
        wireguard-tools \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=coredns /coredns /usr/local/bin/coredns
COPY --from=builder /app/target/release/ssl-proxy .
COPY --from=builder /opt/boringtun/bin/boringtun-cli /usr/local/bin/boringtun-cli
COPY static ./static
COPY --from=builder /opt/instantclient /app/lib
COPY wallet ./wallet
COPY docker/entrypoint.sh /usr/local/bin/start-proxy-wg
RUN ldconfig && chmod +x /usr/local/bin/start-proxy-wg \
 && groupadd -r proxyuser && useradd -r -g proxyuser proxyuser \
 && setcap cap_net_admin+eip /usr/local/bin/boringtun-cli \
 && setcap cap_net_admin+eip /usr/local/bin/coredns \
 && chown -R proxyuser:proxyuser /app /usr/local/bin/start-proxy-wg
ENV LD_LIBRARY_PATH=/app/lib \
    WG_CONFIG_PATH=/config/wg_confs/wg0.conf \
    WG_SUDO=1 \
    COREDNS_CONFIG=/config/coredns/Corefile
EXPOSE 3000/tcp 3001/tcp 443/udp
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:3000/health || exit 1
USER proxyuser
ENTRYPOINT ["/usr/local/bin/start-proxy-wg"]
