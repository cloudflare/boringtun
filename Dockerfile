FROM rust:alpine as builder

RUN apk add linux-headers musl-dev

WORKDIR /boringtun

COPY Cargo.toml Cargo.lock ./
COPY src/ ./src

RUN cargo build --release

FROM alpine:latest

# Just install `wg` CLI
RUN apk add --no-cache wireguard-tools

COPY --from=builder /boringtun/target/release/boringtun /usr/bin/boringtun

