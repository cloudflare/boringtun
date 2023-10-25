# Build Stage
FROM --platform=linux/amd64 ubuntu:20.04 as builder

## Install build dependencies.
# Update default packages
RUN apt-get update

# Get Ubuntu packages
RUN apt-get install -y build-essential curl sudo

# Get Rust
RUN curl https://sh.rustup.rs -sSf | bash -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

## Add source code to the build stage.
ADD . /boringtun
WORKDIR /boringtun/boringtun

# Configure Rust and build fuzz file
RUN rustup default nightly
RUN cargo install cargo-fuzz
RUN cargo fuzz build --target x86_64-unknown-linux-gnu new_mac

# Package Stage
FROM --platform=linux/amd64 ubuntu:20.04
COPY --from=builder /boringtun/boringtun/fuzz/target/x86_64-unknown-linux-gnu/release /
