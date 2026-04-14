.PHONY: build test docker lint clean

# Build the ssl-proxy binary
build:
	cargo build --release

# Run tests
test:
	cargo test

# Build the Docker image for ssl-proxy
docker:
	docker compose build

# Run clippy lints
lint:
	cargo clippy -- -D warnings

# Clean build artifacts
clean:
	cargo clean
