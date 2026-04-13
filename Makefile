.PHONY: build test docker lint clean

# Build all crates in the workspace
build:
	cargo build --release --workspace

# Run tests for all crates in the workspace
test:
	cargo test --workspace

# Build the Docker image for ssl-proxy
docker:
	cd ssl && docker build -t ssl-proxy .

# Run clippy lints
lint:
	cargo clippy --workspace -- -D warnings

# Clean build artifacts
clean:
	cargo clean