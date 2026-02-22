# Run everything: format, lint, test
check: fmt lint test

# Run tests
test:
    cargo test

# Run clippy
lint:
    cargo clippy -- -D warnings

# Format code
fmt:
    cargo fmt

# Run the server
run *ARGS:
    cargo run -- {{ARGS}}

# Run in dev mode
dev:
    cargo run -- --dev-mode

# Run benchmarks
bench:
    cargo bench
