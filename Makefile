.PHONY: fmt lint test build run run-json

fmt:
	cargo fmt --all

lint:
	cargo clippy --all-targets --all-features -- -D warnings

test:
	cargo test --all-targets

build:
	cargo build --release

run:
	cargo run -- --format text

run-json:
	cargo run -- --format json
