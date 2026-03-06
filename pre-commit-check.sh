#!/bin/sh

# This script is used to run checks before committing changes to the repository.
# It is a good approximation of what CI will do.

# Fail if any command fails
set -e

# Check formatting
cargo +nightly fmt --check --all

# Check clippy
cargo +nightly clippy --workspace --exclude mpz-wasm-bench --all-targets --all-features -- -D warnings

# Check clippy on wasm-bench (requires wasm32 target: rustup target add wasm32-unknown-unknown)
(cd crates/wasm-bench && cargo +nightly clippy --lib --target wasm32-unknown-unknown -- -D warnings)
