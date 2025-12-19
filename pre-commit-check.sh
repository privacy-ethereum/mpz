#!/bin/sh

# This script is used to run checks before committing changes to the repository.
# It is a good approximation of what CI will do.

# Fail if any command fails
set -e

# Check formatting
cargo +nightly fmt --check --all

# Check clippy (excluding wasm-bench which requires wasm32 target)
cargo +nightly clippy --workspace --exclude mpz-wasm-bench --all-targets --all-features --locked -- -D warnings

# To check wasm-bench lib, run separately with wasm32 target (from crates/wasm-bench/):
# cargo +nightly clippy --lib --target wasm32-unknown-unknown -- -D warnings
