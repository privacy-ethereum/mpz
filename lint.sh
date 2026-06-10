#!/bin/sh

# Formatting and lint checks for the workspace. CI runs this same script
# (see .github/workflows/rust.yml), so passing locally means the Rustfmt
# and Clippy job will pass too.

# Fail if any command fails
set -e

# Check formatting
cargo +nightly fmt --check --all

# Check clippy
cargo +nightly clippy --workspace --all-targets --all-features -- -D warnings
