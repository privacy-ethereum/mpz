#!/bin/sh

# This script is used to run checks before committing changes to the repository.
# It is a good approximation of what CI will do.

# Fail if any command fails
set -e

# Check formatting
cargo +nightly fmt --check --all

# Check clippy
cargo +nightly clippy --all-targets --all-features --locked -- -D warnings
