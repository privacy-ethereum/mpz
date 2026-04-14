#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
PROGRAMS_DIR="$WORKSPACE_ROOT/crates/profile-bench-programs"
OUT_DIR="$SCRIPT_DIR/wasm"

echo "Building profile-bench-programs for wasm32-unknown-unknown..."
cargo +nightly build \
    --manifest-path "$PROGRAMS_DIR/Cargo.toml" \
    --target wasm32-unknown-unknown \
    --profile wasm \
    -Zbuild-std=std,panic_abort

mkdir -p "$OUT_DIR"
cp "$PROGRAMS_DIR/target/wasm32-unknown-unknown/wasm/profile_bench_programs.wasm" "$OUT_DIR/"

echo "Done. Output: $OUT_DIR/profile_bench_programs.wasm"
ls -lh "$OUT_DIR/profile_bench_programs.wasm"
