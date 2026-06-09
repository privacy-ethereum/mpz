#!/bin/bash
# Build the in-browser profiler: compile cost-explorer to wasm32-unknown-unknown
# and generate the `--target web` JS bindings in pkg/.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$ROOT"

# The wasm-bindgen CLI must exactly match the wasm-bindgen crate version.
CRATE_VER="$(cargo tree -p cost-explorer -i wasm-bindgen --target wasm32-unknown-unknown 2>/dev/null \
    | grep -oE 'wasm-bindgen v[0-9.]+' | head -1 | sed 's/wasm-bindgen v//')"
CLI_VER="$(wasm-bindgen --version 2>/dev/null | awk '{print $2}' || echo none)"
if [ "$CLI_VER" != "$CRATE_VER" ]; then
    echo "wasm-bindgen CLI is '$CLI_VER', crate needs '$CRATE_VER' — installing..."
    cargo install -f wasm-bindgen-cli --version "$CRATE_VER"
fi

echo "Building cost-explorer for wasm32-unknown-unknown..."
cargo build -p cost-explorer --target wasm32-unknown-unknown --release

echo "Generating JS bindings (--target web)..."
wasm-bindgen --target web --no-typescript \
    --out-dir "$SCRIPT_DIR/pkg" \
    "$ROOT/target/wasm32-unknown-unknown/release/cost_explorer.wasm"

echo "Done. Output in $SCRIPT_DIR/pkg/"
ls -lh "$SCRIPT_DIR/pkg/"
