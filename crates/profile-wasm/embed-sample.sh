#!/bin/bash
# Build the sample guest (profile-bench-programs) to wasm and embed it as base64
# in sample-module.js, so the page loads and profiles it by default.
# Requires the nightly toolchain (for -Zbuild-std) and the
# wasm32-unknown-unknown target.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
GUEST_DIR="$ROOT/crates/profile-bench-programs"

echo "Building sample guest for wasm32-unknown-unknown..."
# Build from the crate dir so cargo discovers its .cargo/config.toml (memory
# limits + the __heap_base export).
( cd "$GUEST_DIR" && cargo +nightly build \
    --target wasm32-unknown-unknown \
    --profile wasm \
    -Zbuild-std=std,panic_abort )

WASM="$GUEST_DIR/target/wasm32-unknown-unknown/wasm/profile_bench_programs.wasm"

python3 - "$WASM" "$SCRIPT_DIR/sample-module.js" <<'PY'
import base64, sys
wasm = open(sys.argv[1], "rb").read()
b64 = base64.b64encode(wasm).decode()
out = (
    "// Embedded sample guest module (crates/profile-bench-programs): exports\n"
    "//   sha256(ptr, len, out) and json_parse(ptr, len).\n"
    "// Loaded by default so the page works out of the box.\n"
    "// Regenerate with ./crates/profile-wasm/embed-sample.sh\n"
    'export const sampleName = "profile_bench_programs.wasm";\n'
    f'export const sampleBase64 =\n  "{b64}";\n'
)
open(sys.argv[2], "w").write(out)
print(f"embedded sample-module.js ({len(wasm)} bytes wasm)")
PY
