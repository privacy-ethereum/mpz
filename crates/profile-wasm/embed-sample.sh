#!/bin/bash
# Regenerate sample-module.js from the built sample guest wasm, so the page
# can load it by default without a separate file. Build the guest first:
#   ./crates/profile-bench/build-wasm.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
WASM="$ROOT/crates/profile-bench/wasm/profile_bench_programs.wasm"

if [ ! -f "$WASM" ]; then
    echo "guest wasm not found — run ./crates/profile-bench/build-wasm.sh first" >&2
    exit 1
fi

python3 - "$WASM" "$SCRIPT_DIR/sample-module.js" <<'PY'
import base64, sys
wasm = open(sys.argv[1], "rb").read()
b64 = base64.b64encode(wasm).decode()
out = (
    "// Embedded sample guest module (crates/profile-bench-programs): exports\n"
    "//   sha256(ptr, len, out) and json_parse(ptr, len).\n"
    "// Loaded by default so the page works out of the box. Regenerate with:\n"
    "//   ./crates/profile-bench/build-wasm.sh && ./crates/profile-wasm/embed-sample.sh\n"
    'export const sampleName = "profile_bench_programs.wasm";\n'
    f'export const sampleBase64 =\n  "{b64}";\n'
)
open(sys.argv[2], "w").write(out)
print(f"wrote sample-module.js ({len(wasm)} bytes wasm)")
PY
