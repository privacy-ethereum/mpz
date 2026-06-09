# profile-wasm

The profiler ([`profile-core`](../profile-core)) compiled to WebAssembly and
embedded in a page, so you can profile **arbitrary** WASM modules in the
browser. Drop a `.wasm`, write a small JS harness to set up its inputs, and run
it through the single-party tracing VM — the result renders in the Cost Explorer
(instruction histograms + estimated proving cost).

## Build

Requires the `wasm32-unknown-unknown` target (`rustup target add
wasm32-unknown-unknown`). The script also installs a matching `wasm-bindgen-cli`
if needed.

```sh
./crates/profile-wasm/build-wasm.sh
```

This compiles the crate and writes the `--target web` bindings to `pkg/`
(`profile_wasm.js` + `profile_wasm_bg.wasm`).

## Run

The page loads the wasm via ES modules + `fetch`, so it must be served over
HTTP (opening `index.html` from `file://` will not work):

```sh
cd crates/profile-wasm
python3 -m http.server 8000
# open http://localhost:8000/index.html
```

A sample module (`sha256` + `json_parse`, embedded as base64 in
`sample-module.js`) is loaded and profiled on open, so the page works out of the
box. Regenerate it with `./embed-sample.sh` after rebuilding the guest. Drop
your own `.wasm` to replace it.

Its exports are listed; click one to prefill a call. The
harness is plain JavaScript with a `Tracer` named `tracer` in scope, edited in a
small syntax-highlighting editor (CodeJar + Prism, vendored under `vendor/` so
the page stays self-contained):

```js
const heap = tracer.heapBase();
const input = new TextEncoder().encode("hello");
tracer.writePrivate(heap, input);          // staged as a private (secret) input
return tracer.fn.my_export(heap, input.length);
```

Each export is exposed as a checked method on `tracer.fn` (e.g.
`tracer.fn.sha256(ptr, len, out)`), so you don't call by string name and get a
clear error on the wrong number of arguments. `tracer.call(name, args)` still
works if you prefer.

Press **Run**. A fresh `Tracer` is created for each run, so re-running starts
from clean module state.

Dropping a `.json` profile (e.g. one written by the `profile-bench` CLI) renders
it directly, bypassing the harness.

### Tracer API (JS)

| Method | Description |
|---|---|
| `new Tracer(bytes)` | Parse a WASM module (a `Uint8Array`). |
| `tracer.exports()` | JSON array of `{ name, func_idx, params, results }`. |
| `tracer.heapBase()` | `__heap_base` (first free heap address), or 65536. |
| `tracer.writePrivate(ptr, data)` | Stage `data` (Uint8Array) as private/secret. |
| `tracer.writePublic(ptr, data)` | Stage `data` as public. |
| `tracer.writeBlind(ptr, len)` | Reserve `len` blind bytes (held by the other party). |
| `tracer.fn.<export>(...args)` | Checked call to a named export; returns the parsed profile. |
| `tracer.call(export, args)` | Run `export` (by name) with scalar `args`; returns the profile JSON. |

Values read from private (or blind) memory drive **private control flow**; a
module run entirely over public inputs stays in public control flow.

## Try it with the sample guests

```sh
./crates/profile-bench/build-wasm.sh   # builds crates/profile-bench/wasm/profile_bench_programs.wasm
```

Drop that module and call `sha256(ptr, len, out)` or `json_parse(ptr, len)`.
