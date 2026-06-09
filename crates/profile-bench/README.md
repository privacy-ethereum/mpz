# profile-bench

Profiling tool for WASM programs running on the VM. It executes benchmark
functions directly on `mpz-vm-core`'s `Thread` with tracing enabled, collects
execution statistics (op counts, control-flow regions, memory access patterns,
call frequencies), and writes JSON data files for visualization.

It drives the VM as the single party that *holds* every value (see
[`tracer::Tracer`](src/tracer.rs)). Because that party can decide every branch,
indirect call, and `memory.grow` locally, execution never blocks on a peer, so
no two-party exchange or async I/O is needed — only host/imported calls are
serviced. This keeps the profiler decoupled from `mpz-vm-ideal` while producing
the same directive stream the holding party would see in the real protocol.

## Prerequisites

- Rust nightly toolchain (for `-Zbuild-std`)
- `wasm32-unknown-unknown` target
- The `profile-bench-programs` crate (sibling directory)

## Usage

### 1. Build the WASM binary

```sh
./crates/profile-bench/build-wasm.sh
```

This compiles `profile-bench-programs` to WASM and places the output in
`wasm/profile_bench_programs.wasm`.

### 2. Run the profiler

```sh
cargo run -p profile-bench
```

This will:
- Discover exported benchmark functions registered with `register_benchmark!`
- Execute each benchmark on the tracing VM
- Print a summary table with op counts, memory loads/stores, and call stats
- Write per-benchmark JSON files to `output/`

To run a specific benchmark, pass a filter argument:

```sh
cargo run -p profile-bench -- sha256
cargo run -p profile-bench -- json_parse
```

### 3. View results

Open `viewer.html` (the **Cost Explorer**) in a browser and load a JSON file
from `output/`. It shows an execution/proving-cost summary and an instruction
histogram that can be weighted by raw count or by estimated proving cost
(sVOLE or bytes), split by public vs. private control flow. The per-op cost
model is editable in the Cost Table, so you can explore how the instruction
mix and control-flow visibility drive cost.

## Output

The summary table includes:

| Column      | Description                                       |
|-------------|---------------------------------------------------|
| Public CF   | Number of ops executed under public control flow  |
| Private CF  | Number of ops executed under private control flow |
| Priv CF Rgn | Number of private control-flow regions            |
| Mem Ld      | Memory load operations                            |
| Mem St      | Memory store operations                           |
| Calls       | Function call count                               |
| Decode      | Decode operations                                 |

Each benchmark also generates a JSON file in `output/` containing detailed
stats, control-flow regions, block-level info, and call traces.
