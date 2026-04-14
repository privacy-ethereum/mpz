# profile-bench

Profiling tool for WASM programs running on the VM. It executes benchmark
functions through the ideal VM with tracing enabled, collects execution
statistics (op counts, control-flow regions, memory access patterns, call
frequencies), and outputs JSON data files for visualization.

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
- Discover exported benchmark functions from the WASM binary
- Execute each benchmark through two VM instances (private + blind party)
- Print a summary table with op counts, memory loads/stores, and call stats
- Print per-benchmark op histograms
- Write per-benchmark JSON files to `output/`

To run a specific benchmark, pass a filter argument:

```sh
cargo run -p profile-bench -- sha256
cargo run -p profile-bench -- json_parse
```

### 3. View results

Open `viewer.html` in a browser and load a JSON file from `output/` to
visualize the profile data interactively.

## Output

The summary table includes:

| Column      | Description                                    |
|-------------|------------------------------------------------|
| Public CF   | Number of ops executed under public control flow |
| Private CF  | Number of ops executed under private control flow |
| Priv CF Rgn | Number of private control-flow regions         |
| Mem Ld      | Memory load operations                         |
| Mem St      | Memory store operations                        |
| Calls       | Function call count                            |
| Decode      | Decode operations                              |

Each benchmark also generates a JSON file in `output/` containing detailed
stats, control-flow regions, block-level info, and call traces.
