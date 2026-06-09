# profile-bench

Command-line profiler for the fixed benchmark programs. It executes each
benchmark directly on `mpz-vm-core`'s `Thread` with tracing enabled (via
[`profile-core`](../profile-core)) and prints a summary table of execution
statistics. For interactive profiling of arbitrary modules in the browser, see
[`profile-wasm`](../profile-wasm).

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

This discovers the benchmark functions registered with `register_benchmark!`,
runs each on the tracing VM, and prints a summary table. To run a specific
benchmark, pass a filter argument:

```sh
cargo run -p profile-bench -- sha256
cargo run -p profile-bench -- json_parse
```

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
