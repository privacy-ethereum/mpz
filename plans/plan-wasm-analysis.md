# Wasm Analysis Tooling Plan

## Context

This plan covers Phase 0B from the engineering plan: building analysis tooling
for Wasm programs. The original engineering plan split this into "static
analysis" and "dynamic profiling." After further analysis, we've unified them:
the IR interpreter provides all the metrics we need, and the handful of
structural metrics that don't require execution are trivial queries on
`ir::Module`, not a separate subsystem.

The IR interpreter is not throwaway profiling infrastructure -- it is the first
iteration of the zkVM's execution engine. The prover will eventually execute
Wasm programs step-by-step to generate execution traces, and this interpreter
serves that role. In profiling mode it collects statistics; in future proving
mode it will generate witnesses.

## Existing Assets

- **`crates/ir`**: Parses `.wasm` binaries into a register-based IR
  (`Module` -> `Function` -> `Vec<Instruction>`). Handles MVP + bulk memory
  instructions, control flow translation, and stack-to-register compilation.
- **`wasmparser` 0.219**: Used by the IR crate for binary parsing.

## External Dependencies

| Crate | Version | Purpose |
|-------|---------|---------|
| `serde` + `serde_json` | (workspace) | Serializable output for analysis results |

No new heavyweight dependencies. We interpret our own IR directly -- no need
for `wasmi`, `wasmtime`, or `walrus`.

## Architecture

```
.wasm binary
    |
    v
crates/ir (existing)        -- parse + translate to register IR
    |
    v
crates/wasm-analyze (new)
    |
    +-- structural queries   -- trivial reads from ir::Module
    |     +-- locals/register counts per function
    |     +-- globals count
    |     +-- br_table fanout
    |     +-- load/store variant distribution (static)
    |
    +-- interpreter          -- executes ir::Module, collects runtime metrics
          +-- step-by-step execution of ir::Instruction
          +-- memory subsystem (linear memory, globals)
          +-- call stack
          +-- metrics collection hooks
```

## Part 1: Structural Metrics

These are direct reads from `ir::Module` that don't require execution. They
feed into open questions OQ5 (register file), OQ6 (globals), and OQ7 (branch
compilation rules).

| Metric | Source | Feeds into |
|--------|--------|-----------|
| Locals count per function | `func.locals()` + `func.func_type().params` | OQ5 |
| Register count per function | `func.register_count()` | OQ5 |
| Globals count per module | `module.globals().len()` | OQ6 |
| `br_table` fanout | Scan function bodies for `BrTable`, count `targets.len()` | OQ7 |
| Load/store variant distribution | Count each `I32Load`, `I32Load8U`, `I64Store`, etc. | Q5.1 (RAM granularity) |
| Alignment distribution | Extract `memarg.align` from all load/store instructions | Q5.1 |

This is ~100 lines of code. Not a subsystem -- just a module with a few
functions that iterate over the IR.

## Part 2: IR Interpreter

A step-by-step interpreter for `ir::Module` that executes the register-based IR
and collects runtime metrics. This is the core deliverable and the first layer
of the zkVM execution engine.

### 2A: VM State

- **Frame**: function index, instruction pointer, register file (`Vec<Value>`)
- **Value**: `enum Value { I32(i32), I64(i64) }` -- no floats (zkVM excludes
  them)
- **Linear memory**: byte-addressable `Vec<u8>` with bounds checking,
  initialized from data segments
- **Globals**: `Vec<Value>`, initialized from module global init expressions
- **Tables**: `Vec<Option<u32>>` (function indices for `call_indirect`)
- **Call stack**: `Vec<Frame>`
- **Control stack** (per frame): tracks `Block`/`Loop`/`If` scopes for branch
  resolution at runtime, analogous to the translator's `Scope` but tracking
  runtime instruction positions

### 2B: Execution Loop

Match on `ir::Instruction`, update state, advance PC:

- **Arithmetic/bitwise**: straightforward -- evaluate the op on register
  values, store to `dst`. Wrapping semantics for i32/i64 (Rust's
  `wrapping_add`, etc.).
- **Memory**: compute effective address (`addr_reg_value + memarg.offset`),
  bounds check, read/write bytes with appropriate width and sign extension.
- **Control flow**: `Block`/`Loop`/`If` push to the control stack.
  `Br`/`BrIf`/`BrTable` pop scopes and jump. `End` pops the current scope. The
  control stack entries need to record the instruction index to jump to (for
  `Br` targeting a `Block`, jump to the matching `End`; for `Loop`, jump back
  to the `Loop` instruction).
- **Calls**: `Call` pushes a new frame. Arguments are copied from the caller's
  registers to the callee's parameter registers. `Return` pops the frame and
  copies results. `CallIndirect` resolves the function index via the table,
  then proceeds like `Call`.
- **Traps**: `Unreachable`, division by zero, out-of-bounds memory, call stack
  overflow, table index out of bounds, type mismatch on `call_indirect`.

### 2C: Metrics Collection

Hooks that fire during execution. Controlled by a runtime flag so there's zero
overhead when disabled.

| Metric | Collection method | Feeds into |
|--------|------------------|-----------|
| Instruction execution counts (per opcode) | Increment counter per `Instruction` variant | Instruction mix ratios, Phase 0D cost model |
| Branch taken/not-taken ratios | Record at each `BrIf` | OQ7, dispatch strategy |
| Call depth histogram | Track call stack depth at each `Call` | OQ4 (call stack) |
| `call_indirect` frequency | Count at each `CallIndirect` | OQ4 |
| Loop iteration counts | Counter per loop instance, record at loop exit | OQ7, dispatch strategy |
| Memory load/store frequency | Count at each load/store execution | Phase 3A.1 (binary vs prime), Q5.2 |
| Sub-word access frequency | Count i8/i16 load/store variants vs i32/i64 at runtime | Q5.1 (RAM granularity) |
| Access alignment | Record `memarg.align` at each load/store | Q5.1 |
| Address stride analysis | Record sequences of memory addresses, compute strides | Memory access pattern characterization |
| Domain crossing count | Track domain (arith/bitwise) of last instruction, count transitions | Phase 3A.1 (binary vs prime) |

### 2D: Host Function Interface

For handling imported functions:

- Trait `HostFunction` with a
  `call(&mut self, args: &[Value]) -> Result<Vec<Value>>` method.
- Default: trap on any host call (sufficient for self-contained benchmarks
  compiled with `wasm32-unknown-unknown`).
- Optional: minimal WASI shim for `wasm32-wasi` targets (just `fd_write` for
  stdout and `proc_exit`). Only if needed by the benchmark suite.

### 2E: Proving Mode (Out of Scope)

The interpreter is designed so that proving mode is a future extension, not a
rewrite. The metrics hooks in 2C are the extension points: in proving mode,
instead of incrementing counters, they record values into an execution trace for
the ZK proof. The interpreter's structure -- step-by-step execution, explicit
state, per-instruction granularity -- is exactly what the prover needs.

## Part 3: Output

A function (and optionally a CLI binary) that:

1. Takes a `.wasm` file path
2. Parses it via `ir::Module::parse`
3. Runs structural metrics (Part 1)
4. Runs the interpreter (Part 2) with a specified entry point and input
5. Outputs results as JSON (for consumption by the Phase 0D cost model)

## Crate Structure

```
crates/wasm-analyze/
    Cargo.toml
    src/
        lib.rs             -- public API
        structural.rs      -- Part 1: structural metrics from ir::Module
        interpreter/
            mod.rs
            state.rs       -- 2A: VM state (frames, memory, globals, tables)
            execute.rs     -- 2B: execution loop
            metrics.rs     -- 2C: metrics collection hooks
            host.rs        -- 2D: host function interface
        report.rs          -- Part 3: JSON output
```

## Build Order

1. **2A: VM state** -- define `Value`, `Frame`, memory, globals, tables
2. **2B: Execution loop (arithmetic + memory)** -- get basic instructions
   working, verify against simple Wasm programs
3. **2B: Execution loop (control flow)** --
   `Block`/`Loop`/`If`/`Br`/`BrIf`/`BrTable` -- the hardest part
4. **2B: Execution loop (calls)** -- `Call`/`CallIndirect`/`Return`
5. **2C: Metrics hooks** -- add profiling on top of the working interpreter
6. **Part 1: Structural metrics** -- trivial, can be done at any point
7. **2D: Host interface** -- only when benchmark programs require imports
8. **Part 3: Output** -- wraps everything, done last

The interpreter (steps 1-4) is the critical path. Steps 5-8 can be
parallelized or reordered.
