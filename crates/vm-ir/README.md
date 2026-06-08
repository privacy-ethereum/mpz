# IR - WebAssembly Module Data Model

A Rust crate that provides a complete data model for WebAssembly modules, supporting the WASM core specification. Built on top of `wasmparser` for robust and standards-compliant parsing.

## Features

- Complete WASM core spec support
- Type-safe data structures for all WASM components
- Instruction-level representation
- Built on the battle-tested `wasmparser` library
- Zero-copy parsing where possible

## Usage

```rust
use mpz_ir::Module;

// Parse a WebAssembly module from bytes
let wasm_bytes = std::fs::read("module.wasm")?;
let module = Module::parse(&wasm_bytes)?;

// Access module components
println!("Functions: {}", module.functions.len());
println!("Imports: {}", module.imports.len());
println!("Exports: {}", module.exports.len());

// Iterate over function types
for func_type in &module.types {
    println!("Func type: {} params, {} results",
        func_type.params.len(),
        func_type.results.len()
    );
}
```

## Data Model

The crate provides strongly-typed structures for all WASM components:

- **Module**: Top-level container with types, functions, tables, memories, globals, etc.
- **FuncType**: Function signatures with parameters and results
- **Instruction**: Integer-only instruction set (no floating point)
- **ValType**: Integer value types (i32, i64)
- **Import/Export**: Module imports and exports
- **Table/Memory**: Linear memories and tables
- **Global**: Global variables
- **Element/Data**: Element and data segments

**Note**: This crate intentionally does **not** support floating point operations (f32/f64). Any module containing floating point types or instructions will be rejected during parsing with a clear error message.

## Supported Instructions

Integer-only WASM instructions are supported, including:
- Control flow (block, loop, if, br, etc.)
- Function calls (call, call_indirect)
- Variable access (local.get, global.set, etc.)
- Memory operations (i32/i64 load, store with all variants)
- Integer operations (arithmetic, comparison, bitwise)
- Integer conversions (wrap, extend, sign extension)
- Reference types (funcref, externref)

**Explicitly NOT supported**:
- Floating point types (f32, f64)
- Floating point instructions (f32.add, f64.mul, etc.)
- Float/int conversions (f32.convert_i32_s, i32.trunc_f32_s, etc.)
- Float memory operations (f32.load, f64.store, etc.)

## Testing

The crate includes comprehensive test coverage with WAT (WebAssembly Text) fixtures in `tests/fixtures/`:

- `empty.wat` - Minimal empty module
- `simple_function.wat` - Basic function with constant return
- `import.wat` - Module with imports
- `export.wat` - Module with exports
- `memory.wat` - Linear memory and data segments
- `table.wat` - Function tables and element segments
- `global.wat` - Global variables (mutable and immutable)
- `control_flow.wat` - Complex control flow (loops, blocks, branches)

Tests use the `wat` crate to compile WAT files to WASM at test time, making fixtures easy to read and maintain.

## Limitations

- **No floating point support** - f32 and f64 types/instructions are explicitly rejected
- Only WebAssembly modules are supported (not components)
- Multi-memory proposal is not supported
- Some advanced proposals beyond core spec are not included

This crate is designed for scenarios where floating point arithmetic is not needed or not desired, such as cryptographic computations, zero-knowledge proofs, or other integer-only workloads.
