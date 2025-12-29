# Test Fixtures

This directory contains WebAssembly Text (WAT) format test fixtures used to verify the IR crate's parsing capabilities.

## Fixtures

### `empty.wat`
Minimal empty module - tests basic module structure parsing.

### `simple_function.wat`
Simple function that returns a constant i32 value (42). Tests:
- Function type parsing
- Basic instruction parsing (i32.const)
- Function body parsing

### `import.wat`
Module with an imported function from the "env" module. Tests:
- Import section parsing
- Function type references in imports

### `export.wat`
Module with an exported "add" function that adds two i32 parameters. Tests:
- Export section parsing
- Function parameters and locals
- Binary operations (i32.add)
- Local variable access (local.get)

### `memory.wat`
Module with linear memory and data segment. Tests:
- Memory section parsing
- Data section parsing
- Memory initialization with string data

### `table.wat`
Module with a function table and element segment. Tests:
- Table section parsing
- Multiple functions
- Element section with function references
- Function table initialization

### `global.wat`
Module with global variables (mutable and immutable). Tests:
- Global section parsing
- Global mutability
- Global get/set instructions
- Initialization expressions

### `control_flow.wat`
Module with complex control flow implementing a factorial function. Tests:
- Blocks and loops
- Conditional branches (br_if)
- Unconditional branches (br)
- Local variables
- Complex instruction sequences

## Usage

These fixtures are loaded and compiled by the test suite using the `wat` crate:

```rust
fn load_fixture(name: &str) -> Vec<u8> {
    let wat_path = format!("tests/fixtures/{}.wat", name);
    let wat = std::fs::read_to_string(&wat_path).unwrap();
    wat::parse_str(&wat).unwrap()
}
```

## Adding New Fixtures

To add a new test fixture:

1. Create a `.wat` file in this directory
2. Add a corresponding test in `src/tests.rs`
3. Use `load_fixture("your_fixture_name")` to load it

The WAT format is human-readable and easier to maintain than raw WASM bytecode.
