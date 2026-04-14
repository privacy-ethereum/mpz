# Plan: CPU Emulation Architecture Design

## Steps

### Step 1: RISC Zero Technical Summary
Produce `docs/zk-vm/reference/risc0-architecture.md` — a technical summary of how RISC Zero models the RISC-V state machine as circuits. Cover:
- How the execution trace is structured (segments, cycles)
- The step circuit: how one CPU cycle is represented
- How instruction dispatch works (opcode selectors, multiplexing)
- How registers, memory, and the program counter are modeled
- How the call stack / control flow is handled
- How memory consistency is proved (memory argument)
- How state threads between steps
- Concrete costs / circuit sizes where available

Source: RISC Zero documentation, whitepapers, and open-source code.

### Step 2: WASM vs RISC-V Differences
Produce `docs/zk-vm/design/wasm-vs-riscv.md` — document the key architectural differences between WASM and RISC-V that affect the circuit design. Cover:
- Stack machine vs register machine
- Structured control flow vs flat PC + branches
- Variable-length instructions vs fixed-size
- Type system (i32/i64 typed values vs untyped 32-bit words)
- Linear memory model differences
- Function calls (WASM's typed call/return vs RISC-V's JAL/JALR)
- How each difference affects the step circuit design

### Step 3: Architecture Design Document
Produce `docs/zk-vm/design/cpu-emulation-architecture.md` — the full architecture for our VOLE-based CPU emulation approach applied to WASM, incorporating lessons from RISC Zero. This will be developed step-by-step collaboratively. Cover:
- Step state representation
- Step circuit structure
- Instruction dispatch mechanism
- Register/stack model
- Memory architecture
- Call stack handling
- Integration with the hybrid IR (Emulated nodes)
- Cost model

## Current Status
- [x] Step 1: RISC Zero technical summary
- [x] Step 2: WASM vs RISC-V differences
- [ ] Step 3: Architecture design document
