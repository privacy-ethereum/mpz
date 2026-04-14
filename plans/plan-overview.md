# Zero-Knowledge Virtual Machine: R&D Plan Overview

## Why This Project

Zero-knowledge virtual machines (zkVMs) let one party prove to another that a
program was executed correctly -- without revealing private inputs. This is a
foundational capability for privacy-preserving computation.

Existing zkVMs (based on STARKs and SNARKs) are designed around a different set
of trade-offs: they optimize for **small proof size** and **fast verification**,
at the cost of an extremely expensive prover. This makes them well-suited for
on-chain verification where proof size matters, but poorly suited for
interactive settings where two parties are cooperating in real time and the
prover's speed is the bottleneck.

Our zkVM targets a fundamentally different design point:

- **Fast prover.** The proving cost scales linearly with program size -- no
  superlinear blowup. The underlying VOLE-based proof protocols are the fastest
  known for this class of computation, with demonstrated throughput of millions
  of operations per second.
- **Privacy preserving.** The verifier learns nothing about private inputs or
  the execution path taken on private data. STARK-based systems are not designed
  for this.
- **WebAssembly target.** The system proves general-purpose Wasm programs, which
  is the standard compilation target for Rust, C/C++, and many other languages.

The VOLE-based approach represents the current state of the art in interactive
zero-knowledge proofs. The core protocols we build on have been published at
top-tier venues (IEEE S&P, ACM CCS, CRYPTO, USENIX Security) in the last 3
years, and several have not yet been composed into a complete VM system -- this
is where our design work begins.

## What Has Been Done

We completed a structured literature survey and analysis of 25 research papers
spanning every component needed: core proof protocols, memory verification,
instruction dispatch, type conversions, and branching. Each paper was distilled
into a summary optimized for making design decisions.

From this survey, we made 15 preliminary design decisions covering the security
model, proof protocols, memory architecture, and WebAssembly feature scope. We
also identified 4 remaining design questions that require further analysis.

## What Remains

The remaining work falls into three workstreams.

### Workstream 1: Understand the Workload

Before finalizing the design, we need to understand what real WebAssembly
programs look like in practice -- what operations they perform, how they access
memory, and how complex their control flow is. Academic papers give us
per-protocol throughput numbers, but not how those protocols compose under real
workloads.

This workstream produces a **benchmark suite** of representative Wasm programs
(general-purpose and cryptographic), **analysis tooling** that profiles any Wasm
binary for the metrics that drive design trade-offs, and a **study of
compilation strategies** that can restructure programs to reduce proving cost.

### Workstream 2: Validate and Finalize Design Choices

Using the empirical data from Workstream 1, we revisit the preliminary design
decisions to confirm or revise them. We also resolve the remaining open design
questions -- each driven by specific data about how real programs behave (e.g.,
how deep call stacks go determines how we handle function calls; how many local
variables functions use determines how we design the register file).

This workstream produces a **protocol selection document** that assigns one
concrete approach to each functional role in the system, with justification
grounded in both the academic literature and our empirical analysis.

### Workstream 3: Architecture Design

With design choices validated, we produce the full system architecture. This
covers how WebAssembly execution maps to proof steps, how memory is verified,
how instruction dispatch works, and how the system handles transitions between
different computational domains. The key output is a **per-instruction cost
table** that gives concrete performance estimates for every supported Wasm
instruction.

## Deliverables

| Deliverable | Description |
|-------------|-------------|
| Benchmark suite | Representative Wasm programs for performance modeling |
| Analysis tooling | Profiles Wasm binaries for design-relevant metrics |
| Protocol selection document | One concrete protocol per functional role, with justification |
| Architecture design document | Full system specification with per-instruction cost estimates |

## Workstream Dependencies

Workstreams 1 and 2 overlap: workload analysis begins immediately and feeds into
design validation as data becomes available. The architecture design begins once
protocol selections are finalized.
