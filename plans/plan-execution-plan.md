# Execution Plan Data Structure

This document describes the **execution plan**, a public data structure that both
parties (prover and verifier) independently and deterministically construct during
co-execution of a WebAssembly program under the
[Verifiable Compute specification](https://sinui0.github.io/vc-spec/). The
execution plan describes the **structure of symbolic computation** that needs to
be proved, without prescribing how it is proved.

## Motivation

Both parties execute the same Wasm module with the same call configuration. Taint
(concrete vs. symbolic) is a deterministic, publicly computable property of every
value during execution. Both parties therefore agree, at every point during
execution, on:

- Which instruction is executing.
- The taint of every operand.
- The concrete values of all concrete operands.
- The structure of all control flow reachable from the current point.

Fully concrete computation — where all operands are concrete — needs no proof.
Both parties compute the same result. These operations are **folded**: they
produce no proof obligations, and their results are absorbed as public constants
into subsequent symbolic operations.

The execution plan is the record of everything that *wasn't* folded: the symbolic
operations, their structure, and the concrete values that flow into them. It
serves as the shared input from which both parties can independently derive:

- Resource budgets (gate counts, memory accesses, domain conversions).
- Circuit topologies for each proof obligation.
- State threading requirements between proof obligations.
- The inputs needed for any downstream proof protocol.

The plan is **protocol-agnostic**. It does not specify which proof protocols are
used, which algebraic fields computations occur in, or how proof obligations are
batched or composed. A separate **plan compiler** consumes the execution plan and
produces a protocol-specific proving strategy.

## Relationship to WebAssembly

The execution plan uses the same instruction set, type system, and structured
control flow as WebAssembly. It is the result of **partially evaluating** the
Wasm program with respect to the concrete (public) inputs: concrete operations
are evaluated and their results are folded in as constants, while symbolic
operations are preserved. The output is a Wasm-shaped program where every
remaining non-constant value is symbolic.

This is analogous to constant propagation and folding in a compiler, except
that "constant" means "concrete under the VC spec's taint rules" — a broader
notion that includes runtime values which happen to be public, not just
compile-time constants.

No separate intermediate representation is introduced. The plan reuses the
Wasm IR. The additional information carried by the plan — taint, memory access
metadata, prover-communicated loop bounds — is represented as sidecar data
rather than modifications to the IR itself.

## Concepts

**Block**

A *block* is a straight-line sequence of symbolic operations with no control
flow. All operations execute unconditionally. Concrete operations within the
block have been folded — only symbolic operations remain, with concrete
intermediate results embedded as public constants. A block is the atomic unit
of the plan; it contains no branches, loops, or disjunctions.

**Disjunction**

A *disjunction* is a symbolic branch point. The branch condition is symbolic,
so the verifier does not know which path was taken (the prover does). A
disjunction contains B *arms*, each of which is a sub-plan. Both arms are
derived by static analysis of the Wasm code with concrete folding applied.

**Loop**

A *loop* is a repeated computation with a symbolic exit condition. It contains
a *body* (a sub-plan describing one iteration) and an *iteration count*
communicated by the prover.

**Recursion**

A *recursion* is a function that calls itself (directly or via mutual
recursion) with a symbolic argument controlling the recursion depth. The plan
records the function body (analyzed once), the prover-communicated depth, and
the per-frame state that must be preserved across recursive invocations.

**Reveal**

A *reveal* is a synchronization point where one or more symbolic values become
concrete. After a reveal, the affected values are concrete and subsequent
computation on them may be folded.

**Folding**

*Folding* is the elimination of fully concrete computation from the plan. When
an instruction's operands are all concrete, both parties execute it locally and
obtain the same result. The instruction produces no entry in the plan. Its
result is available as a public constant to subsequent operations.

**Interface**

An *interface* describes the symbolic state flowing into or out of a plan node.
It lists the symbolic wire slots (each with a type) that cross the boundary.
Concrete state is not listed — both parties know it from the taint environment.

**Wire Reference**

A *wire reference* identifies a symbolic value within the plan. It refers
either to a slot in a node's input interface or to the output of a prior
operation within the same block.

**Taint Environment**

The *taint environment* is the mapping from every value-carrying location
(locals, globals, memory bytes) to its taint (concrete or symbolic) and, for
concrete locations, the value. Both parties maintain identical taint
environments throughout co-execution.

## Structure

The execution plan is a tree. The interior nodes are disjunctions, loops, and
recursions. The leaves are blocks and reveal points. Concrete-only execution
between nodes produces no nodes — it is folded, and its results appear as
concrete values in interfaces or as public constants within blocks.

### Grammar

```
Plan        = Node*
Node        = Block | Disjunction | Loop | Recursion | Reveal

Block       = { ops: Op*, mem: MemAccess*, in: Interface, out: Interface }
Disjunction = { arms: Plan*, in: Interface, out: Interface }
Loop        = { body: Plan, iterations: u32, in: Interface, out: Interface }
Recursion   = { body: Plan, depth: u32, frame: Interface,
                in: Interface, out: Interface }
Reveal      = { wires: WireRef* }

Op          = { instruction: InstructionId, operands: Operand*, result: Type }
Operand     = Concrete(value) | Symbolic(WireRef)

MemAccess   = { kind: Load | Store,
                address: Concrete(u32) | Symbolic,
                value_taint: Concrete | Symbolic,
                width: u32,
                align: u32 }

Interface   = { wires: WireSlot* }
WireSlot    = { id: WireId, type: Type }
```

### Blocks

A block is a straight-line sequence of symbolic operations. Every operation in
a block has at least one symbolic operand (otherwise it would have been folded).
Each operation records:

- The **instruction** (an opcode or fused-operation identifier).
- The **operands**, each either a concrete value or a wire reference to a
  symbolic value.
- The **result type**.

Operations within a block execute in order. The output of operation N is
referenceable by subsequent operations via a wire reference.

A block also records its **memory accesses** — the loads and stores that
occurred during the block's operations. Each memory access records the access
kind, address (concrete or symbolic), value taint, and the width and alignment
of the access.

> **Note**
> Memory accesses are recorded at the block level rather than per-operation.
> This enables downstream consumers to batch all accesses from a block into a
> single RAM proof invocation.

### Disjunctions

A disjunction represents a symbolic branch. Both parties know:

- The number of arms (B).
- The Wasm code for each arm (from the module, which is public).
- The taint of every value at the entry point (from the taint environment).

From this, both parties independently derive the sub-plan for each arm by
walking the arm's code and applying concrete folding. The sub-plans may differ
in size — one arm may have more symbolic operations than another.

The output interface of a disjunction is always fully symbolic for any value
that is symbolic on *any* arm, per the VC spec's taint rules (the branch
condition is symbolic, so the verifier cannot distinguish which arm produced
the output).

### Loops

A loop represents a repeated computation whose exit condition is symbolic.
Both parties encounter the loop and see that its exit condition is symbolic.
The verifier does not know the iteration count (the prover does).

Resolution:

1. The prover determines the actual iteration count.
2. The prover communicates a **padded iteration count** N to the verifier
   (e.g., the actual count rounded to the next power of 2, or some other
   configurable padding strategy).
3. Both parties analyze the loop body with the known input taints, producing
   a sub-plan for one iteration.
4. The plan records: loop with body sub-plan, N iterations.

The iteration count N is part of the plan and is public. The padding strategy
is configurable and determines the trade-off between privacy (hiding the
exact count) and efficiency (fewer wasted iterations). The plan is agnostic
to the strategy — it records N and nothing else. The embedder configures
the policy.

Disclosing a padded iteration count is analogous to non-constant-time code
leaking information via timing. The best mitigation is the same: **guest code
should ideally be written to have constant-time control flow** — loops
should iterate a fixed, publicly known number of times regardless of private
inputs. When this is not possible, the padding policy controls the
leakage-efficiency trade-off. See [Padding Policy](#padding-policy).

### Recursions

A recursion represents a function that calls itself (directly or through mutual
recursion) where the recursion depth depends on a symbolic value. Both parties
see the recursive call and recognize that the depth is not statically
determined.

A recursion records:

- The function **body** as a sub-plan, analyzed once with concrete folding
  applied. The recursive call site within the body is marked but not expanded
  — the body is not inlined into itself.
- The **depth** D, communicated by the prover (padded, subject to the same
  padding policy as loop iteration counts).
- The **frame** interface: the set of values from each invocation that must be
  preserved across the recursive call and restored when it returns. This is the
  state that a conventional call stack would save — typically the caller's live
  locals and any pending computation (e.g., the left operand of a
  multiplication that awaits the recursive call's result).

The plan does not prescribe how frames are stored or restored. The plan
compiler decides the implementation: a LIFO stack structure, RAM-based
save/restore, decomposition into descent and ascent loops, or another strategy.
The plan provides the information needed for that decision: the frame shape,
the depth, and the body's proof obligations.

#### Why recursion is a distinct node type

Recursion cannot be represented as a loop because the calling frame is
*suspended*, not consumed. A loop has one active frame per iteration; recursion
has D simultaneously live frames. Recursion cannot be expanded by inlining
because the depth is symbolic — inlining does not terminate.

Recursion also cannot be reduced to a disjunction. While each level of the
recursion contains a disjunction (base case vs. recursive case), the recursive
case references the same function body, creating a cycle that the plan's tree
structure cannot represent through nesting alone.

A dedicated node type keeps the plan honest about the structure of the
computation. The plan compiler translates it to proof obligations using
whatever mechanism is appropriate.

#### Concrete-depth recursion

If the argument controlling recursion depth is concrete, both parties know the
depth. They can inline the function body D times during plan construction,
producing a tree of D nested disjunctions (base case vs. recursive case at
each level). No `Recursion` node is emitted — the recursion is fully expanded
into the tree. The `Recursion` node is only needed when the depth is symbolic.

### Reveals

A reveal point records that one or more symbolic values have been opened and
are now concrete. It references the wire slots of the revealed values.

After a reveal point, the taint environment is updated: the revealed values
become concrete. Subsequent computation involving only these (now concrete)
values and other concrete values is folded.

## Concrete Folding

Folding is the process that eliminates concrete computation from the plan. It
operates identically at every level of the tree — at the top level, within
disjunction arms, within loop bodies, and within recursion bodies.

When processing an instruction during plan construction:

1. Look up the taint of each operand in the taint environment.
2. Apply the VC spec's taint propagation rules (default rule, annihilator
   exceptions, select rule).
3. If the result taint is **concrete**: execute the instruction, update the
   taint environment with the concrete result. No entry is added to the plan.
4. If the result taint is **symbolic**: add an operation to the current block.
   Concrete operands are recorded with their values. Symbolic operands are
   recorded as wire references.

Inside disjunction arms, both parties apply this procedure to each arm
independently. They produce the same sub-plans because taint propagation is
deterministic and the Wasm code is public.

Inside loop bodies, folding applies to the body sub-plan. If the loop body
contains concrete state that varies per iteration (e.g., a concrete loop
counter), different iterations may fold differently. See open question 2.

## Padding Policy

Symbolic loop iteration counts and recursion depths are communicated by the
prover. The padded value N is public and leaks information about the private
inputs that determined the actual count. This is analogous to non-constant-time
code leaking information via observable resource consumption.

The best mitigation is at the source: **guest code should be written with
constant-time control flow wherever possible.** Loops should iterate a fixed,
publicly known number of times. Recursion should reach a fixed, publicly known
depth. When control flow does not depend on private inputs, no padding is
needed and no information is leaked.

When constant-time guest code is not feasible, the padding strategy is
**configurable by the embedder**. The plan records the padded count N and is
agnostic to how it was chosen. Reasonable strategies include:

- **Reject**: abort if a loop or recursion depends on a symbolic condition.
- **Exact**: N = actual count (no padding, full leakage).
- **Power-of-2**: N = next power of 2. Leaks ≤ 1 bit per loop. ≤ 2× overhead.
- **Step(K)**: N = ceil(actual / K) × K. Leaks count within a K-wide range.
- **Max(M)**: N = M (fixed upper bound). No leakage. Overhead = M / actual.

These can be combined (e.g., power-of-2 capped at a declared maximum). The
choice is a per-loop policy decision balancing privacy against proof cost.

## Registers

Wasm locals and the operand stack are compiled to a register representation.
Register indices are always statically known:

- `local.get`, `local.set`, and `local.tee` take static immediate indices.
- `global.get` and `global.set` take static immediate indices.
- The operand stack depth at every program point is statically determined by
  Wasm's type system, regardless of which branches are taken.

This means the register file never has the "symbolic address" problem that
linear memory has. Both parties always know exactly which register is being
read or written, and can maintain precise per-register taint. Registers are
represented naturally in the Wasm-like IR as locals with precise taint. No
RAM-style proof is needed for register access — registers are named wires.

### Registers across call boundaries

Each function has its own register namespace (its locals plus the compiled
operand stack slots). Register indices are per-function and always static.

When a function calls another function under concrete control flow, both
parties know the callee and its register count. The caller's registers must
survive the call — they are live but inactive while the callee executes. The
plan records the caller's live symbolic registers in the interface at the call
boundary, but does not prescribe how they are preserved (wire forwarding, RAM
save/restore, or a stack structure). This is a plan-compiler decision.

A `call_indirect` with a symbolic index produces a disjunction over the
possible callees. All candidates have the same type signature (enforced by
Wasm's type system), so the input and output interfaces of the disjunction
are identical across arms. Each arm's sub-plan uses the callee's own register
namespace internally. The caller's registers are part of the disjunction's
input/output interface.

## Memory

Memory operations (`i32.load`, `i32.store`, etc.) remain in the plan's IR as
instructions. The plan records each memory access as a `MemAccess` entry
within the containing block. The plan does not track memory *state* (what
value is stored at each address) — that is maintained in the taint
environment, which both parties update during co-execution.

### Memory regions

A symbolic-address store poisons memory taint: after such a store, the
verifier cannot determine which bytes were written (the prover can), so
every byte in the affected region must be treated as potentially symbolic
for the purposes of plan construction. A subsequent load from any
address in that region produces a symbolic result, regardless of the address's
own taint.

> **Note**
> A concrete-address store *after* a symbolic-address store can reclaim a
> specific location: both parties know the store wrote a definite value to a
> definite address, so that address becomes concrete again (if the stored value
> is concrete). But every other address remains potentially affected by the
> symbolic store.

To limit the blast radius of symbolic-address stores, the plan supports
**memory regions** — partitions of linear memory where symbolic-address stores
only affect the region they target. A symbolic store to region A does not
poison region B. Loads from region B retain precise taint.

How regions are defined and enforced is an open question. Candidates include
embedder-defined region boundaries, static analysis of access patterns, or
custom section annotations in the Wasm module.

### Interaction with the plan

Memory accesses in the plan record which region they target (if regions are
used). The plan compiler uses this to determine:

- Which regions need RAM proofs (regions with any symbolic accesses).
- Which regions can be handled without RAM proofs (regions with only
  concrete-address, concrete-value accesses — these are fully folded and
  produce no `MemAccess` entries at all).
- The size and access count per region (for sizing the RAM data structures).

## State Threading

Between adjacent nodes in the plan, the VM state threads through implicitly.
Both parties maintain the taint environment, so they agree on which state
elements are symbolic and which are concrete at every node boundary. The
interface at each node boundary lists the symbolic wire slots — the concrete
state is elided because both parties know it.

A node's input interface is the set of symbolic values it reads from the
prior state. Its output interface is the set of symbolic values it produces.
The convention is implicit: the output interface of node N is the input
interface of node N+1.

## Function Calls

A direct function call under concrete control flow is transparent to the plan.
Both parties follow the call. The callee's body is processed the same way as
any other code — its instructions are folded or recorded depending on taint.
A call boundary may start a new block if the callee introduces new symbolic
operations.

A `call_indirect` with a symbolic table index is a disjunction. The arms are
the possible callees, enumerated from the module's table and the function
type signature.

A recursive call with symbolic depth produces a `Recursion` node. A recursive
call with concrete depth is inlined during plan construction — both parties
know the depth and expand the recursion into nested disjunctions.

## Derived Quantities

Both parties can independently compute the following from the plan:

| Quantity | Source |
|----------|--------|
| Total symbolic operations | Count of ops across all blocks in the tree |
| Operation frequency histogram | Grouped by instruction type |
| Total memory accesses | Count of mem records across all blocks |
| Memory access profile | Loads vs. stores, concrete vs. symbolic addresses |
| Memory region usage | Which regions are touched, access counts per region |
| Disjunction count and nesting depth | From the tree shape |
| Per-disjunction arm count and arm sizes | From disjunction nodes |
| Loop iteration counts and body sizes | From loop nodes |
| Recursion depths and frame sizes | From recursion nodes |
| State threading width at each boundary | From interfaces |
| Domain conversion points | From ops that cross arithmetic/boolean boundaries |

A **plan compiler** consumes these quantities to produce a protocol-specific
proving strategy: which proof protocol to use for each node, how to batch
nodes, where to place domain conversions, and how to allocate preprocessing
resources.

## What the Plan Does Not Contain

- **Private values.** The plan never contains the bit patterns of symbolic
  values. The prover holds those separately as its witness.
- **Which arm was taken** in a disjunction. The plan records the structure of
  all arms; the prover's witness records the actual path.
- **Proof protocol choices.** The plan does not name specific proof protocols.
- **Field assignments.** The plan does not specify which algebraic field a
  computation occurs in.
- **Wire layout.** The plan does not assign wires to positions in an extended
  witness vector. That is a protocol-specific concern.
- **Batching strategy.** Whether blocks are merged, loop iterations are
  batched, or disjunctions are flattened is a downstream optimization.
- **Call stack implementation.** The plan records the frame shape and depth
  for recursive calls, but does not prescribe how frames are stored (RAM,
  stack structure, wire forwarding).
- **Memory region implementation.** The plan records memory accesses with
  region annotations, but does not prescribe which RAM protocol is used or
  how regions map to proof data structures.

## Open Questions

### 1. Block Boundaries

What causes a new block to start? Candidates:

- Any control flow, even concrete (e.g., a concrete `if/else` starts new
  blocks for the taken path).
- Only when transitioning between concrete and symbolic execution.
- At function call boundaries.
- At some maximum block size (for resource management).

This affects the number and size of blocks in the plan.

### 2. Loop Body Variation Across Iterations

If different iterations of a symbolic loop have different concrete values
flowing in (e.g., a concrete loop counter incrementing each iteration), the
folding within each iteration may differ — some operations concrete in one
iteration may be symbolic in another (or vice versa, though this is less
common). This means the "body sub-plan" may not be uniform across iterations.

Options:

- a) Require uniform body sub-plans: the body is analyzed once with a
  conservative taint (treating varying concrete values as symbolic for
  uniformity). This wastes some proof capacity but simplifies the model.
- b) Allow per-iteration sub-plans: each iteration has its own folded plan.
  More efficient but makes the plan O(N) in size for N iterations.
- c) Group iterations by taint signature: iterations with the same taint
  pattern share a sub-plan. A middle ground.

### 3. Disjunction Nesting Depth

How deeply can disjunctions nest in real Wasm programs? A symbolic `if` inside
a symbolic `if` creates a disjunction within a disjunction arm. If nesting is
deep, the tree becomes expensive. Should the plan compiler be allowed to
flatten nested disjunctions (e.g., 2-way × 2-way → 4-way)?

This is a plan-compiler concern, not a plan-structure concern — the tree
representation supports arbitrary nesting. But the plan construction should
be aware of practical limits.

### 4. Reveals Inside Disjunctions

Can a reveal occur inside a disjunction arm? A reveal requires cooperation
between both parties, but inside a symbolic branch the parties do not agree on
which arm is executing. This likely means reveals cannot occur inside
disjunction arms. If the Wasm code contains a reveal call inside a symbolic
branch, the embedder must handle this — possibly by aborting or by deferring
the reveal to after the branch.

### 5. Plan Serialization

Does the plan need a concrete serialization format (e.g., for transmission
between components, or for caching), or is it always computed locally by each
party from the shared execution? If it needs serialization, a binary format
should be defined.

### 6. Incremental Proving

Can proving begin on early nodes of the plan while execution continues and
produces later nodes? This depends on whether proof protocols can operate in
a streaming fashion over the plan tree. If yes, the plan's incremental
construction is a feature — proving and execution overlap. If no, the full
plan must be materialized before proving starts.

### 7. Memory Region Definition

How are memory regions defined? Candidates:

- Embedder-declared region boundaries (e.g., "bytes 0-1023 are region A,
  1024-2047 are region B").
- Static analysis of memory access patterns in the Wasm module.
- Custom section annotations in the Wasm module (advisory, per the VC spec).
- A single region (all of linear memory) as the default, with region
  splitting as an optimization.

The choice affects how aggressively symbolic-address store poisoning can be
contained.

### 8. Mutual Recursion

The `Recursion` node assumes direct self-recursion. Mutual recursion (function
A calls B, B calls A) creates a cycle involving multiple function bodies. The
plan may need to represent this as a group of mutually recursive functions
with a shared depth bound and per-function frame layouts. The frequency of
mutual recursion in target Wasm programs is likely low, but the model should
at least acknowledge it.
