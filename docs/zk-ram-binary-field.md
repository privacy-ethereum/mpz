**ZK RAM over Binary Fields via Two-Shuffle Structure**

# 1. Overview

We design set membership, read-only memory (ROM), and read/write memory (RAM)
data structures for VOLE-based ZK proofs over the binary field F_{2^k}. The
design adapts the two-shuffles approach (Yang & Heath, 2023) — which was
originally presented over prime fields — to binary extension fields.

The key adaptation for binary fields: integer arithmetic operations (increment,
subtraction) required by the two-shuffles protocols are implemented via Boolean
adder/subtractor circuits, since field addition in F_{2^k} is XOR, not integer
addition.

**Parameters:**
- F = F_{2^k}, binary extension field (k = 64)
- n: number of memory elements
- T: number of accesses (assume T = w(n))
- l: tuple width (number of field elements per memory entry)
- W: bit-width of memory words

# 2. Permutation Proofs over F_{2^k}

All three data structures rely on proving that two vectors are permutations of
each other. Given vectors x, y of length m, the polynomial identity test works
identically to the prime field case.

**Scalar case.** When each entry is a single element of F_{2^k}:

1. V samples uniform r in F_{2^k} and sends it to P.

2. Both parties evaluate:
   p(r) = prod_i (x[i] + r)
   q(r) = prod_i (y[i] + r)
   and check p(r) = q(r).

Over F_{2^k}, subtraction is addition (XOR), so (x[i] - r) = (x[i] + r).
The product requires 2(m-1) multiplication gates over F_{2^k}.

Soundness error: m / 2^k.

**Tuple case.** When entries are d-tuples of field elements (d = l + 2 for ROM
with l-element values, plus address and version/time), V samples a challenge
vector Y in (F_{2^k})^d. Each tuple is compressed to a scalar via
<Y, tuple> = Y_0 * addr + Y_1 * val_1 + ... + Y_l * val_l + Y_{l+1} * ver.
Since Y is public, this is a linear operation (free). The product check then
proceeds on the compressed scalars.

Integer fields (address, version, time) are embedded into F_{2^k} via canonical
bit-to-polynomial mapping before the linear combination.

Soundness error: m / 2^k (by Schwartz-Zippel on total degree m polynomial
over all challenge variables).

**Packing shortcut.** When d = 1, or when the total bit-width of a tuple is
≤ k, the tuple can be bit-packed into a single F_{2^k} element directly,
avoiding the extra challenge vector. For RAM tuples with l = 1:
log(n) + W + b ≤ k suffices. With k = 64, packing requires tighter bounds;
otherwise the tuple-case random linear combination (free) is used.

**QuickSilver acceleration.** Fan-in-m multiplications can be batched using
degree-e polynomial proofs, reducing VOLE correlations from ~2m to
~2m/(e-1). The optimal e depends on the network; values between 8-32 give
good tradeoffs.

# 3. Integer Arithmetic in F_{2^k}

The two-shuffles protocols require two integer operations that have no direct
F_{2^k} analogue:

## 3.1 Integer Increment (v + 1)

Used in ROM version chains. Given authenticated bits [v_0], ..., [v_{b-1}]
representing integer v (b bits, see Section 3.3 for sizing), compute [v+1]:

```
carry = 1  (public constant)
for i in 0..b:
    [sum_i] = [v_i] XOR carry       // free (linear)
    carry   = [v_i] AND carry        // half-adder carry
```

At i=0: carry_1 = [v_0] AND 1 = [v_0] (free, public * private is linear).
At i=1: carry_2 = [v_1] AND [carry_1] (1 AND gate, private * private).
At i=2..b-2: each carry costs 1 AND gate (private * private).
We need carries up to carry_{b-1} to compute sum_{b-1}. carry_b is not needed.

**Cost:** (b - 2) AND gates per increment.

## 3.2 Integer Subtraction (clock - t)

Used in RAM timing checks. Given public clock value c (represented as b bits)
and authenticated bits [t_0], ..., [t_{b-1}], compute [c - t] as [c + (~t) + 1]
(two's complement):

```
// Flip bits of t (free: XOR with public 1)
for i in 0..b:
    [not_t_i] = [t_i] XOR 1

// Add c to ~t, plus 1 for two's complement
// c_i are public, initial carry is 1 (public).
carry = 1
for i in 0..b:
    [sum_i] = [not_t_i] XOR c_i XOR carry       // free (linear)
    carry   = maj([not_t_i], c_i, carry)          // full-adder carry
```

The carry update is: carry_{i+1} = ([~t_i] AND c_i) XOR ([~t_i] AND carry_i)
XOR (c_i AND carry_i).

At i=0, both c_0 and carry_0 = 1 are public. carry_1 is a linear function of
[~t_0] (free to compute). Whether carry_1 is public or private depends on c_0:
if c_0 = 1, carry_1 = 1 (public); if c_0 = 0, carry_1 = [~t_0] (private).

Once carry becomes private at some position j, all subsequent positions i > j
have [~t_i] AND [carry_i] as private * private = 1 AND gate. The other terms
(c_i * [~t_i] and c_i * [carry_i]) are public * private = free.

Worst case (carry goes private at i=0): AND gates at positions i=1 through
i=b-2 (for carries 2 through b-1), totaling b-2.

**Cost:** At most (b - 2) AND gates. Same worst case as increment. The actual
count can be lower depending on the specific clock value (consecutive 1-bits
in c keep the carry public longer).

## 3.3 Bit-Width Constraint

Integer arithmetic is performed mod 2^b. The RAM timing check computes
diff = clock - t mod 2^b and verifies diff ∈ {1,...,T}. If t > clock (a
future read), diff wraps: diff = 2^b - (t - clock). For soundness, this
wrapped value must NOT be in {1,...,T}.

Worst case: t = T, clock = 1, giving diff = 2^b - (T - 1). We require
2^b - (T - 1) > T, i.e., **2^b > 2T - 1**, so **2^b ≥ 2T**.

This matches the prime-field constraint |F| ≥ 2T from two-shuffles. The
required bit-width is:

    b = ceil(log(2T))

Note: b = ceil(log(T + n)) is NOT always sufficient. For example, if
T = 2^24 - 1, n = 1, then b = 24, but 2^24 < 2T. An attacker claiming
t = clock + 1 gets diff = 2^24 - 1 = T ∈ {1,...,T}, bypassing the timing
check.

For ROM (no timing check), the only constraint is that versions don't
overflow: b_rom ≥ ceil(log(T + 1)), since the maximum version for a single key
is T.

For the set used inside RAM, we reuse b = ceil(log(2T)) since this already
satisfies b ≥ ceil(log(T + 1)).

Throughout this document, "b" refers to the RAM bit-width ceil(log(2T)) unless
otherwise noted. ROM may use a smaller b_rom = ceil(log(T + 1)) when
instantiated independently.

# 4. Read-Only Memory (ROM)

## 4.1 Data Structure

```
type ROM {
    content : Vec<(F, F^l)>      // (key, value) pairs, set at init
    reads   : Vec<(F, F^l, F)>   // (key, value, version) tuples
    writes  : Vec<(F, F^l, F)>
}
```

Versions are represented as b-bit integers embedded in F_{2^k} via bit-packing.

## 4.2 Protocol

**Setup(content: [(key, value); n]):**
For each (i, x[i]) in content:
    writes.append((i, x[i], 0))          // version 0, all public

**Lookup(key: F) -> F^l:**
P inputs: val (l field elements), version v (b authenticated bits)
Circuit computes: [v+1] via Boolean increment    // (b-2) AND gates
reads.append((key, val, Pack(v)))
writes.append((key, val, Pack(v+1)))
return val

**Teardown:**
For each address i in [n]:
    P inputs: final version v_i (b authenticated bits)
    reads.append((i, x[i], Pack(v_i)))
Verify: reads ~ writes                          // permutation proof

## 4.3 Correctness

The permutation check enforces that every written (key, val, version) tuple
is also read exactly once. At setup, version 0 is written on public wires
(not from P). Each lookup reads version v and writes version v+1. At teardown,
the final version of each key is read.

This forces P into building per-key chains: the setup writes version 0, the
first lookup reads 0 and writes 1, the second reads 1 and writes 2, etc. P
cannot forge initial values because version 0 is written by the circuit, not
by P. P cannot skip versions because every write must have a matching read.

P *can* read from the future (read version v before the lookup that writes v),
but this cannot form cycles and does not affect ROM soundness since all lookups
to the same key return the same value regardless of order.

## 4.4 Gate Cost

Per lookup:
- l field elements + b subfield VOLEs (value + version bits from P)
- (b - 2) AND gates (integer increment for version, b = ceil(log(T+1)) for ROM)

Teardown:
- n input gates (final versions)
- Two fan-in-(n+T) multiplications over F_{2^k} (permutation check)

**Total non-linear cost per lookup:** (b - 2) AND gates + amortized permutation
check contribution.

# 5. Set Membership

Set membership is a specialization of ROM with l = 0 (keys only, no values).
Given a public set S = {s_1, ..., s_m}, it proves that a private value x
belongs to S. This primitive is critical to RAM soundness: it enforces the
timing constraint that prevents P from reading values written in the future.

## 5.1 Data Structure

```
type Set {
    reads  : Vec<(F, F)>    // (key, version) tuples
    writes : Vec<(F, F)>
}
```

Tuples contain only key and version (no value field). Versions are b-bit
integers embedded in F_{2^k} via bit-packing.

## 5.2 Protocol

**Setup(keys: [F; m]):**
For each key s in keys:
    writes.append((s, 0))                // version 0, all public

**Prove-member(val: F):**
P inputs: version v (b authenticated bits)
Circuit computes: [v+1] via Boolean increment    // (b-2) AND gates
reads.append((val, Pack(v)))
writes.append((val, Pack(v+1)))

**Teardown:**
For each key s in keys:
    P inputs: final version v_s (b authenticated bits)
    reads.append((s, Pack(v_s)))
Verify: reads ~ writes                          // permutation proof

## 5.3 Correctness

The argument follows directly from ROM correctness (Section 4.3) with l = 0.
Setup writes each key at version 0 on public wires. Each prove-member call
reads version v and writes v+1, forming per-key version chains. Teardown reads
the final version of each key.

If P claims x ∈ S but x ∉ S, no setup entry exists for x. P must produce a
(x, v) read, but the only writes with key x are those P created via
prove-member — each of which also created a read at version v-1. There is no
version-0 write for x (those are circuit-controlled, not from P), so the chain
has no root. The permutation check fails because writes will contain an
unmatched entry.

## 5.4 Gate Cost

Per membership query:
- 1 input gate (version)
- (b - 2) AND gates (version increment)

Teardown:
- m input gates (final versions)
- Two fan-in-(m + T) multiplications over F_{2^k} (permutation check)

## 5.5 Optimization: Public Setup Product

The initial m writes are publicly known: (s_1, 0), (s_2, 0), ..., (s_m, 0).
After V sends the random challenge r, both parties can locally compute the
product of the setup terms:

    prod_{j=1}^{m} (Pack(s_j, 0) + r)

This saves m multiplications in the permutation proof.

## 5.6 Optimization: Amortized Sets

A set can be shared across multiple consumers. For instance, the set
{1, ..., T} used by RAM for timing checks can also serve comparison operations
elsewhere in the proof. Sharing amortizes the teardown cost (m input gates +
m multiplications) across all users.

# 6. Read/Write Memory (RAM)

## 6.1 Data Structure

```
type RAM {
    reads      : Vec<(F, F^l, F)>    // (addr, value, time) tuples
    writes     : Vec<(F, F^l, F)>
    valid_diffs: Set                   // set {1, ..., T}
    clock      : usize                 // public counter, starts at 1
    size       : usize                 // n
}
```

## 6.2 Protocol

**Setup(content: [F^l; n]):**
For each address i in [n]:
    writes.append((i, content[i], 0))     // time 0, all public
Initialize valid_diffs as a Set (Section 5) with keys {1, ..., T}.

**Access(op: F, addr: F, w: F^l) -> F^l:**
P inputs: old (l field elements), t (b authenticated bits representing the
          time when addr was last written)

// Timing check: prove clock - t is in {1, ..., T}
// clock is public, t is private. Compute diff = clock - t.
[diff] = integer_subtract(clock, [t])     // at most (b-2) AND gates (Section 3.2)
prove_member(valid_diffs, Pack(diff))      // (b-2) AND gates (version increment)

// Multiplex load vs store (applied component-wise for l-tuples)
[new] = [old] + [op] * ([w] - [old])      // l multiplication gates

// Record the access
reads.append((addr, old, Pack(t)))
writes.append((addr, new, clock))

clock += 1
return old

**Teardown -> [F^l; n]:**
content = []
For each address i in [n]:
    P inputs: val (l field elements), t (b authenticated bits)
    reads.append((i, val, Pack(t)))
    content.append(val)
Verify: reads ~ writes                    // permutation check
Teardown valid_diffs set
return content

## 6.3 Soundness Argument

The RAM invariant: before each access to address i, writes contains exactly one
tuple (i, val, t) not yet matched in reads. This tuple records the most recent
write.

**Permutation check** ensures every write is matched by a read and vice versa.

**Set membership check** ensures clock - t ∈ {1,...,T}, i.e., the claimed
write time t is strictly in the past. This prevents P from reading values
written in the future.

**Binary-field wrap-around safety.** Integer subtraction is computed mod 2^b. If
P claims a future time t > clock, the result wraps: diff = 2^b - (t - clock).
With the constraint 2^b ≥ 2T (Section 3.3), the wrapped value satisfies
2^b - (t - clock) ≥ 2^b - (T - 1) > T, so it is NOT in {1,...,T}. Without
this constraint, a circular-dependency attack is possible: two accesses each
claim to read from the other's write time, creating a cycle that the
permutation check alone cannot detect.

**Together** these imply that P must read the most recent write: if P claims an
older write time t' < t_latest, then the tuple (addr, val', t') was already
consumed by a previous read (it was matched in the permutation). P cannot
re-use it without creating a duplicate in reads that has no matching write.

**Address bounds.** The RAM does not explicitly check addr ∈ [0, n) at access
time. Out-of-range addresses are caught at teardown: teardown only iterates
over [0, n), so any writes to addresses outside this range are never consumed,
causing the permutation check to fail.

**op constraint.** The multiplex assumes op ∈ {0, 1}. This must be enforced by
the calling circuit (e.g., the CPU). The RAM primitive does not verify it.

**Soundness error:** (T + n) / 2^k from the permutation proofs, plus
2T / 2^k from the set's permutation proof. Total: O(T/2^k), negligible for
k = 128.

## 6.4 Cost Summary

Three cost types: **input gates** (P sends authenticated values), **AND gates**
(Boolean multiplications over F_2), and **F_{2^k} multiplications** (extension
field). All per-access costs below are amortized assuming T >> n.

Notation: b = ceil(log(2T)) for RAM/set, b_rom = ceil(log(T+1)) for standalone
ROM, l = tuple width, n = entries, T = accesses.

### Set Membership (size-m set, T queries)

Each query costs 1 input gate and (b - 2) AND gates for the version increment.
Teardown adds m input gates for final versions and a permutation proof on
vectors of length m + T, which costs 2(m + T - 1) F_{2^k} multiplications
(halved with public-setup optimization on the m setup entries).

**Per query (amortized):** 1 + m/T inputs, (b - 2) AND, ~(m + 2T)/T mults.
For the RAM's internal set (m = T): **2 inputs, (b - 2) AND, ~3 mults.**

### Read-Only Memory (n entries, l-element values)

Each lookup costs l + 1 input gates (value + version) and (b_rom - 2) AND gates
for the version increment. Teardown adds n input gates and a permutation proof
on vectors of length n + T.

**Per lookup (amortized):** l + 1 inputs, (b_rom - 2) AND, ~2 mults.

### Read/Write Memory (n entries, l-element values)

Each access performs integer subtraction (≤ b - 2 AND), a set membership query
(b - 2 AND, 1 input), and a load/store mux (l mults). P also inputs old value
and timestamp (l + 1 inputs). Teardown contributes two permutation proofs: one
for the RAM vectors (length T + n) and one for the set vectors (length 2T).

**Per access (amortized):** l + 3 inputs, ≤ 2(b - 2) AND, 5 + l mults.

For l = 1, b = 24 (T = 2^23): **4 inputs, ≤ 44 AND, 6 mults.** Matches
two-shuffles (Yang & Heath) at 4 inputs + 6 mults per access.

# 7. QuickSilver Polynomial Batching for Permutation Products

## 7.1 Problem

The permutation proofs in Sections 4–6 require fan-in-M products over
F_{2^k}:

    p(r) = prod_{i=1}^{M} (e_i + r)

where the entries e_i are committed F_{2^k} values (packed tuples) and r is the
verifier's public challenge.

In the gate-by-gate approach, this product is computed as M−1 sequential
F_{2^k} multiplications. Each intermediate product p_i ∈ F_{2^k} must be
committed, costing k subfield VOLEs per intermediate. Total: (M−1) × k sVOLEs.

Per RAM access (with public op, eliminating the load/store mux), there are 5
such product contributions. Gate-by-gate cost: **5k sVOLEs per access**.

## 7.2 Polynomial Batching

Reference: QuickSilver (Yang et al., CCS 2021), Section 5.

Split the fan-in-M product into chunks of ε−1 entries. Each chunk computes a
degree-ε sub-product:

    q_j = p_{j-1} × prod_{i ∈ chunk_j} (e_i + r)

where p_{j-1} is the previous chunk's boundary value (p_0 = 1).

This sub-product is a degree-ε polynomial in the variables (p_{j-1}, e_{i_1},
..., e_{i_{ε-1}}). All entry variables e_i are already committed from the
RAM access protocol. Only the chunk boundary values p_j require new
commitments.

All chunks share the same polynomial structure (degree-ε product). Using
QuickSilver's polynomial ZK protocol (Figure 6 of the paper), all chunks are
batch-verified with a single random challenge χ and a single shared VOPE
correlation of degree ε−1.

## 7.3 Cost Per Fan-In-M Product

Boundary commitments: ceil(M/(ε−1)) values in F_{2^k}, each costing k
subfield VOLEs:

    boundary cost = ceil(M/(ε−1)) × k  sVOLEs

VOPE correlation (one-time, shared across all chunks):

    VOPE cost = (2ε − 3) × k  sVOLEs

Prover sends (ε−1) F_{2^k} elements total for the polynomial check (batched
via χ across all chunks, per step 6b of Figure 6).

Per entry (amortized, M >> ε):

    cost per entry ≈ k/(ε−1)  sVOLEs

## 7.4 Application to RAM

Each RAM access contributes to 4 permutation products (with public op):

| Product | Fan-in M | Per access (amortized) |
|---------|----------|-----------------------|
| RAM reads | T + n | k/(ε−1) |
| RAM writes | T + n | k/(ε−1) |
| Set reads | T + m | k/(ε−1) |
| Set writes | T + m (m public setup) | k/(ε−1) |

The set has m = T elements ({1,...,T}). The set writes product includes m
public setup entries handled via the public-setup optimization (locally
computed, no committed intermediates).

Accounting for teardown entries (amortized over T accesses):
- RAM products: 2 × (T+n)/(ε−1) × k / T ≈ 2k/(ε−1) per access
- Set reads: (T+m)/(ε−1) × k / T ≈ 2k/(ε−1) per access (m = T)
- Set writes: T/(ε−1) × k / T = k/(ε−1) per access (public entries free)

**Total per access: 5k/(ε−1) sVOLEs.**

One-time VOPE costs (4 products, 1 VOPE each): 4 × (2ε−3) × k sVOLEs.
Amortized per access: negligible for T >> ε.

## 7.5 Soundness

Each product uses the polynomial ZK protocol at degree ε on t = ceil(M/(ε−1))
chunks. By Theorem 3 of QuickSilver, the soundness error per product is:

    (ε + ceil(M/(ε−1))) / 2^k

For ε = 16, M = T = 2^23, k = 64:

    error ≈ (16 + 559,241) / 2^64 ≈ 2^{−44.7}

This provides ρ ≈ 44.7 bits of statistical security, exceeding the standard
ρ = 40 requirement for information-theoretic ZK/MPC protocols.

## 7.6 Concrete Costs

**Parameters:** k = 64, ε = 16, l = 1, W = 32, b = 25.

k = 64 provides ρ > 40 bits of statistical security for T ≤ 2^23 (the
standard threshold for information-theoretic protocols). ε = 16 balances
chunk overhead against polynomial proof complexity (prover evaluates each
chunk at ε+1 interpolation points, O(ε²) work per chunk).

**Per access (with polynomial batching and public op):**

| Component | sVOLEs |
|-----------|--------|
| Inputs: old(32) + t(25) + set_version(25) | 82 |
| AND: timing(23) + set_increment(23) | 46 |
| Products: 5k/(ε−1) = 5 × 64/15 | 21 |
| **Total** | **149** |

# 8. Optimization: Periodic Reset

For very long executions (T' >> n), periodically tear down and re-setup the
RAM every T = O(n * sqrt(T'/n)) accesses. This:

1. Reduces the set size from T' to T, saving teardown cost
2. Allows reusing the same set {1, ..., T} across generations
3. Improves soundness by reducing permutation vector sizes

The teardown returns the RAM contents as authenticated wires, which are used
directly to initialize the next generation (no re-authentication needed).
