//! Source emitter. Walks an [`Ir`] and produces Rust source for the
//! corresponding `impl ProverKernel`.
//!
//! The emitter relies on the same slot-kind algebra as the runtime
//! evaluator — it just renders each operation as Rust source instead
//! of computing values. A small [`liveness`] pass prunes slots whose
//! values do not reach an emitted accumulator slot.

use std::fmt::Write;

use crate::ir::{ConstVal, Ir, NodeHandle, Op, SlotKind};

// ---------------------------------------------------------------------------
// Slot-name helpers
// ---------------------------------------------------------------------------

/// Naming convention:
///
/// * `n{node_id}_{slot}` for an `Extension` slot's `E`-typed local.
/// * `n{node_id}_{slot}_sub` for a `Subfield` slot's `W`-typed local.
///
/// `Zero` slots are not emitted. `Const(One)` is also not emitted as
/// a local — it's inlined at use sites.
fn slot_name(ir: &Ir, h: NodeHandle, k: usize) -> Option<String> {
    if matches!(ir.nodes[h.0].op, Op::Const(ConstVal::One)) {
        return None;
    }
    match ir.nodes[h.0].slot_kinds[k] {
        SlotKind::Zero => None,
        SlotKind::Subfield => Some(format!("n{}_{}_sub", h.0, k)),
        SlotKind::Extension => Some(format!("n{}_{}", h.0, k)),
    }
}

/// Render `<source>` such that the result has type `E`, lifting via
/// `E::embed(...)` if the slot referenced is subfield-typed.
fn ref_as_ext(ir: &Ir, h: NodeHandle, k: usize) -> Option<String> {
    // `Const(One)`'s slot 0 is `embed(W::one()) = E::one()`. Inline.
    if matches!(ir.nodes[h.0].op, Op::Const(ConstVal::One)) {
        debug_assert_eq!(k, 0);
        return Some("E::one()".to_string());
    }
    match ir.nodes[h.0].slot_kinds[k] {
        SlotKind::Zero => None,
        SlotKind::Subfield => Some(format!("E::embed(n{}_{}_sub)", h.0, k)),
        SlotKind::Extension => Some(format!("n{}_{}", h.0, k)),
    }
}

/// Render `<source>` such that the result has type `W` (slot must be
/// statically subfield-typed; otherwise returns `None`).
fn ref_as_sub(ir: &Ir, h: NodeHandle, k: usize) -> Option<String> {
    // `Const(One)`'s slot 0 is `W::one()`. Inline.
    if matches!(ir.nodes[h.0].op, Op::Const(ConstVal::One)) {
        debug_assert_eq!(k, 0);
        return Some("W::one()".to_string());
    }
    match ir.nodes[h.0].slot_kinds[k] {
        SlotKind::Subfield => Some(format!("n{}_{}_sub", h.0, k)),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Per-slot RHS rendering
// ---------------------------------------------------------------------------

/// Emit the RHS of `let n{n.0}_{k}[...] = <here>;` for slot `k` of
/// node `n`. Caller guarantees `n.slot_kinds[k] != Zero`.
fn render_rhs(ir: &Ir, n: NodeHandle, k: usize) -> String {
    let node = &ir.nodes[n.0];
    let out_kind = node.slot_kinds[k];
    debug_assert_ne!(out_kind, SlotKind::Zero);
    match node.op {
        Op::Var(i) => match k {
            0 => format!("macs[{i}]"),
            1 => format!("values[{i}]"),
            _ => unreachable!("Var has degree 1"),
        },
        Op::Const(ConstVal::Zero) => unreachable!("Zero slot is never rendered"),
        Op::Const(ConstVal::One) => "W::one()".to_string(),
        Op::Neg(a) => match out_kind {
            SlotKind::Subfield => format!("-{}", ref_as_sub(ir, a, k).unwrap()),
            SlotKind::Extension => format!("-({})", ref_as_ext(ir, a, k).unwrap()),
            SlotKind::Zero => unreachable!(),
        },
        Op::Add(a, b) => {
            let da = ir.nodes[a.0].degree;
            let db = ir.nodes[b.0].degree;
            let d = da.max(db);
            let shift_a = d - da;
            let shift_b = d - db;
            let from_a = (k >= shift_a).then(|| (a, k - shift_a));
            let from_b = (k >= shift_b).then(|| (b, k - shift_b));
            render_add(ir, from_a, from_b, out_kind)
        }
        Op::Mul(a, b) => {
            let da = ir.nodes[a.0].degree;
            let db = ir.nodes[b.0].degree;
            // Convolution pairs (i, j) with i + j = k.
            let pairs: Vec<(usize, usize)> = (0..=da)
                .filter_map(|i| {
                    let j = k.checked_sub(i)?;
                    (j <= db).then_some((i, j))
                })
                .collect();
            render_mul(ir, a, b, &pairs, out_kind)
        }
    }
}

fn render_add(
    ir: &Ir,
    from_a: Option<(NodeHandle, usize)>,
    from_b: Option<(NodeHandle, usize)>,
    out_kind: SlotKind,
) -> String {
    // Render in the output's type:
    //   - Subfield output: both contributors must be subfield; render with
    //     `<sub_name> + <sub_name>`.
    //   - Extension output: lift any subfield contributor via embed, then sum.
    let mut terms: Vec<String> = Vec::new();
    let push_term = |terms: &mut Vec<String>, h: NodeHandle, k: usize| {
        if matches!(ir.nodes[h.0].slot_kinds[k], SlotKind::Zero) {
            return;
        }
        let s = match out_kind {
            SlotKind::Subfield => ref_as_sub(ir, h, k).expect("Sub output requires Sub contrib"),
            SlotKind::Extension => ref_as_ext(ir, h, k).unwrap(),
            SlotKind::Zero => unreachable!(),
        };
        terms.push(s);
    };
    if let Some((h, k)) = from_a {
        push_term(&mut terms, h, k);
    }
    if let Some((h, k)) = from_b {
        push_term(&mut terms, h, k);
    }
    debug_assert!(!terms.is_empty(), "Add output Zero should be skipped");
    terms.join(" + ")
}

fn render_mul(
    ir: &Ir,
    a: NodeHandle,
    b: NodeHandle,
    pairs: &[(usize, usize)],
    out_kind: SlotKind,
) -> String {
    // For each (i, j), render the term `a[i] · b[j]`:
    //   (Zero, _) / (_, Zero):  skip
    //   (Sub,  Sub):  `na_i_sub * nb_j_sub` (in W)
    //   (Sub,  Ext):  `nb_j.scale_by_subfield(na_i_sub)` (or symmetric)
    //   (Ext,  Ext):  `na_i * nb_j` (full mul)
    let mut terms: Vec<String> = Vec::new();
    for &(i, j) in pairs {
        let ka = ir.nodes[a.0].slot_kinds[i];
        let kb = ir.nodes[b.0].slot_kinds[j];
        if ka == SlotKind::Zero || kb == SlotKind::Zero {
            continue;
        }
        let term = match (ka, kb) {
            (SlotKind::Subfield, SlotKind::Subfield) => {
                // Sub × Sub stays subfield. If the OUTPUT slot is extension,
                // wrap in embed.
                let s = format!(
                    "{} * {}",
                    ref_as_sub(ir, a, i).unwrap(),
                    ref_as_sub(ir, b, j).unwrap()
                );
                if out_kind == SlotKind::Subfield {
                    s
                } else {
                    format!("E::embed({s})")
                }
            }
            (SlotKind::Subfield, SlotKind::Extension) => format!(
                "{}.scale_by_subfield({})",
                ref_as_ext(ir, b, j).unwrap(),
                ref_as_sub(ir, a, i).unwrap()
            ),
            (SlotKind::Extension, SlotKind::Subfield) => format!(
                "{}.scale_by_subfield({})",
                ref_as_ext(ir, a, i).unwrap(),
                ref_as_sub(ir, b, j).unwrap()
            ),
            (SlotKind::Extension, SlotKind::Extension) => format!(
                "{} * {}",
                ref_as_ext(ir, a, i).unwrap(),
                ref_as_ext(ir, b, j).unwrap()
            ),
            _ => unreachable!(),
        };
        terms.push(term);
    }
    debug_assert!(!terms.is_empty(), "Mul output Zero should be skipped");
    terms.join(" + ")
}

// ---------------------------------------------------------------------------
// Liveness
// ---------------------------------------------------------------------------

/// Compute the set of `(node, slot)` pairs whose value reaches an
/// emitted accumulator slot. Walks backward from the output's slots
/// `0..degree` (the slot at `degree` is the dropped top, not live)
/// through each node's `Op`-specific parent dependencies. `Const(One)`
/// is excluded because it gets inlined at use sites, not bound to a
/// local.
fn liveness(ir: &Ir) -> std::collections::HashSet<(NodeHandle, usize)> {
    use std::collections::HashSet;
    let mut live: HashSet<(NodeHandle, usize)> = HashSet::new();
    let mut worklist: Vec<(NodeHandle, usize)> = Vec::new();
    let output = ir
        .output
        .expect("trace must bind an output before liveness");
    let degree = ir.nodes[output.0].degree;

    let mark = |live: &mut HashSet<(NodeHandle, usize)>,
                worklist: &mut Vec<(NodeHandle, usize)>,
                h: NodeHandle,
                k: usize| {
        // Skip slots that are either zero (no local emitted) or
        // belong to a `Const(One)` node (inlined, no local emitted).
        if ir.nodes[h.0].slot_kinds[k] == SlotKind::Zero
            || matches!(ir.nodes[h.0].op, Op::Const(ConstVal::One))
        {
            return;
        }
        if live.insert((h, k)) {
            worklist.push((h, k));
        }
    };

    // Seed: output's non-top slots.
    for k in 0..degree {
        mark(&mut live, &mut worklist, output, k);
    }

    while let Some((h, k)) = worklist.pop() {
        let node = &ir.nodes[h.0];
        match node.op {
            Op::Var(_) | Op::Const(_) => {}
            Op::Neg(a) => mark(&mut live, &mut worklist, a, k),
            Op::Add(a, b) => {
                let da = ir.nodes[a.0].degree;
                let db = ir.nodes[b.0].degree;
                let d = da.max(db);
                let shift_a = d - da;
                let shift_b = d - db;
                if k >= shift_a {
                    mark(&mut live, &mut worklist, a, k - shift_a);
                }
                if k >= shift_b {
                    mark(&mut live, &mut worklist, b, k - shift_b);
                }
            }
            Op::Mul(a, b) => {
                let da = ir.nodes[a.0].degree;
                let db = ir.nodes[b.0].degree;
                for i in 0..=da {
                    if let Some(j) = k.checked_sub(i)
                        && j <= db
                    {
                        mark(&mut live, &mut worklist, a, i);
                        mark(&mut live, &mut worklist, b, j);
                    }
                }
            }
        }
    }

    live
}

// ---------------------------------------------------------------------------
// Public emitter API
// ---------------------------------------------------------------------------

/// Paths used by the emitted source to reference the kernel traits
/// and the `ExtensionField` / `Field` bounds. Parameterized so the
/// same emitter can produce code that compiles both *inside*
/// `mpz-poly-proof-core` (where `crate::kernel::…` works) and
/// *outside* it (via an external absolute path).
#[derive(Debug, Clone)]
pub struct Paths {
    /// Path to the `ProverKernel` trait (prover side).
    pub kernel: String,
    /// Path to the `VerifierKernel` trait.
    pub verifier_kernel: String,
    /// Path to the `ConstraintDef` trait.
    pub constraint_def: String,
    /// Path to `ExtensionField`.
    pub extension_field: String,
    /// Path to `Field`.
    pub field: String,
}

impl Default for Paths {
    fn default() -> Self {
        // Default: external absolute paths suitable for `include!`-ing
        // generated code into any crate that has `mpz_poly_proof_core`
        // and `mpz_fields` as dependencies.
        Self {
            kernel: "::mpz_poly_proof_core::kernel::ProverKernel".into(),
            verifier_kernel: "::mpz_poly_proof_core::kernel::VerifierKernel".into(),
            constraint_def: "::mpz_poly_proof_core::kernel::ConstraintDef".into(),
            extension_field: "::mpz_fields::ExtensionField".into(),
            field: "::mpz_fields::Field".into(),
        }
    }
}

/// Emit the **prover-side** `ProverKernel` impl for `name` from
/// `ir`, referencing trait/bound paths from `paths`.
///
/// Produces:
///
/// ```ignore
/// pub struct <Name>;
/// impl<E, W> ProverKernel<E, W> for <Name>
/// where E: ExtensionField<W>, W: Field
/// {
///     const NUM_VARS: usize = <ir.num_vars>;
///     const DEGREE: usize = <ir.output.degree>;
///     fn accumulate(macs: &[E], values: &[W], chi: E, accumulators: &mut [E]) {}
/// }
/// ```
pub fn emit_prover(name: &str, ir: &Ir, paths: &Paths) -> String {
    let mut out = String::new();
    let output = ir.output.expect("trace must bind an output before emit");
    let degree = ir.nodes[output.0].degree;

    writeln!(out, "pub struct {name};").unwrap();
    writeln!(out).unwrap();
    writeln!(out, "impl<E, W> {}<E, W> for {name}", paths.kernel).unwrap();
    writeln!(out, "where").unwrap();
    writeln!(out, "    E: {}<W>,", paths.extension_field).unwrap();
    writeln!(out, "    W: {},", paths.field).unwrap();
    writeln!(out, "{{").unwrap();
    writeln!(out, "    const NUM_VARS: usize = {};", ir.num_vars).unwrap();
    writeln!(out, "    const DEGREE: usize = {};", degree).unwrap();
    writeln!(out).unwrap();
    writeln!(
        out,
        "    fn accumulate(macs: &[E], values: &[W], chi: E, accumulators: &mut [E]) {{"
    )
    .unwrap();
    // Safety asserts. Mirror what the hand-written kernels do.
    writeln!(out, "        unsafe {{").unwrap();
    writeln!(
        out,
        "            std::hint::assert_unchecked(macs.len() >= {});",
        ir.num_vars
    )
    .unwrap();
    writeln!(
        out,
        "            std::hint::assert_unchecked(values.len() >= {});",
        ir.num_vars
    )
    .unwrap();
    writeln!(
        out,
        "            std::hint::assert_unchecked(accumulators.len() >= {});",
        degree
    )
    .unwrap();
    writeln!(out, "        }}").unwrap();
    writeln!(out).unwrap();

    // Liveness pass: only emit lets for slots that feed an emitted
    // accumulator slot. Drops `Const(One)` (inlined), dead witness
    // slots that only feed the dropped top, and Mul outputs whose
    // top coefficient is the constraint's witness-only value.
    let live = liveness(ir);

    for (id, node) in ir.nodes.iter().enumerate() {
        let h = NodeHandle(id);
        for k in 0..node.slot_kinds.len() {
            if !live.contains(&(h, k)) {
                continue;
            }
            let kind = node.slot_kinds[k];
            let ty = match kind {
                SlotKind::Subfield => ": W",
                SlotKind::Extension => "",
                SlotKind::Zero => unreachable!("Zero slots are never marked live"),
            };
            let name = slot_name(ir, h, k).expect("live slot must have a name");
            let rhs = render_rhs(ir, h, k);
            writeln!(out, "        let {name}{ty} = {rhs};").unwrap();
        }
    }

    // Accumulator update: out[k] for k in 0..degree, dropping the top.
    writeln!(out).unwrap();
    writeln!(out, "        let n = accumulators.len();").unwrap();
    for k in 0..degree {
        // Output's slot k must be extension when it lands here; lift if needed.
        let out_kind = ir.nodes[output.0].slot_kinds[k];
        if out_kind == SlotKind::Zero {
            // No contribution to this accumulator slot.
            continue;
        }
        let term = ref_as_ext(ir, output, k).unwrap();
        writeln!(
            out,
            "        accumulators[n - {}] = accumulators[n - {}] + ({term}) * chi;",
            degree - k,
            degree - k
        )
        .unwrap();
    }

    writeln!(out, "    }}").unwrap();
    writeln!(out, "}}").unwrap();
    out
}

/// Emit the **verifier-side** `VerifierKernel` impl for `name` from
/// `ir`.
///
/// Produces:
///
/// ```ignore
/// pub struct <Name>;
/// impl<E> VerifierKernel<E> for <Name>
/// where E: Field
/// {
///     const NUM_VARS: usize = <ir.num_vars>;
///     const DEGREE: usize = <ir.output.degree>;
///     fn evaluate(keys: &[E], delta_pow: &[E]) -> E {}
/// }
/// ```
pub fn emit_verifier(name: &str, ir: &Ir, paths: &Paths) -> String {
    let mut out = String::new();
    let output = ir.output.expect("trace must bind an output before emit");
    let degree = ir.nodes[output.0].degree;

    writeln!(out, "pub struct {name};").unwrap();
    writeln!(out).unwrap();
    writeln!(out, "impl<E> {}<E> for {name}", paths.verifier_kernel).unwrap();
    writeln!(out, "where").unwrap();
    writeln!(out, "    E: {},", paths.field).unwrap();
    writeln!(out, "{{").unwrap();
    writeln!(out, "    const NUM_VARS: usize = {};", ir.num_vars).unwrap();
    writeln!(out, "    const DEGREE: usize = {};", degree).unwrap();
    writeln!(out).unwrap();
    writeln!(out, "    fn evaluate(keys: &[E], delta_pow: &[E]) -> E {{").unwrap();
    writeln!(out, "        unsafe {{").unwrap();
    writeln!(
        out,
        "            std::hint::assert_unchecked(keys.len() >= {});",
        ir.num_vars
    )
    .unwrap();
    writeln!(
        out,
        "            std::hint::assert_unchecked(delta_pow.len() > {});",
        degree
    )
    .unwrap();
    writeln!(out, "        }}").unwrap();
    writeln!(out).unwrap();

    // Liveness: only emit locals for nodes that transitively feed the
    // output. Skips dead sub-DAGs that the constraint built but didn't
    // end up using (rare, but matches the prover-kernel emitter's
    // hygiene).
    let live = liveness_verifier(ir);

    // The output node is rendered as the block's tail expression rather
    // than `let n.. = ..; n..` (which trips `clippy::let_and_return`).
    let mut output_rhs = String::new();
    for (id, node) in ir.nodes.iter().enumerate() {
        let h = NodeHandle(id);
        if !live.contains(&h) {
            continue;
        }
        let rhs = match node.op {
            Op::Var(i) => format!("keys[{i}]"),
            Op::Const(ConstVal::Zero) => "E::zero()".to_string(),
            Op::Const(ConstVal::One) => "E::one()".to_string(),
            Op::Neg(a) => format!("-n{}", a.0),
            Op::Mul(a, b) => format!("n{} * n{}", a.0, b.0),
            Op::Add(a, b) => {
                let da = ir.nodes[a.0].degree;
                let db = ir.nodes[b.0].degree;
                let d = da.max(db);
                let shift_a = d - da;
                let shift_b = d - db;
                let term_a = if shift_a == 0 {
                    format!("n{}", a.0)
                } else {
                    format!("n{} * delta_pow[{}]", a.0, shift_a)
                };
                let term_b = if shift_b == 0 {
                    format!("n{}", b.0)
                } else {
                    format!("n{} * delta_pow[{}]", b.0, shift_b)
                };
                format!("{term_a} + {term_b}")
            }
        };
        if h == output {
            output_rhs = rhs;
        } else {
            writeln!(out, "        let n{id} = {rhs};").unwrap();
        }
    }

    writeln!(out).unwrap();
    writeln!(out, "        {output_rhs}").unwrap();
    writeln!(out, "    }}").unwrap();
    writeln!(out, "}}").unwrap();
    out
}

/// Transitive backward reach from the output node.
fn liveness_verifier(ir: &Ir) -> std::collections::HashSet<NodeHandle> {
    use std::collections::HashSet;
    let mut live: HashSet<NodeHandle> = HashSet::new();
    let mut worklist: Vec<NodeHandle> = Vec::new();
    let output = ir
        .output
        .expect("trace must bind an output before liveness");
    live.insert(output);
    worklist.push(output);
    while let Some(h) = worklist.pop() {
        let parents: Vec<NodeHandle> = match ir.nodes[h.0].op {
            Op::Var(_) | Op::Const(_) => vec![],
            Op::Neg(a) => vec![a],
            Op::Add(a, b) | Op::Mul(a, b) => vec![a, b],
        };
        for p in parents {
            if live.insert(p) {
                worklist.push(p);
            }
        }
    }
    live
}

/// Emit the `ConstraintDef` bundle binding a prover-kernel struct and
/// a verifier-kernel struct under one registration-friendly type.
/// Mirrors what the `#[poly_kernel]` macro emits on its side; lets
/// `build.rs` produce the same bundle for constraints whose original
/// fn lives in an upstream crate (where the macro can't reach).
///
/// Produces:
///
/// ```ignore
/// pub struct <Name>;
/// impl<E, W> ConstraintDef<E, W> for <Name>
/// where E: ExtensionField<W>, W: Field
/// {
///     const NUM_VARS: usize = <ir.num_vars>;
///     const DEGREE: usize = <ir.output.degree>;
///     type ProverKernel = <prover_kernel>;
///     type VerifierKernel = <verifier_kernel>;
/// }
/// ```
pub fn emit_constraint_def(
    name: &str,
    prover_kernel: &str,
    verifier_kernel: &str,
    ir: &Ir,
    paths: &Paths,
) -> String {
    let mut out = String::new();
    let output = ir.output.expect("trace must bind an output before emit");
    let degree = ir.nodes[output.0].degree;
    let num_vars = ir.num_vars;

    writeln!(out, "pub struct {name};").unwrap();
    writeln!(out).unwrap();
    writeln!(out, "impl<E, W> {}<E, W> for {name}", paths.constraint_def).unwrap();
    writeln!(out, "where").unwrap();
    writeln!(out, "    E: {}<W>,", paths.extension_field).unwrap();
    writeln!(out, "    W: {},", paths.field).unwrap();
    writeln!(out, "{{").unwrap();
    writeln!(out, "    const NUM_VARS: usize = {num_vars};").unwrap();
    writeln!(out, "    const DEGREE: usize = {degree};").unwrap();
    writeln!(out, "    type ProverKernel = {prover_kernel};").unwrap();
    writeln!(out, "    type VerifierKernel = {verifier_kernel};").unwrap();
    writeln!(out, "}}").unwrap();
    out
}
