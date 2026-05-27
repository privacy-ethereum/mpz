//! Test-only utilities shared across the lifter's test modules.
//!
//! Two independent ways to produce the constraint polynomial of a
//! traced constraint live here:
//!
//!   * [`PolyCtx`] — a `Context` impl that walks the original closure directly.
//!     Wires are `Vec<E>` polynomial coefficient vectors (held in the Context's
//!     own table; indexed by `usize`). Ops mirror the protocol's lift semantics
//!     — top-aligned add, polynomial-convolution mul, per-coefficient negation.
//!     Does **not** go through the lifter's IR.
//!
//!   * [`evaluate_ir_full`] — walks an [`Ir`] per slot with kind-aware dispatch
//!     (subfield slots compute in `W`, extension slots in `E`), then collapses
//!     the output's slot vector into a full `Vec<E>` (top slot included).
//!
//! Comparison of the two outputs is a strong consistency check on
//! the IR pipeline: the oracle never goes through `trace_constraint`
//! or the slot-kind algebra, so any divergence implicates the IR
//! layer.

use mpz_circuits_new::Context;
use mpz_fields::{ExtensionField, Field};

use crate::ir::{ConstVal, Ir, NodeHandle, Op, SlotKind};

// ---------------------------------------------------------------------------
// Closure oracle
// ---------------------------------------------------------------------------

/// `Context` impl whose wires are polynomial coefficient vectors.
/// Owns the vectors in `polys`; wires are indices into it (required
/// because [`Context::Wire`] must be `Copy`).
pub(crate) struct PolyCtx<E: Field> {
    polys: Vec<Vec<E>>,
    out: Option<Vec<E>>,
}

impl<E: Field> PolyCtx<E> {
    pub(crate) fn new() -> Self {
        Self {
            polys: Vec::new(),
            out: None,
        }
    }

    /// Register a polynomial and return its wire index.
    pub(crate) fn push(&mut self, p: Vec<E>) -> usize {
        self.polys.push(p);
        self.polys.len() - 1
    }

    /// Consume the Context and return the polynomial recorded by
    /// `assert_const` (which the constraint must call once at the end).
    pub(crate) fn into_output(self) -> Vec<E> {
        self.out.expect("constraint must call assert_const")
    }
}

impl<E: Field> Context for PolyCtx<E> {
    type Error = ();
    type Wire = usize;
    type Field = E;

    /// Top-aligned add: pad the shorter operand with leading zeros
    /// (the QuickSilver lift convention — the lower-degree operand's
    /// top coefficient must align with the higher's).
    fn add(&mut self, a: usize, b: usize) -> usize {
        let av = self.polys[a].clone();
        let bv = self.polys[b].clone();
        let len = av.len().max(bv.len());
        let mut out = vec![E::zero(); len];
        let off_a = len - av.len();
        for (k, &v) in av.iter().enumerate() {
            out[off_a + k] = out[off_a + k] + v;
        }
        let off_b = len - bv.len();
        for (k, &v) in bv.iter().enumerate() {
            out[off_b + k] = out[off_b + k] + v;
        }
        self.push(out)
    }

    /// `a - b` via `a + (-b)`. Negation is per-coefficient.
    fn sub(&mut self, a: usize, b: usize) -> usize {
        let neg_b: Vec<E> = self.polys[b].iter().map(|&x| E::zero() - x).collect();
        let nb = self.push(neg_b);
        self.add(a, nb)
    }

    /// Polynomial convolution: `out[i + j] += a[i] * b[j]`.
    fn mul(&mut self, a: usize, b: usize) -> usize {
        let av = self.polys[a].clone();
        let bv = self.polys[b].clone();
        let out_len = av.len() + bv.len() - 1;
        let mut out = vec![E::zero(); out_len];
        for (i, &ai) in av.iter().enumerate() {
            for (j, &bj) in bv.iter().enumerate() {
                out[i + j] = out[i + j] + ai * bj;
            }
        }
        self.push(out)
    }

    /// Constants are degree-0 polynomials.
    fn constant(&mut self, v: E) -> usize {
        self.push(vec![v])
    }

    /// Records the output polynomial. `expected` is ignored — we want
    /// the polynomial, not a satisfaction check.
    fn assert_const(&mut self, v: usize, _expected: E) -> Result<(), ()> {
        self.out = Some(self.polys[v].clone());
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// IR walker
// ---------------------------------------------------------------------------

/// Walk an [`Ir`] per slot and return the output node's full
/// coefficient vector lifted to `E`. The top slot is included
/// (unlike the production accumulator path, which drops it).
pub(crate) fn evaluate_ir_full<E, W>(ir: &Ir, macs: &[E], values: &[W]) -> Vec<E>
where
    E: ExtensionField<W>,
    W: Field,
{
    let mut node_ext: Vec<Vec<E>> = Vec::with_capacity(ir.nodes.len());
    let mut node_sub: Vec<Vec<W>> = Vec::with_capacity(ir.nodes.len());

    for node in &ir.nodes {
        let mut ext_vec = vec![E::zero(); node.degree + 1];
        let mut sub_vec = vec![W::zero(); node.degree + 1];

        match node.op {
            Op::Var(i) => {
                ext_vec[0] = macs[i];
                sub_vec[1] = values[i];
            }
            Op::Const(ConstVal::Zero) => {}
            Op::Const(ConstVal::One) => {
                sub_vec[0] = W::one();
            }
            Op::Neg(a) => {
                for k in 0..=node.degree {
                    match node.slot_kinds[k] {
                        SlotKind::Zero => {}
                        SlotKind::Subfield => sub_vec[k] = W::zero() - node_sub[a.0][k],
                        SlotKind::Extension => ext_vec[k] = E::zero() - node_ext[a.0][k],
                    }
                }
            }
            Op::Add(a, b) => {
                let da = ir.nodes[a.0].degree;
                let db = ir.nodes[b.0].degree;
                let d = da.max(db);
                let shift_a = d - da;
                let shift_b = d - db;
                for k in 0..=d {
                    let kind = node.slot_kinds[k];
                    if kind == SlotKind::Zero {
                        continue;
                    }
                    let from_a = (k >= shift_a).then(|| (a, k - shift_a));
                    let from_b = (k >= shift_b).then(|| (b, k - shift_b));
                    let (ext_v, sub_v) = eval_add(ir, &node_ext, &node_sub, from_a, from_b, kind);
                    if kind == SlotKind::Subfield {
                        sub_vec[k] = sub_v;
                    } else {
                        ext_vec[k] = ext_v;
                    }
                }
            }
            Op::Mul(a, b) => {
                let da = ir.nodes[a.0].degree;
                let db = ir.nodes[b.0].degree;
                for k in 0..=node.degree {
                    let kind = node.slot_kinds[k];
                    if kind == SlotKind::Zero {
                        continue;
                    }
                    let pairs: Vec<(usize, usize)> = (0..=da)
                        .filter_map(|i| {
                            let j = k.checked_sub(i)?;
                            (j <= db).then_some((i, j))
                        })
                        .collect();
                    let (ext_v, sub_v) = eval_mul(ir, &node_ext, &node_sub, a, b, &pairs, kind);
                    if kind == SlotKind::Subfield {
                        sub_vec[k] = sub_v;
                    } else {
                        ext_vec[k] = ext_v;
                    }
                }
            }
        }

        node_ext.push(ext_vec);
        node_sub.push(sub_vec);
    }

    let output = ir.output.expect("output bound");
    let degree = ir.nodes[output.0].degree;
    let mut full = Vec::with_capacity(degree + 1);
    for k in 0..=degree {
        full.push(match ir.nodes[output.0].slot_kinds[k] {
            SlotKind::Zero => E::zero(),
            SlotKind::Subfield => E::embed(node_sub[output.0][k]),
            SlotKind::Extension => node_ext[output.0][k],
        });
    }
    full
}

fn eval_add<E, W>(
    ir: &Ir,
    node_ext: &[Vec<E>],
    node_sub: &[Vec<W>],
    from_a: Option<(NodeHandle, usize)>,
    from_b: Option<(NodeHandle, usize)>,
    out_kind: SlotKind,
) -> (E, W)
where
    E: ExtensionField<W>,
    W: Field,
{
    let mut ext_v = E::zero();
    let mut sub_v = W::zero();
    for contrib in [from_a, from_b].into_iter().flatten() {
        let (h, k) = contrib;
        let kind = ir.nodes[h.0].slot_kinds[k];
        match (out_kind, kind) {
            (_, SlotKind::Zero) => {}
            (SlotKind::Subfield, SlotKind::Subfield) => sub_v = sub_v + node_sub[h.0][k],
            (SlotKind::Extension, SlotKind::Subfield) => ext_v = ext_v + E::embed(node_sub[h.0][k]),
            (SlotKind::Extension, SlotKind::Extension) => ext_v = ext_v + node_ext[h.0][k],
            (SlotKind::Subfield, SlotKind::Extension) | (SlotKind::Zero, _) => {
                unreachable!("kind algebra: Sub output requires Sub contribs only")
            }
        }
    }
    (ext_v, sub_v)
}

fn eval_mul<E, W>(
    ir: &Ir,
    node_ext: &[Vec<E>],
    node_sub: &[Vec<W>],
    a: NodeHandle,
    b: NodeHandle,
    pairs: &[(usize, usize)],
    out_kind: SlotKind,
) -> (E, W)
where
    E: ExtensionField<W>,
    W: Field,
{
    let mut ext_v = E::zero();
    let mut sub_v = W::zero();
    for &(i, j) in pairs {
        let ka = ir.nodes[a.0].slot_kinds[i];
        let kb = ir.nodes[b.0].slot_kinds[j];
        match (ka, kb) {
            (SlotKind::Zero, _) | (_, SlotKind::Zero) => {}
            (SlotKind::Subfield, SlotKind::Subfield) => {
                let term = node_sub[a.0][i] * node_sub[b.0][j];
                if out_kind == SlotKind::Subfield {
                    sub_v = sub_v + term;
                } else {
                    ext_v = ext_v + E::embed(term);
                }
            }
            (SlotKind::Subfield, SlotKind::Extension) => {
                ext_v = ext_v + node_ext[b.0][j].scale_by_subfield(node_sub[a.0][i]);
            }
            (SlotKind::Extension, SlotKind::Subfield) => {
                ext_v = ext_v + node_ext[a.0][i].scale_by_subfield(node_sub[b.0][j]);
            }
            (SlotKind::Extension, SlotKind::Extension) => {
                ext_v = ext_v + node_ext[a.0][i] * node_ext[b.0][j];
            }
        }
    }
    (ext_v, sub_v)
}
