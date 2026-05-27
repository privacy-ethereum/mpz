//! IR types: the structural representation of a traced constraint.

/// Handle into [`Ir::nodes`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NodeHandle(pub usize);

/// Operation at an IR node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    /// Input variable, by index into the kernel's `macs` / `values` slices.
    Var(usize),
    /// Constant. Only `Zero` / `One` are supported (all the step-circuit
    /// fixtures use). Arbitrary constants would need a richer encoding.
    Const(ConstVal),
    /// Negation. Same degree and slot-kind structure as the operand.
    Neg(NodeHandle),
    /// `Add(a, b)` — polynomial Add with Δ-shift on the lower-degree
    /// operand. Output degree = max(deg(a), deg(b)).
    Add(NodeHandle, NodeHandle),
    /// `Mul(a, b)` — polynomial convolution. Output degree =
    /// deg(a) + deg(b).
    Mul(NodeHandle, NodeHandle),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConstVal {
    Zero,
    One,
}

/// Slot kind. One per polynomial coefficient. Determines what the
/// emitter writes for that slot:
///
/// * `Zero`: the slot is statically zero. The emitter omits it entirely.
/// * `Subfield`: the slot's value lives in `W` (the subfield). The emitter
///   writes a `let n{id}_{k}_sub: W = …;` local.
/// * `Extension`: the slot is a general `E` element. The emitter writes a `let
///   n{id}_{k}: E = …;` local.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlotKind {
    Zero,
    Subfield,
    Extension,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IrNode {
    pub op: Op,
    pub degree: usize,
    /// One per coefficient, length = `degree + 1`.
    pub slot_kinds: Vec<SlotKind>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ir {
    pub num_vars: usize,
    pub nodes: Vec<IrNode>,
    pub output: Option<NodeHandle>,
}

// ---------------------------------------------------------------------------
// Builder API (subfield-generic, no `Context` needed)
// ---------------------------------------------------------------------------
//
// These methods let callers build an `Ir` directly, without going
// through a `Context` impl (which is parameterized on `(E, W)`). The
// AST-interpreting proc macro uses this surface; `KernelEmitter` in
// `trace.rs` provides the runtime-traced equivalent for callers that
// have concrete field types.

impl Ir {
    pub fn new() -> Self {
        Self {
            num_vars: 0,
            nodes: Vec::new(),
            output: None,
        }
    }

    fn push(&mut self, node: IrNode) -> NodeHandle {
        let h = NodeHandle(self.nodes.len());
        self.nodes.push(node);
        h
    }

    /// Allocate a `Var(idx)` node. Slots: `[Extension, Subfield]`, degree 1.
    pub fn op_var(&mut self, idx: usize) -> NodeHandle {
        self.num_vars = self.num_vars.max(idx + 1);
        self.push(IrNode {
            op: Op::Var(idx),
            degree: 1,
            slot_kinds: vec![SlotKind::Extension, SlotKind::Subfield],
        })
    }

    /// Allocate a `Const(Zero)` node. Slot: `[Zero]`, degree 0.
    pub fn op_const_zero(&mut self) -> NodeHandle {
        self.push(IrNode {
            op: Op::Const(ConstVal::Zero),
            degree: 0,
            slot_kinds: vec![SlotKind::Zero],
        })
    }

    /// Allocate a `Const(One)` node. Slot: `[Subfield]`, degree 0.
    /// `embed(W::one())` is a subfield value.
    pub fn op_const_one(&mut self) -> NodeHandle {
        self.push(IrNode {
            op: Op::Const(ConstVal::One),
            degree: 0,
            slot_kinds: vec![SlotKind::Subfield],
        })
    }

    /// Emit `Add(a, b)`. Computes the result's slot kinds via the
    /// algebra's Δ-shifted addition rules.
    pub fn op_add(&mut self, a: NodeHandle, b: NodeHandle) -> NodeHandle {
        let na = &self.nodes[a.0];
        let nb = &self.nodes[b.0];
        let slot_kinds =
            crate::algebra::add_slot_kinds(&na.slot_kinds, na.degree, &nb.slot_kinds, nb.degree);
        let degree = na.degree.max(nb.degree);
        self.push(IrNode {
            op: Op::Add(a, b),
            degree,
            slot_kinds,
        })
    }

    /// Emit `Mul(a, b)`. Result's slot kinds come from convolution.
    pub fn op_mul(&mut self, a: NodeHandle, b: NodeHandle) -> NodeHandle {
        let na = &self.nodes[a.0];
        let nb = &self.nodes[b.0];
        let slot_kinds = crate::algebra::mul_slot_kinds(&na.slot_kinds, &nb.slot_kinds);
        let degree = na.degree + nb.degree;
        self.push(IrNode {
            op: Op::Mul(a, b),
            degree,
            slot_kinds,
        })
    }

    /// Emit `Neg(a)`. Slot kinds carry through unchanged.
    pub fn op_neg(&mut self, a: NodeHandle) -> NodeHandle {
        let na = &self.nodes[a.0];
        let slot_kinds = na.slot_kinds.clone();
        let degree = na.degree;
        self.push(IrNode {
            op: Op::Neg(a),
            degree,
            slot_kinds,
        })
    }

    /// Set the output node — the wire that the constraint's
    /// `assert_const(_, 0)` was applied to.
    pub fn set_output(&mut self, h: NodeHandle) {
        self.output = Some(h);
    }
}

impl Default for Ir {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    //! Cross-check the IR's polynomial against an independent closure
    //! oracle. The two evaluators ([`PolyCtx`] and
    //! [`evaluate_ir_full`]) and the closure walker live in
    //! [`crate::test_utils`]; the comparison logic lives here.
    //!
    //! [`PolyCtx`]: crate::test_utils::PolyCtx
    //! [`evaluate_ir_full`]: crate::test_utils::evaluate_ir_full

    use mpz_circuits_new::fixtures;
    use mpz_fields::{ExtensionField, gf2::Gf2, gf2_64::Gf2_64};

    use crate::{
        LifterError,
        test_utils::{PolyCtx, evaluate_ir_full},
        trace_constraint,
    };

    /// For each fixture, build the constraint polynomial two
    /// independent ways and assert equality coefficient by
    /// coefficient.
    #[test]
    fn ir_polynomial_matches_closure_oracle() {
        macro_rules! check {
            ($name:literal, $fixture:path, $num_vars:literal) => {{
                // Deterministic per-fixture inputs (no rng dep needed).
                // mac_i is a Weyl-style sequence; value_i alternates 0/1.
                let macs: [Gf2_64; $num_vars] = std::array::from_fn(|i| {
                    Gf2_64(0x9e3779b97f4a7c15u64.wrapping_mul(1 + i as u64))
                });
                let values: [Gf2; $num_vars] = std::array::from_fn(|i| Gf2((i & 1) == 1));

                // Oracle: walk the closure via PolyCtx. Each var wire
                // is the polynomial [mac, embed(value)] (degree 1),
                // registered in the Context's poly table.
                let mut ctx = PolyCtx::<Gf2_64>::new();
                let var_wires: [usize; $num_vars] =
                    std::array::from_fn(|i| ctx.push(vec![macs[i], Gf2_64::embed(values[i])]));
                $fixture(&mut ctx, var_wires).expect("oracle run");
                let oracle_poly = ctx.into_output();

                // Under test: trace → evaluate_ir_full.
                let ir = trace_constraint::<Gf2_64, Gf2, _, $num_vars>(|ctx, vars| {
                    $fixture(ctx, vars).map_err(|_| LifterError::NoConstraint)
                })
                .unwrap();
                let ir_poly = evaluate_ir_full::<Gf2_64, Gf2>(&ir, &macs, &values);

                assert_eq!(
                    oracle_poly, ir_poly,
                    "IR polynomial diverged from closure oracle for {}",
                    $name
                );
            }};
        }

        check!("mul_force", fixtures::mul_force, 3);
        check!("fp_mux", fixtures::fp_mux, 4);
        check!("carry_chain", fixtures::carry_chain, 4);
        check!("addr_index_mux", fixtures::addr_index_mux, 4);
        check!("carry_generate", fixtures::carry_generate, 5);
        check!("addr_base_mux", fixtures::addr_base_mux, 6);
        check!("acc_mux", fixtures::acc_mux, 6);
        check!("sp_mux", fixtures::sp_mux, 6);
        check!("pc_mux", fixtures::pc_mux, 8);
        check!("write_back", fixtures::write_back, 13);
        check!("write_back_bit0", fixtures::write_back_bit0, 14);
        check!("mul_bit_extraction", fixtures::mul_bit_extraction, 38);
    }
}
