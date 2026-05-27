//! Quicksilver-specific circuit representation of a multivariate constraint
//! polynomial.
//!
//! Stored as a DAG of operation nodes: `Var`, `Const`, `Mul`, `Add`, `Neg`.

use mpz_circuits_new::Context;

use crate::{ExtensionField, Field};

/// Index into the node arena.
pub type NodeId = usize;

/// A node in the arithmetic circuit.
#[derive(Debug, Clone, Copy)]
pub(crate) enum CircuitNode<E> {
    /// An input variable (leaf). Index into the input slice.
    Var(usize),
    /// A constant scalar (leaf).
    Const(E),
    /// Multiply two sub-expressions. Degree = deg(a) + deg(b).
    Mul(NodeId, NodeId),
    /// Add two sub-expressions. Degree = max(deg(a), deg(b)).
    Add(NodeId, NodeId),
    /// Negate a sub-expression. Degree = deg(a).
    Neg(NodeId),
}

/// An arithmetic circuit representing a constraint polynomial.
///
/// Built via [`CircuitBuilder`], then frozen. Stores the node arena in
/// topological order, pre-computed per-node degrees, and the single
/// output node.
#[derive(Debug, Clone)]
pub(crate) struct Circuit<E> {
    /// The node arena in topological order (children before parents).
    pub(crate) nodes: Vec<CircuitNode<E>>,
    /// Degree of each node.
    pub(crate) node_degrees: Vec<usize>,
    /// The output node (root): the node whose value `evaluate` returns.
    pub(crate) output: NodeId,
    /// Total degree of the polynomial (= degree of the output node).
    degree: usize,
    /// Number of input variables. Callers size their input slices to this.
    num_vars: usize,
}

impl<E: Field> Circuit<E> {
    /// Total degree of the polynomial.
    pub(crate) fn degree(&self) -> usize {
        self.degree
    }

    /// Number of `Mul` nodes (multiplication gates in the circuit).
    #[cfg(test)]
    pub(crate) fn mul_count(&self) -> usize {
        self.nodes
            .iter()
            .filter(|n| matches!(n, CircuitNode::Mul(_, _)))
            .count()
    }

    /// Number of input variables.
    pub(crate) fn num_vars(&self) -> usize {
        self.num_vars
    }

    /// Accumulate this circuit's constraint-polynomial contribution into
    /// the prover's running coefficient vector.
    ///
    /// # Arguments
    ///
    /// * `layout` - Scratch-slot layout for this circuit.
    /// * `scratch` - Caller-owned working buffer.
    /// * `accumulators` - The prover's running coefficient vector.
    /// * `d_max` - Maximum degree across the surrounding constraint set.
    /// * `macs` - Per-variable MACs.
    /// * `values` - Per-variable witness values.
    /// * `chi_power` - The Fiat-Shamir-derived weight for this evaluation.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn accumulate<W: Field>(
        &self,
        layout: &CircuitLayout,
        scratch: &mut [E],
        accumulators: &mut [E],
        d_max: usize,
        macs: &[E],
        values: &[W],
        chi_power: E,
    ) where
        E: ExtensionField<W>,
    {
        for ((node, &offset), &out_deg) in self
            .nodes
            .iter()
            .zip(&layout.node_offsets)
            .zip(&self.node_degrees)
        {
            match *node {
                CircuitNode::Var(idx) => {
                    scratch[offset] = macs[idx];
                    scratch[offset + 1] = E::embed(values[idx]);
                }
                CircuitNode::Const(c) => {
                    scratch[offset] = c;
                }
                CircuitNode::Mul(a, b) => {
                    // Var nodes are always degree-1 polynomials with two
                    // coefficients: [mac, embed(w)]. The arms below exploit
                    // this structure to keep witness terms in the subfield
                    // until they have to enter the extension field.
                    match (self.nodes[a], self.nodes[b]) {
                        // Variable × variable
                        (CircuitNode::Var(a_idx), CircuitNode::Var(b_idx)) => {
                            // (mac_a + w_a·Δ)(mac_b + w_b·Δ) expanded by degree:
                            //   slot 0 (Δ⁰): mac_a · mac_b
                            //   slot 1 (Δ¹): w_b · mac_a + w_a · mac_b
                            //   slot 2 (Δ²): w_a · w_b
                            let a_mac = macs[a_idx];
                            let a_w = values[a_idx];
                            let b_mac = macs[b_idx];
                            let b_w = values[b_idx];
                            scratch[offset] = a_mac * b_mac;

                            // Using `scale_by_subfield` here and in all invocations below instead
                            // of direct multiplication saves ~15% on wasm but loses ~3% on native
                            // x86 — there the `pclmulqdq` was already pipelined for free.
                            scratch[offset + 1] =
                                a_mac.scale_by_subfield(b_w) + b_mac.scale_by_subfield(a_w);
                            scratch[offset + 2] = E::embed(a_w * b_w);
                        }
                        // Variable × coefficient vector (either operand may
                        // be the Var; we pick out which and use one loop body)
                        (CircuitNode::Var(v), _) | (_, CircuitNode::Var(v)) => {
                            let (var_idx, other) = if matches!(self.nodes[a], CircuitNode::Var(_)) {
                                (v, b)
                            } else {
                                (v, a)
                            };
                            let out_len = out_deg + 1;
                            for k in 0..out_len {
                                scratch[offset + k] = E::zero();
                            }
                            let v_mac = macs[var_idx];
                            let v_w = values[var_idx];
                            let e_off = layout.node_offsets[other];
                            let e_len = self.node_degrees[other] + 1;
                            for i in 0..e_len {
                                let coeff = scratch[e_off + i];
                                scratch[offset + i] = scratch[offset + i] + coeff * v_mac;
                                scratch[offset + i + 1] =
                                    scratch[offset + i + 1] + coeff.scale_by_subfield(v_w);
                            }
                        }
                        // Coefficient vector × coefficient vector (general convolution)
                        _ => {
                            let out_len = out_deg + 1;
                            for k in 0..out_len {
                                scratch[offset + k] = E::zero();
                            }
                            let a_off = layout.node_offsets[a];
                            let a_len = self.node_degrees[a] + 1;
                            let b_off = layout.node_offsets[b];
                            let b_len = self.node_degrees[b] + 1;
                            for ai in 0..a_len {
                                let a_val = scratch[a_off + ai];
                                for bi in 0..b_len {
                                    scratch[offset + ai + bi] =
                                        scratch[offset + ai + bi] + a_val * scratch[b_off + bi];
                                }
                            }
                        }
                    }
                }
                // Negate every coefficient of the operand.
                CircuitNode::Neg(a) => {
                    let len = out_deg + 1;
                    let a_off = layout.node_offsets[a];
                    for k in 0..len {
                        scratch[offset + k] = -scratch[a_off + k];
                    }
                }
                // Add two coefficient vectors. The lower-degree operand
                // is degree-shifted to match the higher-degree one.
                CircuitNode::Add(a, b) => {
                    let out_len = out_deg + 1;
                    let out_end = offset + out_len;
                    let a_len = self.node_degrees[a] + 1;
                    let a_end = layout.node_offsets[a] + a_len;
                    let b_len = self.node_degrees[b] + 1;
                    let b_end = layout.node_offsets[b] + b_len;

                    for k in 0..out_len {
                        scratch[offset + k] = E::zero();
                    }
                    for k in 0..a_len {
                        scratch[out_end - 1 - k] = scratch[a_end - 1 - k];
                    }
                    for k in 0..b_len {
                        scratch[out_end - 1 - k] =
                            scratch[out_end - 1 - k] + scratch[b_end - 1 - k];
                    }
                }
            }
        }

        // Skip the highest-degree coefficient.
        let out_end = layout.node_offsets[self.output] + self.degree();

        // Degree-shift the output into the accumulator, aligning
        // lower-degree outputs to match d_max.
        for k in 0..self.degree() {
            accumulators[d_max - 1 - k] =
                accumulators[d_max - 1 - k] + scratch[out_end - 1 - k] * chi_power;
        }
    }

    /// Evaluate this circuit's constraint polynomial at Δ from the
    /// verifier's `keys`.
    ///
    /// # Arguments
    ///
    /// * `keys` - One MAC key per input variable.
    /// * `delta_pow` - Precomputed powers of Δ, with `delta_pow[k] == Δ^k`.
    ///
    /// # Returns
    ///
    /// The constraint polynomial evaluated at Δ, at the circuit's *own*
    /// degree.
    pub(crate) fn evaluate(&self, keys: &[E], delta_pow: &[E]) -> E {
        let mut node_vals: Vec<E> = Vec::with_capacity(self.nodes.len());
        for node in &self.nodes {
            let val = match *node {
                CircuitNode::Var(idx) => keys[idx],
                CircuitNode::Const(c) => c,
                CircuitNode::Mul(a, b) => node_vals[a] * node_vals[b],
                // The lower-degree operand is multiplied by Δ^shift to
                // align with the higher-degree one before adding.
                CircuitNode::Add(a, b) => {
                    let da = self.node_degrees[a];
                    let db = self.node_degrees[b];
                    let d = da.max(db);
                    let shift_a = d - da;
                    let shift_b = d - db;
                    let va = if shift_a == 0 {
                        node_vals[a]
                    } else {
                        node_vals[a] * delta_pow[shift_a]
                    };
                    let vb = if shift_b == 0 {
                        node_vals[b]
                    } else {
                        node_vals[b] * delta_pow[shift_b]
                    };
                    va + vb
                }
                CircuitNode::Neg(a) => -node_vals[a],
            };
            node_vals.push(val);
        }
        node_vals[self.output]
    }

    /// Evaluate the circuit on the given input values.
    ///
    /// Returns the output node's value.
    #[cfg(test)]
    pub(crate) fn evaluate_cleartext(&self, values: &[E]) -> E {
        let mut node_vals: Vec<E> = Vec::with_capacity(self.nodes.len());
        for node in &self.nodes {
            let val = match *node {
                CircuitNode::Var(idx) => values[idx],
                CircuitNode::Const(c) => c,
                CircuitNode::Mul(a, b) => node_vals[a].mul(node_vals[b]),
                CircuitNode::Add(a, b) => node_vals[a].add(node_vals[b]),
                CircuitNode::Neg(a) => -node_vals[a],
            };
            node_vals.push(val);
        }
        node_vals[self.output]
    }
}

/// Scratch-buffer layout for one circuit.
///
/// Each node produces an intermediate polynomial in Δ; this layout assigns
/// each node a contiguous range of slots (one slot per coefficient) in a flat
/// scratch array. Precomputed once per circuit and reused across evaluations
/// by [`Circuit::accumulate`].
#[derive(Clone)]
pub(crate) struct CircuitLayout {
    /// Scratch offset for each node, indexed by `NodeId` (parallel to
    /// [`Circuit::nodes`]).
    node_offsets: Vec<usize>,
    /// Total scratch slots needed for this circuit.
    pub(crate) scratch_size: usize,
}

impl CircuitLayout {
    pub(crate) fn from_circuit<E: Field>(circuit: &Circuit<E>) -> Self {
        let mut node_offsets = vec![0usize; circuit.nodes.len()];
        let mut offset = 0;
        for (i, &deg) in circuit.node_degrees.iter().enumerate() {
            node_offsets[i] = offset;
            offset += deg + 1;
        }
        Self {
            node_offsets,
            scratch_size: offset,
        }
    }
}

// ---------------------------------------------------------------------------
// Circuit builder
// ---------------------------------------------------------------------------

/// Builder for constructing a [`Circuit`].
///
/// Nodes are appended in topological order (children before parents).
/// The builder does NOT deduplicate: if the user creates the same
/// sub-expression twice, it gets two separate nodes. The user is
/// responsible for sharing via explicit `NodeId` reuse.
pub struct CircuitBuilder<E> {
    /// The node arena, appended in topological order (children before parents).
    nodes: Vec<CircuitNode<E>>,
    /// Degree of each node, kept in lock-step with `nodes`.
    node_degrees: Vec<usize>,
    /// Largest `Var` index seen so far; drives `num_vars` on build.
    max_var: Option<usize>,
    /// Root of the constraint polynomial.
    output: Option<NodeId>,
}

impl<E: Field> Default for CircuitBuilder<E> {
    fn default() -> Self {
        Self::new()
    }
}

impl<E: Field> CircuitBuilder<E> {
    /// Create an empty builder.
    pub fn new() -> Self {
        Self {
            nodes: Vec::new(),
            node_degrees: Vec::new(),
            max_var: None,
            output: None,
        }
    }

    fn push(&mut self, node: CircuitNode<E>, degree: usize) -> NodeId {
        let id = self.nodes.len();
        self.nodes.push(node);
        self.node_degrees.push(degree);
        id
    }

    /// Create an input-variable node referencing input `idx`. Degree = 1.
    pub fn var(&mut self, idx: usize) -> NodeId {
        self.max_var = Some(self.max_var.map_or(idx, |m| m.max(idx)));
        self.push(CircuitNode::Var(idx), 1)
    }

    /// Create a constant node holding `val`. Degree = 0.
    pub fn constant(&mut self, val: E) -> NodeId {
        self.push(CircuitNode::Const(val), 0)
    }

    /// Multiply two sub-expressions. Degree = deg(a) + deg(b).
    pub fn mul(&mut self, a: NodeId, b: NodeId) -> NodeId {
        let deg = self.node_degrees[a] + self.node_degrees[b];
        self.push(CircuitNode::Mul(a, b), deg)
    }

    /// Add two sub-expressions. Degree = max(deg(a), deg(b)).
    pub fn add(&mut self, a: NodeId, b: NodeId) -> NodeId {
        let deg = self.node_degrees[a].max(self.node_degrees[b]);
        self.push(CircuitNode::Add(a, b), deg)
    }

    /// Negate a sub-expression. Degree = deg(a).
    pub fn neg(&mut self, a: NodeId) -> NodeId {
        let deg = self.node_degrees[a];
        self.push(CircuitNode::Neg(a), deg)
    }

    /// Subtract `b` from `a`.
    pub fn sub(&mut self, a: NodeId, b: NodeId) -> NodeId {
        let neg_b = self.neg(b);
        self.add(a, neg_b)
    }

    /// Freeze the circuit, declaring `output` as the root.
    pub(crate) fn build(self, output: NodeId) -> Circuit<E> {
        let degree = self.node_degrees[output];
        let num_vars = self.max_var.map_or(0, |m| m + 1);

        Circuit {
            nodes: self.nodes,
            node_degrees: self.node_degrees,
            output,
            degree,
            num_vars,
        }
    }
}

impl<E: Field> Context for CircuitBuilder<E> {
    type Error = BuildError;
    type Wire = NodeId;
    type Field = E;

    fn add(&mut self, a: NodeId, b: NodeId) -> NodeId {
        CircuitBuilder::add(self, a, b)
    }

    fn sub(&mut self, a: NodeId, b: NodeId) -> NodeId {
        CircuitBuilder::sub(self, a, b)
    }

    fn mul(&mut self, a: NodeId, b: NodeId) -> NodeId {
        CircuitBuilder::mul(self, a, b)
    }

    fn constant(&mut self, v: E) -> NodeId {
        CircuitBuilder::constant(self, v)
    }

    fn assert_const(&mut self, v: NodeId, expected: E) -> Result<(), BuildError> {
        if self.output.is_some() {
            return Err(BuildError::MultipleConstraints);
        }
        let root = if expected == E::zero() {
            v
        } else {
            let c = CircuitBuilder::constant(self, expected);
            CircuitBuilder::sub(self, v, c)
        };
        self.output = Some(root);
        Ok(())
    }
}

/// Compile a constraint closure into a [`Circuit`].
///
/// `num_vars` input wires are pre-allocated via [`CircuitBuilder::var`]
/// and passed to `f` as a slice. The closure expresses its constraint
/// with `Context` operations and must end with exactly one `assert_*`
/// call.
pub(crate) fn compile<E, F>(num_vars: usize, f: F) -> Result<Circuit<E>, BuildError>
where
    E: Field,
    F: FnOnce(&mut CircuitBuilder<E>, &[NodeId]) -> Result<(), BuildError>,
{
    let mut builder = CircuitBuilder::<E>::new();
    let vars: Vec<NodeId> = (0..num_vars).map(|i| builder.var(i)).collect();
    f(&mut builder, &vars)?;
    let output = builder.output.ok_or(BuildError::NoConstraint)?;
    Ok(builder.build(output))
}

/// Errors raised while compiling a constraint closure or attaching a kernel.
#[derive(Debug, thiserror::Error)]
pub enum BuildError {
    /// The closure returned without calling any `assert_*` method —
    /// no constraint polynomial was produced.
    #[error("constraint closure emitted no assertion")]
    NoConstraint,
    /// The closure called `assert_*` more than once.
    #[error("constraint closure emitted multiple assertions; split into separate circuits")]
    MultipleConstraints,
    /// `add_kernel` was called with an `id` that has no registered constraint.
    #[error("kernel attached to unknown constraint id {id}")]
    UnknownConstraint { id: usize },
    /// `add_kernel`'s kernel disagrees with the registered circuit on
    /// `num_vars` or `degree`.
    #[error(
        "kernel shape mismatch for constraint {id}: \
         expected (num_vars={expected_num_vars}, degree={expected_degree}), \
         got (num_vars={actual_num_vars}, degree={actual_degree})"
    )]
    KernelShape {
        id: usize,
        expected_num_vars: usize,
        actual_num_vars: usize,
        expected_degree: usize,
        actual_degree: usize,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Field,
        fixture::coverage,
        test_utils::{EvalCtx, PolyOracle, eval_at},
    };
    use mpz_fields::{ExtensionField, gf2::Gf2, gf2_64::Gf2_64, p256::P256};
    use rand::{Rng, SeedableRng, rngs::StdRng};

    /// Compilation faithfulness: `compile`-ing the [`coverage`] fixture.
    #[test]
    fn coverage_compile_matches_cleartext() {
        let circuit = compile::<P256, _>(6, |cb, vars| {
            let arr: [_; 6] = vars.try_into().unwrap();
            coverage(cb, arr)
        })
        .expect("coverage must compile");

        // Structural properties a value-differential can't see.
        assert_eq!(circuit.num_vars(), 6);
        assert_eq!(circuit.degree(), 4);
        assert_eq!(circuit.mul_count(), 5);

        let mut rng = StdRng::seed_from_u64(0xC0FFEE);
        for _ in 0..64 {
            let vals: [P256; 6] = std::array::from_fn(|_| rng.random());

            // Closure side: run the fn directly through the cleartext ctx.
            let mut ctx = EvalCtx::<P256>::new();
            coverage(&mut ctx, vals).expect("cleartext eval");
            let expected = ctx.into_output();

            // DAG side: walk the compiled circuit; must agree.
            assert_eq!(
                circuit.evaluate_cleartext(&vals),
                expected,
                "compiled DAG diverges from cleartext closure at {vals:?}"
            );
        }
    }

    /// DAG-walker faithfulness: the prover/verifier *lift* walks on a
    /// compiled circuit must match the independent
    /// [`PolyOracle`](crate::test_utils::PolyOracle).
    #[test]
    fn coverage_dag_walkers_match_poly_oracle() {
        let circuit = compile::<Gf2_64, _>(6, |cb, vars| {
            let arr: [_; 6] = vars.try_into().unwrap();
            coverage(cb, arr)
        })
        .expect("coverage must compile");
        let layout = CircuitLayout::from_circuit(&circuit);
        let d = circuit.degree();

        let mut rng = StdRng::seed_from_u64(0xDA9_C0FFEE);
        let delta = Gf2_64(rng.random::<u64>());
        let mut delta_pow = vec![Gf2_64::one(); d + 1];
        for k in 1..=d {
            delta_pow[k] = delta_pow[k - 1] * delta;
        }

        for _ in 0..16 {
            let values: Vec<Gf2> = (0..6).map(|_| Gf2(rng.random::<bool>())).collect();
            let macs: Vec<Gf2_64> = (0..6).map(|_| Gf2_64(rng.random::<u64>())).collect();
            let keys: Vec<Gf2_64> = (0..6)
                .map(|i| macs[i] + Gf2_64::embed(values[i]) * delta)
                .collect();

            // Oracle Q(X).
            let mut oracle = PolyOracle::<Gf2_64>::new();
            let wires: [usize; 6] =
                std::array::from_fn(|i| oracle.push_var(macs[i], Gf2_64::embed(values[i])));
            coverage(&mut oracle, wires).expect("oracle constraint run");
            let q = oracle.into_output();

            // Verifier DAG walk → Q(Δ).
            assert_eq!(
                circuit.evaluate(&keys, &delta_pow),
                eval_at(&q, delta),
                "evaluate disagrees with oracle at Δ"
            );

            // Prover DAG walk → Q's bottom-`d` coefficients (χ=1).
            let mut scratch = vec![Gf2_64::zero(); layout.scratch_size];
            let mut acc = vec![Gf2_64::zero(); d];
            circuit.accumulate(
                &layout,
                &mut scratch,
                &mut acc,
                d,
                &macs,
                &values,
                Gf2_64::one(),
            );
            for k in 0..d {
                assert_eq!(
                    acc[k], q[k],
                    "accumulate coefficient {k} disagrees with oracle"
                );
            }
        }
    }

    /// `assert_const(v, c)` with `c ≠ 0` builds output `v − c`.
    #[test]
    fn test_compile_assert_const_nonzero() {
        // assert w0·w1 = 1 → output = w0·w1 − 1.
        let circuit = compile::<P256, _>(2, |cb, vars| {
            let prod = Context::mul(cb, vars[0], vars[1]);
            Context::assert_const(cb, prod, P256::one())
        })
        .expect("compile must succeed");

        assert_eq!(circuit.num_vars(), 2);
        // 1·1 − 1 = 0 → satisfying.
        assert_eq!(
            circuit.evaluate_cleartext(&[P256::one(), P256::one()]),
            P256::zero()
        );
        // 2·2 − 1 = 3 ≠ 0 → unsatisfying.
        let two = P256::one() + P256::one();
        assert_ne!(circuit.evaluate_cleartext(&[two, two]), P256::zero());
    }

    /// An error from the constraint closure must propagate out of
    /// `compile` unchanged.
    #[test]
    fn test_compile_propagates_closure_error() {
        let result = compile::<P256, _>(2, |_cb, _vars| Err(BuildError::MultipleConstraints));
        assert!(matches!(result, Err(BuildError::MultipleConstraints)));
    }

    /// `compile` rejects closures that emit zero assertions.
    #[test]
    fn test_compile_rejects_no_constraint() {
        let result = compile::<P256, _>(1, |_cb, _vars| Ok(()));
        assert!(matches!(result, Err(BuildError::NoConstraint)));
    }

    /// `compile` rejects closures that emit multiple assertions.
    #[test]
    fn test_compile_rejects_multiple_constraints() {
        let result = compile::<P256, _>(1, |cb, vars| {
            Context::assert_const(cb, vars[0], P256::zero())?;
            Context::assert_const(cb, vars[0], P256::zero())?; // second assert errors
            Ok(())
        });
        assert!(matches!(result, Err(BuildError::MultipleConstraints)));
    }
}
