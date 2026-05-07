//! Arithmetic-circuit representation of multivariate constraint polynomials.
//!
//! A DAG of `{Var, Const, Mul, Add}` nodes that represents a constraint
//! polynomial as a factored arithmetic circuit. Intermediate sums are
//! first-class nodes that can feed into multiplications — e.g.
//! `(a + c) · (bf + c)` is 2 multiplications, reusing `c` in both factors.

use crate::Field;

/// Index into the node arena.
pub type NodeId = usize;

/// A node in the arithmetic circuit.
#[derive(Debug, Clone, Copy)]
pub enum CircuitNode<E> {
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
pub struct Circuit<E> {
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
    pub fn degree(&self) -> usize {
        self.degree
    }

    /// Number of nodes in the arena.
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Number of `Mul` nodes (multiplication gates in the circuit).
    pub fn mul_count(&self) -> usize {
        self.nodes
            .iter()
            .filter(|n| matches!(n, CircuitNode::Mul(_, _)))
            .count()
    }

    /// Number of input variables.
    pub fn num_vars(&self) -> usize {
        self.num_vars
    }

    /// Evaluate the circuit on the given input values.
    ///
    /// Returns the output node's value.
    pub fn evaluate(&self, values: &[E]) -> E {
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
    pub fn build(self, output: NodeId) -> Circuit<E> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use hybrid_array::{
        Array,
        typenum::{U1, U8},
    };
    use itybity::{BitLength, FromBitIterator, GetBit, Lsb0, Msb0};
    use mpz_fields::FieldError;
    use rand::distr::{Distribution, StandardUniform};
    use std::ops::{Add, Mul, Neg, Sub};

    /// Prime field F_17.
    #[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
    struct F17(u32);

    impl Add for F17 {
        type Output = Self;
        fn add(self, rhs: Self) -> Self {
            F17((self.0 + rhs.0) % 17)
        }
    }

    impl Sub for F17 {
        type Output = Self;
        fn sub(self, rhs: Self) -> Self {
            F17((self.0 + 17 - rhs.0) % 17)
        }
    }

    impl Mul for F17 {
        type Output = Self;
        fn mul(self, rhs: Self) -> Self {
            F17((self.0 * rhs.0) % 17)
        }
    }

    impl Neg for F17 {
        type Output = Self;
        fn neg(self) -> Self {
            if self.0 == 0 { self } else { F17(17 - self.0) }
        }
    }

    impl Distribution<F17> for StandardUniform {
        fn sample<R: rand::Rng + ?Sized>(&self, rng: &mut R) -> F17 {
            F17(rng.random::<u32>() % 17)
        }
    }

    impl TryFrom<Array<u8, U1>> for F17 {
        type Error = FieldError;
        fn try_from(value: Array<u8, U1>) -> Result<Self, Self::Error> {
            let byte: [u8; 1] = value.into();
            Ok(F17(byte[0] as u32 % 17))
        }
    }

    impl BitLength for F17 {
        // Byte-aligned for simplicity; the top 3 bits are always zero.
        const BITS: usize = 8;
    }

    impl GetBit<Lsb0> for F17 {
        fn get_bit(&self, index: usize) -> bool {
            GetBit::<Lsb0>::get_bit(&(self.0 as u8), index)
        }
    }

    impl GetBit<Msb0> for F17 {
        fn get_bit(&self, index: usize) -> bool {
            GetBit::<Msb0>::get_bit(&(self.0 as u8), index)
        }
    }

    impl FromBitIterator for F17 {
        fn from_lsb0_iter(iter: impl IntoIterator<Item = bool>) -> Self {
            F17(u8::from_lsb0_iter(iter) as u32 % 17)
        }
        fn from_msb0_iter(iter: impl IntoIterator<Item = bool>) -> Self {
            F17(u8::from_msb0_iter(iter) as u32 % 17)
        }
    }

    impl crate::Field for F17 {
        type BitSize = U8;
        type ByteSize = U1;

        fn zero() -> Self {
            F17(0)
        }
        fn one() -> Self {
            F17(1)
        }
        fn two_pow(rhs: u32) -> Self {
            F17((1u32 << rhs) % 17)
        }

        fn inverse(self) -> Option<Self> {
            if self.0 == 0 {
                return None;
            }
            // Fermat in F_17: x⁻¹ = x^(17-2) = x^15 = x^8 · x^4 · x^2 · x.
            let x2 = self * self;
            let x4 = x2 * x2;
            let x8 = x4 * x4;
            Some(x8 * x4 * x2 * self)
        }

        fn to_le_bytes(&self) -> Vec<u8> {
            vec![self.0 as u8]
        }
        fn to_be_bytes(&self) -> Vec<u8> {
            vec![self.0 as u8]
        }
    }

    /// Sanity-check the F17 fixture's arithmetic.
    #[test]
    fn test_f17_inv_round_trip() {
        use crate::Field;
        for i in 1..17u32 {
            let x = F17(i);
            assert_eq!(x * x.inverse().unwrap(), F17(1), "inv of {i} is wrong");
        }
    }

    #[test]
    fn test_circuit_evaluate_mul_operands() {
        // Circuit exercises all ten combinations of operand types a Mul
        // node can have (each operand is one of Var, Const, Mul, Add):
        //
        //   k1  = Const · Const   (c_two · c_three)
        //   k2  = Const · Var     (c_two · v0)
        //   k3  = Var   · Var     (v1 · v2)
        //   k4  = Const · Mul     (c_three · k3)
        //   k5  = Var   · Mul     (v3 · k3)
        //   k6  = Mul   · Mul     (k2 · k3)
        //   k7  = Const · Add     (c_two · a1)
        //   k8  = Var   · Add     (v2 · a1)
        //   k9  = Mul   · Add     (k3 · a1)
        //   k10 = Add   · Add     (a1 · a2)
        //
        // Helper Add nodes:  a1 = v0 + v1,  a2 = v2 + c_two.
        //
        // Output = k1 + k2 + … + k10.
        //
        // Max degree = 3 (from k5, k6, k9).
        let mut cb = CircuitBuilder::<F17>::new();
        let c_two = cb.constant(F17(2));
        let c_three = cb.constant(F17(3));
        let v0 = cb.var(0);
        let v1 = cb.var(1);
        let v2 = cb.var(2);
        let v3 = cb.var(3);

        // Add nodes that feed into Muls.
        let a1 = cb.add(v0, v1);
        let a2 = cb.add(v2, c_two);

        let k1 = cb.mul(c_two, c_three);
        let k2 = cb.mul(c_two, v0);
        let k3 = cb.mul(v1, v2);
        let k4 = cb.mul(c_three, k3);
        let k5 = cb.mul(v3, k3);
        let k6 = cb.mul(k2, k3);
        let k7 = cb.mul(c_two, a1);
        let k8 = cb.mul(v2, a1);
        let k9 = cb.mul(k3, a1);
        let k10 = cb.mul(a1, a2);

        // Sum all ten Muls.
        let s1 = cb.add(k1, k2);
        let s2 = cb.add(s1, k3);
        let s3 = cb.add(s2, k4);
        let s4 = cb.add(s3, k5);
        let s5 = cb.add(s4, k6);
        let s6 = cb.add(s5, k7);
        let s7 = cb.add(s6, k8);
        let s8 = cb.add(s7, k9);
        let out = cb.add(s8, k10);
        let circuit = cb.build(out);

        assert_eq!(circuit.degree(), 3);
        assert_eq!(circuit.mul_count(), 10);
        assert_eq!(circuit.num_vars(), 4);

        // Per-evaluation k_i values are computed in the comments below.
        // All sums and reductions done mod 17 by hand.

        // v = (0, 0, 0, 0): a1=0, a2=2. Only k1 contributes non-zero.
        //   k1..k10 = 6, 0, 0, 0, 0, 0, 0, 0, 0, 0 → sum = 6.
        assert_eq!(circuit.evaluate(&[F17(0); 4]), F17(6));

        // v = (1, 1, 1, 1): a1=2, a2=3.
        //   k = 6, 2, 1, 3, 1, 2, 4, 2, 2, 6 → sum = 29 mod 17 = 12.
        assert_eq!(circuit.evaluate(&[F17(1); 4]), F17(12));

        // v = (1, 2, 3, 4): a1=3, a2=5.
        //   k1=6, k2=2, k3=6, k4=18%17=1, k5=24%17=7, k6=12,
        //   k7=6, k8=9, k9=18%17=1, k10=15
        //   sum = 6+2+6+1+7+12+6+9+1+15 = 65 mod 17 = 14.
        assert_eq!(circuit.evaluate(&[F17(1), F17(2), F17(3), F17(4)]), F17(14),);

        // v = (0, 5, 5, 5): a1=5, a2=7.
        //   k1=6, k2=0, k3=25%17=8, k4=24%17=7, k5=40%17=6, k6=0,
        //   k7=10, k8=25%17=8, k9=40%17=6, k10=35%17=1
        //   sum = 6+0+8+7+6+0+10+8+6+1 = 52 mod 17 = 1.
        assert_eq!(circuit.evaluate(&[F17(0), F17(5), F17(5), F17(5)]), F17(1),);

        // v = (16, 1, 1, 16): a1 = 16+1 = 17 ≡ 0 (mod 17), a2=3.
        //   With a1=0, every k involving a1 (k7..k10) is zero.
        //   k1=6, k2=32%17=15, k3=1, k4=3, k5=16, k6=15, k7..k10=0
        //   sum = 6+15+1+3+16+15 = 56 mod 17 = 5.
        assert_eq!(
            circuit.evaluate(&[F17(16), F17(1), F17(1), F17(16)]),
            F17(5),
        );
    }

    #[test]
    fn test_circuit_evaluate_add_operands() {
        // Mirror test for Add: exercise all ten combinations of operand
        // types an Add node can have (each operand ∈ {Var, Const, Mul, Add}).
        //
        //   e1  = Const + Const  (c_one + c_two)           = 3
        //   e2  = Const + Var    (c_one + v0)              = 1 + v0
        //   e3  = Var   + Var    (v0 + v1)                 = v0 + v1
        //   e4  = Const + Mul    (c_two + m1)              = 2 + v0·v1
        //   e5  = Var   + Mul    (v2 + m1)                 = v2 + v0·v1
        //   e6  = Mul   + Mul    (m1 + m2)                 = v0·v1 + v2·v3
        //   e7  = Const + Add    (c_three + a_seed)        = 3 + (v0+v1)
        //   e8  = Var   + Add    (v2 + a_seed)             = v2 + (v0+v1)
        //   e9  = Mul   + Add    (m2 + a_seed)             = v2·v3 + (v0+v1)
        //   e10 = Add   + Add    (a_seed + a_seed2)        = (v0+v1) + (v2+2)
        //
        // Helpers:
        //   m1 = v0·v1,  m2 = v2·v3
        //   a_seed = v0 + v1,  a_seed2 = v2 + c_two
        //
        // Output = Σ e_i.
        // Collecting by monomial:
        //   out = 11 + 6·v0 + 5·v1 + 3·v2 + 3·v0·v1 + 2·v2·v3   (mod 17)
        let mut cb = CircuitBuilder::<F17>::new();
        let c_one = cb.constant(F17(1));
        let c_two = cb.constant(F17(2));
        let c_three = cb.constant(F17(3));
        let v0 = cb.var(0);
        let v1 = cb.var(1);
        let v2 = cb.var(2);
        let v3 = cb.var(3);

        let m1 = cb.mul(v0, v1);
        let m2 = cb.mul(v2, v3);

        let a_seed = cb.add(v0, v1);
        let a_seed2 = cb.add(v2, c_two);

        let e1 = cb.add(c_one, c_two);
        let e2 = cb.add(c_one, v0);
        let e3 = cb.add(v0, v1);
        let e4 = cb.add(c_two, m1);
        let e5 = cb.add(v2, m1);
        let e6 = cb.add(m1, m2);
        let e7 = cb.add(c_three, a_seed);
        let e8 = cb.add(v2, a_seed);
        let e9 = cb.add(m2, a_seed);
        let e10 = cb.add(a_seed, a_seed2);

        // Sum all ten.
        let s1 = cb.add(e1, e2);
        let s2 = cb.add(s1, e3);
        let s3 = cb.add(s2, e4);
        let s4 = cb.add(s3, e5);
        let s5 = cb.add(s4, e6);
        let s6 = cb.add(s5, e7);
        let s7 = cb.add(s6, e8);
        let s8 = cb.add(s7, e9);
        let out = cb.add(s8, e10);
        let circuit = cb.build(out);

        assert_eq!(circuit.degree(), 2);
        assert_eq!(circuit.mul_count(), 2);
        assert_eq!(circuit.num_vars(), 4);

        // v = (0, 0, 0, 0): out = 11.
        assert_eq!(circuit.evaluate(&[F17(0); 4]), F17(11));

        // v = (1, 1, 1, 1): 11 + 6 + 5 + 3 + 3 + 2 = 30 mod 17 = 13.
        assert_eq!(circuit.evaluate(&[F17(1); 4]), F17(13));

        // v = (1, 2, 3, 4): 11 + 6 + 10 + 9 + 3·2 + 2·12 = 66 mod 17 = 15.
        assert_eq!(circuit.evaluate(&[F17(1), F17(2), F17(3), F17(4)]), F17(15),);

        // v = (0, 5, 5, 5): 11 + 0 + 25 + 15 + 0 + 50 = 101 mod 17 = 16.
        assert_eq!(circuit.evaluate(&[F17(0), F17(5), F17(5), F17(5)]), F17(16),);

        // v = (16, 1, 1, 16): 11 + 96 + 5 + 3 + 48 + 32 = (all mod 17)
        //   11 + 11 + 5 + 3 + 14 + 15 = 59 mod 17 = 8.
        assert_eq!(
            circuit.evaluate(&[F17(16), F17(1), F17(1), F17(16)]),
            F17(8),
        );
    }

    /// `cb.sub(a, b)` must compute `a − b` honestly over a field where
    /// `+` and `−` differ.
    #[test]
    fn test_circuit_evaluate_sub_over_prime_field() {
        let mut cb = CircuitBuilder::<F17>::new();
        let a = cb.var(0);
        let b = cb.var(1);
        let out = cb.sub(a, b);
        let circuit = cb.build(out);

        // 5 − 3 = 2.
        assert_eq!(circuit.evaluate(&[F17(5), F17(3)]), F17(2));
        // 3 − 5 = −2 ≡ 15 (mod 17).
        assert_eq!(circuit.evaluate(&[F17(3), F17(5)]), F17(15));
        // 0 − 0 = 0.
        assert_eq!(circuit.evaluate(&[F17(0), F17(0)]), F17(0));

        // `cb.add(a, b)` would have given `5 + 3 = 8` for the first case
        // — confirms `sub` is materially different from `add` here.
        let mut cb2 = CircuitBuilder::<F17>::new();
        let a2 = cb2.var(0);
        let b2 = cb2.var(1);
        let add_out = cb2.add(a2, b2);
        let add_circuit = cb2.build(add_out);
        assert_ne!(
            circuit.evaluate(&[F17(5), F17(3)]),
            add_circuit.evaluate(&[F17(5), F17(3)]),
            "sub and add must give different results over a non-char-2 field"
        );
    }
}
