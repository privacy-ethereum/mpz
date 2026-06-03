use crate::{
    ConstraintId, ConstraintsBuilder, ExtensionField, Field, ProverConstraints, ProverVope,
    VerifierConstraints, VerifierVope,
};
use mpz_circuits_new::{Context, fixtures::and_gate};
use mpz_fields::{gf2::Gf2, gf2_128::Gf2_128};
use rand::Rng;

/// Naive QuickSilver polynomial-lift oracle. Wires are indices into `polys`;
/// each entry is a coefficient vector, lowest degree first.
pub(crate) struct PolyOracle<E: Field> {
    polys: Vec<Vec<E>>,
    output: Option<Vec<E>>,
}

impl<E: Field> PolyOracle<E> {
    pub(crate) fn new() -> Self {
        Self {
            polys: Vec::new(),
            output: None,
        }
    }

    /// Register an authenticated variable `mac + value·X` and return
    /// its wire handle.
    pub(crate) fn push_var(&mut self, mac: E, value: E) -> usize {
        self.intern(vec![mac, value])
    }

    /// Consume the oracle and return the constraint polynomial recorded
    /// by `assert_const`, lowest degree first.
    ///
    /// Panics if the constraint never asserted.
    pub(crate) fn into_output(self) -> Vec<E> {
        self.output
            .expect("constraint must call assert_const exactly once")
    }

    fn intern(&mut self, poly: Vec<E>) -> usize {
        self.polys.push(poly);
        self.polys.len() - 1
    }
}

impl<E: Field> Context for PolyOracle<E> {
    type Error = ();
    type Wire = usize;
    type Field = E;

    fn add(&mut self, a: usize, b: usize) -> usize {
        let p = top_aligned_add(&self.polys[a], &self.polys[b]);
        self.intern(p)
    }

    fn sub(&mut self, a: usize, b: usize) -> usize {
        let nb = neg(&self.polys[b]);
        let p = top_aligned_add(&self.polys[a], &nb);
        self.intern(p)
    }

    fn mul(&mut self, a: usize, b: usize) -> usize {
        let p = convolve(&self.polys[a], &self.polys[b]);
        self.intern(p)
    }

    fn constant(&mut self, v: E) -> usize {
        self.intern(vec![v])
    }

    fn assert_const(&mut self, v: usize, expected: E) -> Result<(), ()> {
        // Constraint polynomial is `v - expected`. `expected` is a
        // degree-0 constant, subtracted top-aligned like any `sub`.
        let nb = neg(&[expected]);
        let q = top_aligned_add(&self.polys[v], &nb);
        self.output = Some(q);
        Ok(())
    }
}

/// Evaluate `poly` (lowest degree first) at `x` by Horner's method.
pub(crate) fn eval_at<E: Field>(poly: &[E], x: E) -> E {
    let mut acc = E::zero();
    for &c in poly.iter().rev() {
        acc = acc * x + c;
    }
    acc
}

/// Top-aligned polynomial addition: align both operands at their
/// highest degree (shift the shorter up), then sum coefficient-wise.
fn top_aligned_add<E: Field>(a: &[E], b: &[E]) -> Vec<E> {
    let len = a.len().max(b.len());
    let mut out = vec![E::zero(); len];
    let off_a = len - a.len();
    let off_b = len - b.len();
    for (i, &c) in a.iter().enumerate() {
        out[off_a + i] = out[off_a + i] + c;
    }
    for (i, &c) in b.iter().enumerate() {
        out[off_b + i] = out[off_b + i] + c;
    }
    out
}

/// Polynomial convolution — ordinary multiplication.
fn convolve<E: Field>(a: &[E], b: &[E]) -> Vec<E> {
    let mut out = vec![E::zero(); a.len() + b.len() - 1];
    for (i, &ai) in a.iter().enumerate() {
        for (j, &bj) in b.iter().enumerate() {
            out[i + j] = out[i + j] + ai * bj;
        }
    }
    out
}

/// Per-coefficient negation.
fn neg<E: Field>(a: &[E]) -> Vec<E> {
    a.iter().map(|&c| E::zero() - c).collect()
}

/// Cleartext circuit evaluator: wires are plain field values and the
/// ops are ordinary field arithmetic — no MACs, no polynomial lift.
pub(crate) struct EvalCtx<E: Field> {
    output: Option<E>,
}

impl<E: Field> EvalCtx<E> {
    pub(crate) fn new() -> Self {
        Self { output: None }
    }

    /// The residual recorded by `assert_const` (`value − expected`).
    /// Panics if the constraint never asserted.
    pub(crate) fn into_output(self) -> E {
        self.output.expect("constraint must call assert_const")
    }
}

impl<E: Field> Context for EvalCtx<E> {
    type Error = ();
    type Wire = E;
    type Field = E;

    fn add(&mut self, a: E, b: E) -> E {
        a + b
    }

    fn sub(&mut self, a: E, b: E) -> E {
        a - b
    }

    fn mul(&mut self, a: E, b: E) -> E {
        a * b
    }

    fn constant(&mut self, v: E) -> E {
        v
    }

    fn assert_const(&mut self, v: E, expected: E) -> Result<(), ()> {
        self.output = Some(v - expected);
        Ok(())
    }
}

/// Draw a uniformly random `Gf2_128`.
pub(crate) fn random_gf128(rng: &mut impl Rng) -> Gf2_128 {
    Gf2_128::new(rng.random::<u128>())
}

/// Authenticate each value under MAC key `delta`, returning the prover's
/// MACs and the verifier's keys with `key = mac + value·Δ`.
pub(crate) fn auth_all<W: Field>(
    values: &[W],
    delta: Gf2_128,
    rng: &mut impl Rng,
) -> (Vec<Gf2_128>, Vec<Gf2_128>)
where
    Gf2_128: ExtensionField<W>,
{
    let mut macs = Vec::new();
    let mut keys = Vec::new();
    for &v in values {
        let mac = random_gf128(rng);
        let key = mac + Gf2_128::embed(v) * delta;
        macs.push(mac);
        keys.push(key);
    }
    (macs, keys)
}

/// Build a matching ([`ProverVope`], [`VerifierVope`]) pair from random
/// coefficients: `sum = Σ cᵢ·Δⁱ`.
pub(crate) fn mock_vope(
    count: usize,
    delta: Gf2_128,
    rng: &mut impl Rng,
) -> (ProverVope<Gf2_128>, VerifierVope<Gf2_128>) {
    let coeffs: Vec<Gf2_128> = (0..count).map(|_| random_gf128(rng)).collect();
    let mut sum = Gf2_128::ZERO;
    let mut delta_power = Gf2_128::ONE;
    for &c in &coeffs {
        sum = sum + c * delta_power;
        delta_power = delta_power * delta;
    }
    (ProverVope { coeffs }, VerifierVope { sum })
}

/// Build a constraint set with a single AND-gate constraint, via the
/// runtime-defined `add_dynamic` path (the upstream `and_gate` fn isn't
/// a `ConstraintDef`).
pub(crate) fn and_gate_constraints() -> (
    ProverConstraints<Gf2_128, Gf2>,
    VerifierConstraints<Gf2_128>,
    ConstraintId,
) {
    let mut b = ConstraintsBuilder::<Gf2_128, Gf2>::new();
    let id = b
        .add_dynamic(3, |cb, vars| {
            let arr: [_; 3] = vars.try_into().unwrap();
            and_gate(cb, arr)
        })
        .unwrap();
    let (pcs, vcs) = b.build();
    (pcs, vcs, id)
}
