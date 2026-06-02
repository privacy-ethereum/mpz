//! Polynomial-constraint expressions for the composite QuickSilver check
//! (eprint 2021/076, §5).
//!
//! A constraint is a polynomial `f` over committed wire values with `f(w) = 0`.
//! Instead of committing every intermediate product (circuit mode), a degree-`d`
//! constraint is evaluated *symbolically* into a polynomial in `Δ`:
//!
//! - The prover holds, per wire, the linear form `mac + value·X`; building `f`
//!   over these forms yields the coefficient vector of
//!   `g(X) = Σ_h f_h(mac + value·X)·X^{d-h}` ([`ProverExpr`]). The top
//!   coefficient (`X^d`) is `f(w)`, dropped by the protocol.
//! - The verifier holds, per wire, the key `k = mac + value·Δ`; building `f`
//!   over the keys yields `g(Δ)` directly ([`VerifierExpr`]).
//!
//! Both build the *same* expression with the `+`/`-`/`*` operators; at `Δ` the
//! prover's coefficient vector and the verifier's value agree (the differential
//! test below). Addition top-aligns operands (multiplying the lower-degree one
//! by `X^shift` / `Δ^shift`) so each (sub)expression stays top-aligned to its own
//! degree, matching the `X^{d-h}` weighting. All arithmetic is over
//! characteristic-2 fields, so negation is the identity and subtraction equals
//! addition.
//!
//! Arithmetic lives on the expression types (as `std::ops` impls) rather than on
//! [`PolyContext`], so the trait's methods don't collide with [`Context`]'s
//! `add`/`sub`/`mul`.

use core::ops::{Add, Mul, Sub};

use itybity::{GetBit, Lsb0};
use mpz_circuits_new::Context;
use mpz_fields::{ExtensionField, gf2::Gf2, gf2_128::Gf2_128};

/// Polynomial-constraint extension of [`Context`].
///
/// Build a degree-`d` constraint symbolically over committed wires with the
/// `+`/`-`/`*` operators on [`Expr`](Self::Expr) (free, degree-raising,
/// uncommitted), then either [`materialize`](Self::materialize) its output as a
/// fresh committed wire pinned by a degree-`d` constraint, or
/// [`assert_zero`](Self::assert_zero) it as a pure check. Implemented by the same
/// `Prover`/`Verifier` execution handles that implement [`Context`].
pub trait PolyContext: Context {
    /// Symbolic polynomial-in-Δ over committed wires. `Copy`, stack-allocated;
    /// composed with the arithmetic operators.
    type Expr: Copy
        + Add<Output = Self::Expr>
        + Sub<Output = Self::Expr>
        + Mul<Output = Self::Expr>;

    /// Lift a committed wire into a degree-1 expression.
    fn lift(&self, wire: Self::Wire) -> Self::Expr;

    /// A degree-0 public constant.
    fn constant(&self, value: Self::Field) -> Self::Expr;

    /// Commit the expression's value as a fresh wire and record the degree-`d`
    /// constraint pinning it to the expression. Returns the committed wire.
    fn materialize(&mut self, expr: Self::Expr) -> Self::Wire;

    /// Record a degree-`d` constraint that `expr == 0` (no commitment).
    fn assert_zero(&mut self, expr: Self::Expr) -> Result<(), Self::Error>;
}

/// Maximum supported constraint degree. Constraint polynomials carry at most
/// `MAX_DEGREE + 1` coefficients; building past this panics in debug.
pub(crate) const MAX_DEGREE: usize = 8;

/// Number of coefficient slots (`degree 0 ..= MAX_DEGREE`).
const NC: usize = MAX_DEGREE + 1;

/// Embed a witness bit into the MAC field.
#[inline]
fn embed(v: Gf2) -> Gf2_128 {
    <Gf2_128 as ExtensionField<Gf2>>::embed(v)
}

/// Least-significant bit of a MAC (the pointer-bit witness value, `Gf2`).
#[inline]
pub(crate) fn lsb(g: Gf2_128) -> Gf2 {
    Gf2(GetBit::<Lsb0>::get_bit(&g, 0))
}

/// Prover-side symbolic polynomial in `Δ` over committed wires.
///
/// `coeffs[h]` is the coefficient of `Δ^h`; the polynomial has degree `degree`
/// (`coeffs[degree]` is its top term, always `embed(value)`). `value` is the
/// cleartext evaluation `f(w)` — the witness this expression computes.
#[must_use]
#[derive(Clone, Copy, Debug)]
pub struct ProverExpr {
    coeffs: [Gf2_128; NC],
    degree: usize,
    value: Gf2,
}

impl ProverExpr {
    /// Degree-1 form `mac + value·X` for a committed wire.
    pub(crate) fn lift(mac: Gf2_128, value: Gf2) -> Self {
        let mut coeffs = [Gf2_128::ZERO; NC];
        coeffs[0] = mac;
        coeffs[1] = embed(value);
        Self {
            coeffs,
            degree: 1,
            value,
        }
    }

    /// Degree-0 public constant.
    pub(crate) fn constant(value: Gf2) -> Self {
        let mut coeffs = [Gf2_128::ZERO; NC];
        coeffs[0] = embed(value);
        Self {
            coeffs,
            degree: 0,
            value,
        }
    }

    /// Witness value computed by this expression.
    pub(crate) fn value(&self) -> Gf2 {
        self.value
    }

    /// Accumulate this expression's constraint contribution, χ-weighted, into
    /// `accumulators` (length `d_max`). The top `Δ^degree` coefficient (`= f(w)`,
    /// zero when satisfied) is dropped; the bottom `degree` coefficients are
    /// top-aligned to `d_max`.
    pub(crate) fn accumulate(&self, accumulators: &mut [Gf2_128], chi: Gf2_128) {
        let d_max = accumulators.len();
        debug_assert!(self.degree <= d_max, "constraint degree exceeds d_max");
        for h in 0..self.degree {
            accumulators[d_max - self.degree + h] =
                accumulators[d_max - self.degree + h] + self.coeffs[h] * chi;
        }
    }
}

impl Mul for ProverExpr {
    type Output = Self;

    /// Convolution of coefficients.
    fn mul(self, other: Self) -> Self {
        let degree = self.degree + other.degree;
        debug_assert!(degree < NC, "constraint degree exceeds MAX_DEGREE");
        let mut coeffs = [Gf2_128::ZERO; NC];
        for i in 0..=self.degree {
            for j in 0..=other.degree {
                coeffs[i + j] = coeffs[i + j] + self.coeffs[i] * other.coeffs[j];
            }
        }
        Self {
            coeffs,
            degree,
            value: self.value * other.value,
        }
    }
}

impl Add for ProverExpr {
    type Output = Self;

    /// Add, top-aligning the lower-degree operand.
    fn add(self, other: Self) -> Self {
        let degree = self.degree.max(other.degree);
        let mut coeffs = [Gf2_128::ZERO; NC];
        for k in 0..=self.degree {
            coeffs[degree - k] = self.coeffs[self.degree - k];
        }
        for k in 0..=other.degree {
            coeffs[degree - k] = coeffs[degree - k] + other.coeffs[other.degree - k];
        }
        Self {
            coeffs,
            degree,
            value: self.value + other.value,
        }
    }
}

impl Sub for ProverExpr {
    type Output = Self;

    /// Subtract. Characteristic 2, so identical to [`Add`].
    fn sub(self, other: Self) -> Self {
        self.add(other)
    }
}

/// Verifier-side symbolic polynomial in `Δ` over committed wires: the value
/// `g(Δ)` at the expression's own degree. Carries a reference to the precomputed
/// `Δ` powers so the operators can degree-align (`delta_pow[k] = Δ^k`).
#[must_use]
#[derive(Clone, Copy, Debug)]
pub struct VerifierExpr<'a> {
    val: Gf2_128,
    degree: usize,
    delta_pow: &'a [Gf2_128],
}

impl<'a> VerifierExpr<'a> {
    /// Degree-1 form for a committed wire: its key `k = mac + value·Δ`.
    pub(crate) fn lift(key: Gf2_128, delta_pow: &'a [Gf2_128]) -> Self {
        Self {
            val: key,
            degree: 1,
            delta_pow,
        }
    }

    /// Degree-0 public constant.
    pub(crate) fn constant(value: Gf2, delta_pow: &'a [Gf2_128]) -> Self {
        Self {
            val: embed(value),
            degree: 0,
            delta_pow,
        }
    }

    /// Detach the `delta_pow` borrow into a buffered [`VerifierTerm`].
    pub(crate) fn term(&self) -> VerifierTerm {
        VerifierTerm {
            val: self.val,
            degree: self.degree,
        }
    }
}

/// Buffered verifier constraint: the expression's value `g(Δ)` and degree,
/// detached from the `delta_pow` borrow so it can be stored across the walk.
#[derive(Clone, Copy, Debug)]
pub(crate) struct VerifierTerm {
    val: Gf2_128,
    degree: usize,
}

impl VerifierTerm {
    /// The batch contribution `B_i = g(Δ)·Δ^{d_max-degree}`, top-aligned to
    /// `d_max`. `delta_pow` must reach `delta_pow[d_max - degree]`.
    pub(crate) fn batch_value(&self, d_max: usize, delta_pow: &[Gf2_128]) -> Gf2_128 {
        self.val * delta_pow[d_max - self.degree]
    }
}

impl Mul for VerifierExpr<'_> {
    type Output = Self;

    fn mul(self, other: Self) -> Self {
        Self {
            val: self.val * other.val,
            degree: self.degree + other.degree,
            delta_pow: self.delta_pow,
        }
    }
}

impl Add for VerifierExpr<'_> {
    type Output = Self;

    /// Add, top-aligning the lower-degree operand via `Δ^shift`.
    fn add(self, other: Self) -> Self {
        let degree = self.degree.max(other.degree);
        let va = self.val * self.delta_pow[degree - self.degree];
        let vb = other.val * self.delta_pow[degree - other.degree];
        Self {
            val: va + vb,
            degree,
            delta_pow: self.delta_pow,
        }
    }
}

impl Sub for VerifierExpr<'_> {
    type Output = Self;

    /// Subtract. Characteristic 2, so identical to [`Add`].
    fn sub(self, other: Self) -> Self {
        self.add(other)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{Rng, SeedableRng, rngs::StdRng};

    fn delta_powers(delta: Gf2_128, up_to: usize) -> Vec<Gf2_128> {
        let mut p = vec![Gf2_128::ONE; up_to + 1];
        for i in 1..=up_to {
            p[i] = p[i - 1] * delta;
        }
        p
    }

    /// Evaluate a prover expression at `delta`.
    fn eval_prover(e: &ProverExpr, dp: &[Gf2_128]) -> Gf2_128 {
        let mut acc = Gf2_128::ZERO;
        for h in 0..=e.degree {
            acc = acc + e.coeffs[h] * dp[h];
        }
        acc
    }

    /// Degree-3 constraint `Y + a + r + u1·(s + a + r)` with `r = u0·(w + a)`,
    /// exercising mul, add, and reuse (an `acc_mux`-shaped polynomial). Generic
    /// over the operator-carrying expression type.
    fn gadget<E>(v: [E; 6]) -> E
    where
        E: Copy + Add<Output = E> + Mul<Output = E>,
    {
        let [y, a, w, s, u0, u1] = v;
        let r = u0 * (w + a);
        let inner = s + a + r;
        let u1_term = u1 * inner;
        y + a + r + u1_term
    }

    /// Differential: the prover's coefficient vector evaluated at `Δ` must equal
    /// the verifier's value, and the dropped top coefficient must be `embed(f(w))`.
    #[test]
    fn prover_verifier_agree_at_delta() {
        let mut rng = StdRng::seed_from_u64(0xC0FFEE);
        for _ in 0..256 {
            let delta = Gf2_128::new(rng.random());
            let dp = delta_powers(delta, MAX_DEGREE);

            let w: [Gf2; 6] = core::array::from_fn(|_| Gf2(rng.random()));
            let mac: [Gf2_128; 6] = core::array::from_fn(|_| Gf2_128::new(rng.random()));
            let key: [Gf2_128; 6] = core::array::from_fn(|i| mac[i] + embed(w[i]) * delta);

            let pe = gadget(core::array::from_fn(|i| ProverExpr::lift(mac[i], w[i])));
            let ve = gadget(core::array::from_fn(|i| VerifierExpr::lift(key[i], &dp)));

            assert_eq!(pe.degree, ve.degree, "degree disagreement");
            assert_eq!(
                eval_prover(&pe, &dp),
                ve.val,
                "prover poly at Δ disagrees with verifier value"
            );
            assert_eq!(pe.coeffs[pe.degree], embed(pe.value));
        }
    }

    /// `accumulate` (prover) and `batch_value` (verifier) satisfy the check
    /// `Σ B_i·χ_i = Σ_{h<d_max} U_h·Δ^h` for satisfied constraints (`f(w)=0`).
    #[test]
    fn accumulate_matches_batch_value() {
        let mut rng = StdRng::seed_from_u64(0x5EED);
        let delta = Gf2_128::new(rng.random());
        let d_max = 4usize;
        let dp = delta_powers(delta, d_max);

        let mut acc = vec![Gf2_128::ZERO; d_max];
        let mut rhs_b = Gf2_128::ZERO;

        // Two satisfied evaluations of `w0·w1 + w2 = 0` (w2 = w0·w1), degree 2.
        for _ in 0..2 {
            let w0 = Gf2(rng.random());
            let w1 = Gf2(rng.random());
            let w2 = w0 * w1;
            let m: [Gf2_128; 3] = core::array::from_fn(|_| Gf2_128::new(rng.random()));
            let w = [w0, w1, w2];
            let keys: [Gf2_128; 3] = core::array::from_fn(|i| m[i] + embed(w[i]) * delta);
            let chi = Gf2_128::new(rng.random());

            let pe = {
                let [a, b, c] = core::array::from_fn(|i| ProverExpr::lift(m[i], w[i]));
                a * b + c
            };
            assert_eq!(pe.value, Gf2::ZERO, "constraint must be satisfied");
            pe.accumulate(&mut acc, chi);

            let ve = {
                let [a, b, c] = core::array::from_fn(|i| VerifierExpr::lift(keys[i], &dp));
                a * b + c
            };
            rhs_b = rhs_b + ve.term().batch_value(d_max, &dp) * chi;
        }

        let lhs: Gf2_128 = (0..d_max)
            .map(|h| acc[h] * dp[h])
            .fold(Gf2_128::ZERO, |a, b| a + b);
        assert_eq!(lhs, rhs_b, "Σ U_h·Δ^h must equal Σ B_i·χ_i");
    }
}
