//! Polynomial-constraint expressions for the composite QuickSilver check
//! (eprint 2021/076, §5).
//!
//! A constraint is a polynomial `f` over committed wire values with
//! `f(w) = 0`. Instead of committing every intermediate product (circuit
//! mode), a degree-`d` constraint is evaluated *symbolically* into a
//! polynomial in `Δ`:
//!
//! - The prover holds, per wire, the linear form `mac + value·X`; building `f`
//!   over these forms yields the coefficient vector of
//!   `g(X) = Σ_h f_h(mac + value·X)·X^{d-h}` ([`ProverCoeffs<V>`]). The top
//!   coefficient (`X^d`) is `f(w)`, dropped by the protocol.
//! - The verifier holds, per wire, the key `k = mac + value·Δ`; building `f`
//!   over the keys yields `g(Δ)` directly ([`VerifierCoeffs`]).
//!
//! Both build the *same* expression with the `+`/`-`/`*` operators; at `Δ` the
//! prover's coefficient vector and the verifier's value agree. Addition
//! top-aligns operands (multiplying the lower-degree one by `X^shift` /
//! `Δ^shift`) so each (sub)expression stays top-aligned to its own degree,
//! matching the `X^{d-h}` weighting. All arithmetic is over characteristic-2
//! fields, so negation is the identity and subtraction equals addition.
//!
//! # Compile-time degree
//!
//! An expression's degree is part of its *type*: [`Expr<C, N>`] carries a
//! [`typenum`] degree `N`, and the operators raise it at the type level —
//! `Add` takes the max ([`Maximum`]), `Mul` the sum ([`Sum`]). This sizes the
//! prover's coefficient storage to the *actual* degree of each expression
//! (a degree-2 product stores two coefficients, not [`MAX_DEGREE`]), and lets
//! the compiler unroll the convolution and alignment loops. Gadgets stay
//! generic over the carrier `C` (so one definition runs on both prover and
//! verifier); the concrete degrees flow through inference without any
//! per-gadget bounds.
//!
//! The carrier `C` is what differs between the two sides ([`ProverCoeffs<V>`]
//! keeps a coefficient vector, [`VerifierCoeffs`] keeps the single value
//! `g(Δ)`); [`PlainCoeffs<V>`] collapses an expression to its cleartext value
//! for the prover's commit pass.
//!
//! # Representation
//!
//! The carriers are generic over the subfield `V` (the wire-value field): the
//! boolean path uses `V = Gf2`, the [`gf64`](crate::gf64) path `V = Gf2_64`,
//! and both embed into the `GF(2^128)` MAC field as
//! [`ExtensionField<V>`](ExtensionField). The expression algebra preserves a
//! stronger invariant: the *top* coefficient of every expression lies in the
//! subfield `V`. A lifted wire is `mac + value·X` (top = `value`), a constant
//! is a bare subfield element, top-aligned addition sums tops in `V`, and
//! multiplication multiplies them. [`ProverCoeffs<V>`] therefore stores the top
//! coefficient as a `V` `value` — which doubles as the cleartext evaluation
//! `f(w)` — and only the `N` lower coefficients as MAC-field elements. The
//! cross-terms between tops and lower coefficients are subfield scalings
//! ([`ExtensionField::scale_by_subfield`]) rather than full MAC
//! multiplications, so a degree `a × b` product costs `a·b` MAC multiplications
//! rather than `(a+1)·(b+1)`. For `V = Gf2` the scaling is a branchless masked
//! XOR (no carry-less multiply at all); for `V = Gf2_64` it is a full MAC
//! multiply — a property of each subfield's `scale_by_subfield` impl.
//!
//! # Accumulation
//!
//! The challenge streams during the accumulate pass, so a constraint is folded
//! into the running check state the moment it is asserted — expressions are
//! never buffered. The prover folds its χ-weighted coefficients top-aligned to
//! [`MAX_DEGREE`] into [`ProverPoly`]; the verifier buckets `χ·g(Δ)` by
//! constraint degree in [`VerifierPoly`], deferring the `Δ^{d_max-d}`
//! alignment factor to a single multiplication per bucket. Both are additive,
//! so disjoint sub-ranges of a trace fold independently and
//! [`merge`](ProverPoly::merge).

use core::{
    marker::PhantomData,
    ops::{Add, Mul, Sub},
};

use hybrid_array::{Array, ArraySize};
use mpz_circuits::Context;
use mpz_fields::{
    Accumulator, ExtensionField, Field,
    gf2_128::{Gf2_128, Gf2_128Accumulator},
};
use typenum::{Max, Maximum, Sum, U0, U1};

use crate::{Error, Result};

/// Degree bound for an [`Expr`]: a [`typenum`] size whose coefficient array is
/// `Copy`.
///
/// [`hybrid_array::Array<T, N>`] is only `Copy` when `N::ArrayType<T>: Copy`, a
/// fact [`ArraySize`] does not promise for a *generic* `N`. Bundling that
/// guarantee here keeps every [`Expr`] unconditionally `Copy` — so gadgets
/// reuse expressions freely — without threading per-degree `Copy` bounds
/// through gadget signatures. Blanket-implemented for every supported size.
pub trait Degree: ArraySize<ArrayType<Gf2_128>: Copy> {}

impl<N: ArraySize<ArrayType<Gf2_128>: Copy>> Degree for N {}

/// Polynomial-constraint extension of [`Context`].
///
/// Build a degree-`d` constraint symbolically over committed wires with the
/// `+`/`-`/`*` operators on [`Expr`] (free, degree-raising, uncommitted), then
/// either [`materialize`](Self::materialize) its output as a fresh committed
/// wire pinned by a degree-`d` constraint, or [`assert_zero`](Self::assert_zero)
/// it as a pure check. Implemented by the same contexts that implement
/// [`Context`].
pub trait PolyContext: Context {
    /// The coefficient carrier for this context's side of the protocol.
    type Coeffs: Coeffs;

    /// Lifts a committed wire into a degree-1 expression.
    fn lift(&self, wire: Self::Wire) -> Expr<Self::Coeffs, U1>;

    /// A degree-0 public constant.
    fn lift_const(&self, value: Self::Field) -> Expr<Self::Coeffs, U0>;

    /// Commits the expression's value as a fresh wire and records the
    /// degree-`d` constraint pinning it to the expression. Returns the
    /// committed wire.
    ///
    /// Consumes one tape entry and 16 bytes of the challenge stream.
    fn materialize<N>(&mut self, expr: Expr<Self::Coeffs, N>) -> Self::Wire
    where
        N: Degree + Max<U1>,
        Maximum<N, U1>: Degree;

    /// Records a degree-`d` constraint that `expr == 0` (no commitment).
    ///
    /// Consumes 16 bytes of the challenge stream when `d ≥ 1`; a degree-0
    /// expression is a public assertion checked locally.
    fn assert_zero<N: Degree>(&mut self, expr: Expr<Self::Coeffs, N>)
    -> Result<(), Self::Error>;
}

/// Maximum supported constraint degree.
///
/// The proof's `d_max` (the number of coefficients sent) is at most this; the
/// per-proof accumulators in [`ProverPoly`]/[`VerifierPoly`] are sized to it.
/// Individual expressions are *not* sized to this — their storage tracks their
/// own degree (see [`Expr`]).
pub const MAX_DEGREE: usize = 32;

/// A symbolic polynomial-in-`Δ` of compile-time degree `N` over committed
/// wires, carried by side `C`.
///
/// `Copy` and stack-allocated; composed with the `+`/`-`/`*` operators, which
/// raise the degree at the type level. The storage lives in `C::At<N>` and is
/// sized to `N`, not to [`MAX_DEGREE`].
#[must_use]
pub struct Expr<C: Coeffs, N: Degree> {
    pub(crate) store: C::At<N>,
}

impl<C: Coeffs, N: Degree> Expr<C, N> {
    #[inline]
    pub(crate) fn new(store: C::At<N>) -> Self {
        Self { store }
    }
}

impl<C: Coeffs, N: Degree> Clone for Expr<C, N> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<C: Coeffs, N: Degree> Copy for Expr<C, N> {}

impl<C, A, B> Add<Expr<C, B>> for Expr<C, A>
where
    C: Coeffs,
    A: Degree + Max<B>,
    B: Degree,
    Maximum<A, B>: Degree,
{
    type Output = Expr<C, Maximum<A, B>>;

    #[inline]
    fn add(self, other: Expr<C, B>) -> Self::Output {
        Expr::new(C::add::<A, B>(self.store, other.store))
    }
}

impl<C, A, B> Sub<Expr<C, B>> for Expr<C, A>
where
    C: Coeffs,
    A: Degree + Max<B>,
    B: Degree,
    Maximum<A, B>: Degree,
{
    type Output = Expr<C, Maximum<A, B>>;

    /// Subtracts. Characteristic 2, so identical to [`Add`].
    #[inline]
    fn sub(self, other: Expr<C, B>) -> Self::Output {
        self.add(other)
    }
}

impl<C, A, B> Mul<Expr<C, B>> for Expr<C, A>
where
    C: Coeffs,
    A: Degree + Add<B>,
    B: Degree,
    Sum<A, B>: Degree,
{
    type Output = Expr<C, Sum<A, B>>;

    #[inline]
    fn mul(self, other: Expr<C, B>) -> Self::Output {
        Expr::new(C::mul::<A, B>(self.store, other.store))
    }
}

/// A per-side coefficient carrier: the storage and primitive arithmetic for
/// one protocol role.
///
/// `At<N>` is the storage for a degree-`N` expression. The two non-trivial
/// operations — top-aligned [`add`](Self::add) and degree-raising
/// [`mul`](Self::mul) — are degree-generic so [`Expr`]'s operators can delegate
/// to them. Implemented by [`PlainCoeffs<V>`] (commit pass), [`ProverCoeffs<V>`],
/// and [`VerifierCoeffs`].
pub trait Coeffs: Copy {
    /// Storage for a degree-`N` expression.
    type At<N: Degree>: Copy;

    /// Top-aligned sum of a degree-`A` and a degree-`B` expression, at the
    /// larger degree.
    fn add<A, B>(a: Self::At<A>, b: Self::At<B>) -> Self::At<Maximum<A, B>>
    where
        A: Degree + Max<B>,
        B: Degree,
        Maximum<A, B>: Degree;

    /// Product of a degree-`A` and a degree-`B` expression, at degree `A + B`.
    fn mul<A, B>(a: Self::At<A>, b: Self::At<B>) -> Self::At<Sum<A, B>>
    where
        A: Degree + Add<B>,
        B: Degree,
        Sum<A, B>: Degree;
}

// --- commit-pass carrier ----------------------------------------------------

/// Plaintext carrier for the prover's commit pass over the subfield `V`: an
/// expression is just its cleartext value, so polynomial gadgets compile down
/// to subfield operations.
pub struct PlainCoeffs<V>(PhantomData<V>);

impl<V> Clone for PlainCoeffs<V> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<V> Copy for PlainCoeffs<V> {}

impl<V: Field> Coeffs for PlainCoeffs<V> {
    type At<N: Degree> = V;

    #[inline]
    fn add<A, B>(a: V, b: V) -> V
    where
        A: Degree + Max<B>,
        B: Degree,
        Maximum<A, B>: Degree,
    {
        a + b
    }

    #[inline]
    fn mul<A, B>(a: V, b: V) -> V
    where
        A: Degree + Add<B>,
        B: Degree,
        Sum<A, B>: Degree,
    {
        a * b
    }
}

impl<V: Field, N: Degree> Expr<PlainCoeffs<V>, N> {
    /// The cleartext subfield value this expression evaluates to.
    #[inline]
    pub(crate) fn plain(self) -> V {
        self.store
    }
}

// --- prover carrier ---------------------------------------------------------

/// Prover-side coefficient carrier over the subfield `V`: keeps the
/// `Δ`-polynomial's lower coefficients and its subfield top.
pub struct ProverCoeffs<V>(PhantomData<V>);

impl<V> Clone for ProverCoeffs<V> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<V> Copy for ProverCoeffs<V> {}

/// Storage for a degree-`N` prover expression: the `N` lower coefficients
/// (`coeffs[h]` is the coefficient of `Δ^h`) and the subfield top coefficient
/// `value` (of `Δ^N`), which is the cleartext evaluation `f(w)`.
pub struct ProverStore<V, N: Degree> {
    pub(crate) coeffs: Array<Gf2_128, N>,
    pub(crate) value: V,
}

impl<V: Field, N: Degree> Clone for ProverStore<V, N> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<V: Field, N: Degree> Copy for ProverStore<V, N> {}

impl<V: Field> Coeffs for ProverCoeffs<V>
where
    Gf2_128: ExtensionField<V>,
{
    type At<N: Degree> = ProverStore<V, N>;

    #[inline]
    fn add<A, B>(a: ProverStore<V, A>, b: ProverStore<V, B>) -> ProverStore<V, Maximum<A, B>>
    where
        A: Degree + Max<B>,
        B: Degree,
        Maximum<A, B>: Degree,
    {
        let (da, db) = (A::USIZE, B::USIZE);
        let dmax = da.max(db);
        let mut coeffs = Array::<Gf2_128, Maximum<A, B>>::from_fn(|_| Gf2_128::ZERO);
        // Each operand top-aligns: coeff of degree `d` lands at `dmax - own + d`.
        for h in 0..da {
            coeffs[(dmax - da) + h] = coeffs[(dmax - da) + h] + a.coeffs[h];
        }
        for h in 0..db {
            coeffs[(dmax - db) + h] = coeffs[(dmax - db) + h] + b.coeffs[h];
        }
        ProverStore {
            coeffs,
            value: a.value + b.value,
        }
    }

    #[inline]
    fn mul<A, B>(a: ProverStore<V, A>, b: ProverStore<V, B>) -> ProverStore<V, Sum<A, B>>
    where
        A: Degree + Add<B>,
        B: Degree,
        Sum<A, B>: Degree,
    {
        let (da, db) = (A::USIZE, B::USIZE);
        let mut coeffs = Array::<Gf2_128, Sum<A, B>>::from_fn(|_| Gf2_128::ZERO);
        // Convolution of the lower coefficients.
        for i in 0..da {
            for j in 0..db {
                coeffs[i + j] = coeffs[i + j] + a.coeffs[i] * b.coeffs[j];
            }
        }
        // Cross-terms against the subfield tops: subfield scalings
        // (a branchless masked XOR for `V = Gf2`, a full MAC multiply for
        // `V = Gf2_64` — see `ExtensionField::scale_by_subfield`).
        for i in 0..da {
            coeffs[i + db] = coeffs[i + db] + a.coeffs[i].scale_by_subfield(b.value);
        }
        for j in 0..db {
            coeffs[j + da] = coeffs[j + da] + b.coeffs[j].scale_by_subfield(a.value);
        }
        ProverStore {
            coeffs,
            value: a.value * b.value,
        }
    }
}

impl<V: Field> Expr<ProverCoeffs<V>, U1>
where
    Gf2_128: ExtensionField<V>,
{
    /// Degree-1 form `mac + value·X` for a committed wire.
    ///
    /// The caller supplies the cleartext `value` (the top coefficient): in the
    /// boolean path it is read off the MAC's LSB, in the
    /// [`gf64`](crate::gf64) path it is carried explicitly.
    #[inline]
    pub(crate) fn lift_wire(mac: Gf2_128, value: V) -> Self {
        let mut coeffs = Array::<Gf2_128, U1>::from_fn(|_| Gf2_128::ZERO);
        coeffs[0] = mac;
        Expr::new(ProverStore { coeffs, value })
    }
}

impl<V: Field> Expr<ProverCoeffs<V>, U0>
where
    Gf2_128: ExtensionField<V>,
{
    /// Degree-0 public constant.
    #[inline]
    pub(crate) fn constant(value: V) -> Self {
        Expr::new(ProverStore {
            coeffs: Array::<Gf2_128, U0>::from_fn(|_| Gf2_128::ZERO),
            value,
        })
    }
}

impl<V: Field, N: Degree> Expr<ProverCoeffs<V>, N>
where
    Gf2_128: ExtensionField<V>,
{
    /// The witness value computed by this expression: its top coefficient.
    #[inline]
    pub(crate) fn value(self) -> V {
        self.store.value
    }
}

// --- verifier carrier -------------------------------------------------------

/// Verifier-side coefficient carrier: keeps the single value `g(Δ)` at the
/// expression's own degree, plus `Δ` for top-alignment in `add`.
#[derive(Clone, Copy, Debug)]
pub struct VerifierCoeffs;

/// Storage for a verifier expression: its value `g(Δ)` and `Δ` (carried so
/// [`add`](Coeffs::add) can compute the `Δ^shift` top-alignment factor without
/// borrowing a powers table — the degree gap is small and known at compile
/// time, so the power fully unrolls).
#[derive(Clone, Copy, Debug)]
pub struct VerifierStore {
    val: Gf2_128,
    delta: Gf2_128,
}

/// `base^exp` by repeated multiplication; `exp` is the (small) degree gap.
#[inline]
fn pow(base: Gf2_128, exp: usize) -> Gf2_128 {
    let mut acc = Gf2_128::ONE;
    for _ in 0..exp {
        acc = acc * base;
    }
    acc
}

impl Coeffs for VerifierCoeffs {
    type At<N: Degree> = VerifierStore;

    #[inline]
    fn add<A, B>(a: VerifierStore, b: VerifierStore) -> VerifierStore
    where
        A: Degree + Max<B>,
        B: Degree,
        Maximum<A, B>: Degree,
    {
        let (da, db) = (A::USIZE, B::USIZE);
        let dmax = da.max(db);
        let val = a.val * pow(a.delta, dmax - da) + b.val * pow(b.delta, dmax - db);
        VerifierStore {
            val,
            delta: a.delta,
        }
    }

    #[inline]
    fn mul<A, B>(a: VerifierStore, b: VerifierStore) -> VerifierStore
    where
        A: Degree + Add<B>,
        B: Degree,
        Sum<A, B>: Degree,
    {
        VerifierStore {
            val: a.val * b.val,
            delta: a.delta,
        }
    }
}

impl Expr<VerifierCoeffs, U1> {
    /// Degree-1 form for a committed wire: its key `k = mac + value·Δ`.
    #[inline]
    pub(crate) fn lift_key(key: Gf2_128, delta: Gf2_128) -> Self {
        Expr::new(VerifierStore { val: key, delta })
    }
}

impl Expr<VerifierCoeffs, U0> {
    /// Degree-0 public constant over the subfield `V`: `g(Δ) = embed(value)`.
    #[inline]
    pub(crate) fn constant<V: Field>(value: V, delta: Gf2_128) -> Self
    where
        Gf2_128: ExtensionField<V>,
    {
        Expr::new(VerifierStore {
            val: <Gf2_128 as ExtensionField<V>>::embed(value),
            delta,
        })
    }
}

impl<N: Degree> Expr<VerifierCoeffs, N> {
    /// The expression's value `g(Δ)`.
    #[inline]
    pub(crate) fn value(self) -> Gf2_128 {
        self.store.val
    }
}

// --- accumulation -----------------------------------------------------------

/// The prover's running polynomial-check state.
///
/// Constraint coefficients are folded in χ-weighted and top-aligned to
/// [`MAX_DEGREE`] with deferred reduction; positions below
/// `MAX_DEGREE - d_max` stay untouched, so [`coefficients`](Self::coefficients)
/// can slice out any `d_max ≥` the maximum degree seen. Partial states from
/// disjoint sub-ranges combine with [`merge`](Self::merge).
#[derive(Debug, Clone)]
pub struct ProverPoly {
    acc: [Gf2_128Accumulator; MAX_DEGREE],
    max_degree: usize,
}

impl Default for ProverPoly {
    fn default() -> Self {
        Self {
            acc: [Gf2_128Accumulator::zero(); MAX_DEGREE],
            max_degree: 0,
        }
    }
}

impl ProverPoly {
    /// Folds a constraint's χ-weighted lower coefficients, dropping the top
    /// (`= f(w)`, zero when satisfied).
    ///
    /// # Panics
    ///
    /// Panics if `coeffs.len()` exceeds [`MAX_DEGREE`].
    #[inline]
    pub(crate) fn fold(&mut self, coeffs: &[Gf2_128], chi: Gf2_128) {
        let d = coeffs.len();
        assert!(d <= MAX_DEGREE, "constraint degree exceeds MAX_DEGREE");
        let off = MAX_DEGREE - d;
        for (acc, &c) in self.acc[off..].iter_mut().zip(coeffs) {
            acc.add_product(c, chi);
        }
        self.max_degree = self.max_degree.max(d);
    }

    /// Folds an expression's χ-weighted lower coefficients into the running
    /// state.
    ///
    /// The shared body of [`PolyContext::materialize`] and
    /// [`PolyContext::assert_zero`] on the prover side: both reduce to folding
    /// the coefficient vector of some [`Expr<ProverCoeffs<V>, N>`] (a pinned
    /// `expr - wire` constraint, or the bare assertion).
    #[inline]
    pub(crate) fn fold_expr<V: Field, N: Degree>(
        &mut self,
        expr: &Expr<ProverCoeffs<V>, N>,
        chi: Gf2_128,
    ) where
        Gf2_128: ExtensionField<V>,
    {
        self.fold(&expr.store.coeffs, chi);
    }

    /// Records a degree-`d` constraint that `expr == 0`.
    ///
    /// Surfaces a witness bug early via the top coefficient `f(w) = expr.value`,
    /// short-circuits the degree-0 public case (no fold, no challenge drawn),
    /// and otherwise folds the lower coefficients under a freshly drawn `chi`.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] if the witness value is non-zero.
    #[inline]
    pub(crate) fn assert_expr<V: Field, N: Degree>(
        &mut self,
        expr: &Expr<ProverCoeffs<V>, N>,
        draw_chi: impl FnOnce() -> Gf2_128,
    ) -> Result<()>
    where
        Gf2_128: ExtensionField<V>,
    {
        if expr.value() != V::zero() {
            return Err(Error::assert());
        }
        // A degree-0 expression is a public assertion; nothing to fold.
        if N::USIZE == 0 {
            return Ok(());
        }
        self.fold(&expr.store.coeffs, draw_chi());
        Ok(())
    }

    /// The maximum constraint degree folded in so far.
    pub fn max_degree(&self) -> usize {
        self.max_degree
    }

    /// `true` if no constraint has been folded in.
    pub fn is_empty(&self) -> bool {
        self.max_degree == 0
    }

    /// Adds another partial state into `self`.
    ///
    /// Used to combine sub-ranges of a trace folded independently.
    pub fn merge(&mut self, other: &Self) {
        for (a, b) in self.acc.iter_mut().zip(&other.acc) {
            a.merge(b);
        }
        self.max_degree = self.max_degree.max(other.max_degree);
    }

    /// Reduces to the proof coefficients `U_0 ..= U_{d_max - 1}`.
    ///
    /// The caller masks them with the degree-`d_max` VOPE coefficients before
    /// sending (see [`Proof::coefficients`](crate::Proof::coefficients)).
    ///
    /// # Errors
    ///
    /// Returns [`Error`] if `d_max` exceeds [`MAX_DEGREE`] or is smaller than
    /// the maximum constraint degree folded in.
    pub fn coefficients(&self, d_max: usize) -> Result<Vec<Gf2_128>> {
        if d_max > MAX_DEGREE || self.max_degree > d_max {
            return Err(Error::degree(self.max_degree, d_max));
        }
        Ok((0..d_max)
            .map(|h| self.acc[MAX_DEGREE - d_max + h].reduce())
            .collect())
    }
}

/// Precomputed powers `Δ^0 ..= Δ^MAX_DEGREE` of the verifier's MAC key, used by
/// [`VerifierPoly::check`].
#[derive(Debug, Clone)]
pub struct DeltaPowers {
    pow: [Gf2_128; MAX_DEGREE + 1],
}

impl DeltaPowers {
    /// Precomputes the powers of `delta`.
    pub fn new(delta: Gf2_128) -> Self {
        let mut pow = [Gf2_128::ONE; MAX_DEGREE + 1];
        for i in 1..=MAX_DEGREE {
            pow[i] = pow[i - 1] * delta;
        }
        Self { pow }
    }

    /// The MAC key `Δ` itself.
    pub fn delta(&self) -> Gf2_128 {
        self.pow[1]
    }
}

/// The verifier's running polynomial-check state.
///
/// Each constraint contributes `χ·g(Δ)` into the bucket of its degree with
/// deferred reduction; the `Δ^{d_max - d}` top-alignment factor is applied
/// once per bucket in [`check`](Self::check). Partial states from disjoint
/// sub-ranges combine with [`merge`](Self::merge).
#[derive(Debug, Clone)]
pub struct VerifierPoly {
    /// `buckets[d]` accumulates `Σ χ_i·g_i(Δ)` over degree-`d` constraints;
    /// index 0 is unused (degree-0 assertions are public, checked locally).
    buckets: [Gf2_128Accumulator; MAX_DEGREE + 1],
    max_degree: usize,
}

impl Default for VerifierPoly {
    fn default() -> Self {
        Self {
            buckets: [Gf2_128Accumulator::zero(); MAX_DEGREE + 1],
            max_degree: 0,
        }
    }
}

impl VerifierPoly {
    /// Folds a constraint's χ-weighted value into its degree bucket.
    ///
    /// # Panics
    ///
    /// Panics if `degree` exceeds [`MAX_DEGREE`].
    #[inline]
    pub(crate) fn fold(&mut self, val: Gf2_128, degree: usize, chi: Gf2_128) {
        assert!(degree <= MAX_DEGREE, "constraint degree exceeds MAX_DEGREE");
        self.buckets[degree].add_product(val, chi);
        self.max_degree = self.max_degree.max(degree);
    }

    /// Folds an expression's χ-weighted value `g(Δ)` into its degree bucket.
    ///
    /// The shared body of [`PolyContext::materialize`] (which folds the pinned
    /// `expr - wire` constraint at degree `Maximum::<N, U1>::USIZE`) on the
    /// verifier side; the caller supplies the bucket `degree`.
    #[inline]
    pub(crate) fn fold_expr<N: Degree>(
        &mut self,
        expr: &Expr<VerifierCoeffs, N>,
        degree: usize,
        chi: Gf2_128,
    ) {
        self.fold(expr.value(), degree, chi);
    }

    /// Records a degree-`d` constraint that `expr == 0`.
    ///
    /// Short-circuits the degree-0 public case (checked locally, no fold and no
    /// challenge drawn), and otherwise folds `g(Δ)` into bucket `N::USIZE`
    /// under a freshly drawn `chi`.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] if a degree-0 expression's value is non-zero.
    #[inline]
    pub(crate) fn assert_expr<N: Degree>(
        &mut self,
        expr: &Expr<VerifierCoeffs, N>,
        draw_chi: impl FnOnce() -> Gf2_128,
    ) -> Result<()> {
        // A degree-0 expression is a public assertion, checked locally.
        if N::USIZE == 0 {
            if expr.value() != Gf2_128::ZERO {
                return Err(Error::assert());
            }
            return Ok(());
        }
        self.fold(expr.value(), N::USIZE, draw_chi());
        Ok(())
    }

    /// The maximum constraint degree folded in so far.
    pub fn max_degree(&self) -> usize {
        self.max_degree
    }

    /// `true` if no constraint has been folded in.
    pub fn is_empty(&self) -> bool {
        self.max_degree == 0
    }

    /// Adds another partial state into `self`.
    ///
    /// Used to combine sub-ranges of a trace folded independently.
    pub fn merge(&mut self, other: &Self) {
        for (a, b) in self.buckets.iter_mut().zip(&other.buckets) {
            a.merge(b);
        }
        self.max_degree = self.max_degree.max(other.max_degree);
    }

    /// Checks the prover's masked coefficients against the accumulated state:
    /// `Σ_i χ_i·B_i + B* = Σ_h U_h·Δ^h`, with `d_max = coefficients.len()`,
    /// `B_i = g_i(Δ)·Δ^{d_max - d_i}` and `B* = vope_sum` the verifier's side
    /// of the degree-`d_max` VOPE correlation.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] if `d_max` exceeds [`MAX_DEGREE`], is smaller than
    /// the maximum constraint degree folded in, or the check equation does not
    /// hold.
    pub fn check(
        &self,
        powers: &DeltaPowers,
        coefficients: &[Gf2_128],
        vope_sum: Gf2_128,
    ) -> Result<()> {
        let d_max = coefficients.len();
        if d_max > MAX_DEGREE || self.max_degree > d_max {
            return Err(Error::degree(self.max_degree, d_max));
        }

        let mut b = vope_sum;
        for d in 1..=d_max {
            b = b + self.buckets[d].reduce() * powers.pow[d_max - d];
        }

        let rhs = coefficients
            .iter()
            .zip(&powers.pow)
            .map(|(&u, &p)| u * p)
            .fold(Gf2_128::ZERO, |a, x| a + x);

        if b != rhs {
            return Err(Error::check());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::lsb;
    use mpz_fields::gf2::Gf2;
    use rand::{Rng, SeedableRng, rngs::StdRng};
    use typenum::{U2, U3, U4};

    /// Embeds a witness bit into the MAC field.
    fn embed(v: Gf2) -> Gf2_128 {
        <Gf2_128 as ExtensionField<Gf2>>::embed(v)
    }

    /// A wire pair: prover MAC (LSB = value) and verifier key
    /// (`key = mac + value·Δ`, LSB of key = 0).
    fn wire(rng: &mut StdRng, value: bool, delta: Gf2_128) -> (Gf2_128, Gf2_128) {
        let key = Gf2_128::new(rng.random::<u128>() & !1);
        let mac = if value { key + delta } else { key };
        (mac, key)
    }

    fn random_delta(rng: &mut StdRng) -> Gf2_128 {
        Gf2_128::new(rng.random::<u128>() | 1)
    }

    /// Degree-3 constraint `Y + a + r + u1·(s + a + r)` with `r = u0·(w + a)`,
    /// exercising mul, add, and reuse (an `acc_mux`-shaped polynomial).
    /// Generic over the carrier so it runs on both sides.
    fn gadget<C: Coeffs>(v: [Expr<C, U1>; 6]) -> Expr<C, U3> {
        let [y, a, w, s, u0, u1] = v;
        let r = u0 * (w + a);
        let inner = s + a + r;
        let u1_term = u1 * inner;
        y + a + r + u1_term
    }

    /// Lifts six prover wires into degree-1 expressions.
    fn prover_lift(macs: [Gf2_128; 6]) -> [Expr<ProverCoeffs<Gf2>, U1>; 6] {
        core::array::from_fn(|i| Expr::<ProverCoeffs<Gf2>, U1>::lift_wire(macs[i], lsb(macs[i])))
    }

    /// Lifts six verifier keys into degree-1 expressions.
    fn verifier_lift(keys: [Gf2_128; 6], delta: Gf2_128) -> [Expr<VerifierCoeffs, U1>; 6] {
        core::array::from_fn(|i| Expr::<VerifierCoeffs, U1>::lift_key(keys[i], delta))
    }

    /// Evaluates a prover expression at `Δ`, including the subfield top.
    fn eval_prover<N: Degree>(e: Expr<ProverCoeffs<Gf2>, N>, delta: Gf2_128) -> Gf2_128 {
        let mut acc = embed(e.store.value) * pow(delta, N::USIZE);
        for h in 0..N::USIZE {
            acc = acc + e.store.coeffs[h] * pow(delta, h);
        }
        acc
    }

    /// Differential: the prover's coefficient vector evaluated at `Δ` must
    /// equal the verifier's value, and the top coefficient must be `f(w)`.
    #[test]
    fn prover_verifier_agree_at_delta() {
        let mut rng = StdRng::seed_from_u64(0xC0FFEE);
        for _ in 0..256 {
            let delta = random_delta(&mut rng);

            let bits: [bool; 6] = core::array::from_fn(|_| rng.random());
            let pairs: [(Gf2_128, Gf2_128); 6] =
                core::array::from_fn(|i| wire(&mut rng, bits[i], delta));
            let macs: [Gf2_128; 6] = core::array::from_fn(|i| pairs[i].0);
            let keys: [Gf2_128; 6] = core::array::from_fn(|i| pairs[i].1);

            let pe = gadget(prover_lift(macs));
            let ve = gadget(verifier_lift(keys, delta));

            assert_eq!(
                eval_prover(pe, delta),
                ve.value(),
                "prover poly at Δ disagrees with verifier value"
            );

            let expected = {
                let w: [Gf2; 6] = core::array::from_fn(|i| Gf2(bits[i]));
                let r = w[4] * (w[2] + w[1]);
                w[0] + w[1] + r + w[5] * (w[3] + w[1] + r)
            };
            assert_eq!(pe.value(), expected, "top coefficient must be f(w)");
        }
    }

    /// Folds the lower coefficients of a degree-`N` prover expression.
    fn fold_prover<N: Degree>(poly: &mut ProverPoly, e: Expr<ProverCoeffs<Gf2>, N>, chi: Gf2_128) {
        poly.fold(&e.store.coeffs, chi);
    }

    /// `ProverPoly::fold` and `VerifierPoly::check` satisfy the batch check
    /// for satisfied constraints of mixed degrees.
    #[test]
    fn accumulate_matches_batch_value() {
        let mut rng = StdRng::seed_from_u64(0x5EED);
        let delta = random_delta(&mut rng);
        let powers = DeltaPowers::new(delta);
        let d_max = 4usize;

        let mut prover = ProverPoly::default();
        let mut verifier = VerifierPoly::default();

        // Degree-2 instances of `w0·w1 + w2 = 0` (w2 = w0·w1).
        for _ in 0..4 {
            let w0: bool = rng.random();
            let w1: bool = rng.random();
            let pairs: [(Gf2_128, Gf2_128); 3] = [
                wire(&mut rng, w0, delta),
                wire(&mut rng, w1, delta),
                wire(&mut rng, w0 & w1, delta),
            ];
            let chi = Gf2_128::new(rng.random());

            let pe = {
                let [a, b, c] =
                    core::array::from_fn(|i| {
                        Expr::<ProverCoeffs<Gf2>, U1>::lift_wire(pairs[i].0, lsb(pairs[i].0))
                    });
                a * b + c
            };
            assert_eq!(pe.value(), Gf2::ZERO, "constraint must be satisfied");
            fold_prover(&mut prover, pe, chi);

            let ve = {
                let [a, b, c] = core::array::from_fn(|i| {
                    Expr::<VerifierCoeffs, U1>::lift_key(pairs[i].1, delta)
                });
                a * b + c
            };
            verifier.fold(ve.value(), 2, chi);
        }
        // Degree-3 gadget instances with Y solved so the gadget is zero.
        for _ in 0..4 {
            let mut w: [Gf2; 6] = core::array::from_fn(|_| Gf2(rng.random()));
            w[0] = Gf2::ZERO;
            let r = w[4] * (w[2] + w[1]);
            w[0] = w[1] + r + w[5] * (w[3] + w[1] + r);
            let pairs: [(Gf2_128, Gf2_128); 6] =
                core::array::from_fn(|i| wire(&mut rng, w[i].0, delta));
            let macs: [Gf2_128; 6] = core::array::from_fn(|i| pairs[i].0);
            let keys: [Gf2_128; 6] = core::array::from_fn(|i| pairs[i].1);
            let chi = Gf2_128::new(rng.random());

            let pe = gadget(prover_lift(macs));
            assert_eq!(pe.value(), Gf2::ZERO);
            fold_prover(&mut prover, pe, chi);

            let ve = gadget(verifier_lift(keys, delta));
            verifier.fold(ve.value(), 3, chi);
        }

        let coefficients = prover.coefficients(d_max).unwrap();
        verifier
            .check(&powers, &coefficients, Gf2_128::ZERO)
            .unwrap();

        // Corrupting a coefficient breaks the check.
        let mut bad = coefficients.clone();
        bad[1] = bad[1] + Gf2_128::ONE;
        assert!(verifier.check(&powers, &bad, Gf2_128::ZERO).is_err());
    }

    /// Merged sub-range partials equal the full fold.
    #[test]
    fn merge_matches_full() {
        let mut rng = StdRng::seed_from_u64(0xFAB);
        let delta = random_delta(&mut rng);

        struct Item {
            macs: [Gf2_128; 6],
            keys: [Gf2_128; 6],
            chi: Gf2_128,
        }
        let items: Vec<Item> = (0..10)
            .map(|_| {
                let bits: [bool; 6] = core::array::from_fn(|_| rng.random());
                let pairs: [(Gf2_128, Gf2_128); 6] =
                    core::array::from_fn(|i| wire(&mut rng, bits[i], delta));
                Item {
                    macs: core::array::from_fn(|i| pairs[i].0),
                    keys: core::array::from_fn(|i| pairs[i].1),
                    chi: Gf2_128::new(rng.random()),
                }
            })
            .collect();

        let mut full = ProverPoly::default();
        let mut lo = ProverPoly::default();
        let mut hi = ProverPoly::default();
        for (i, it) in items.iter().enumerate() {
            let pe = gadget(prover_lift(it.macs));
            fold_prover(&mut full, pe, it.chi);
            fold_prover(if i < 5 { &mut lo } else { &mut hi }, pe, it.chi);
        }
        lo.merge(&hi);
        assert_eq!(full.coefficients(4).unwrap(), lo.coefficients(4).unwrap());

        let mut v_full = VerifierPoly::default();
        let mut v_lo = VerifierPoly::default();
        let mut v_hi = VerifierPoly::default();
        for (i, it) in items.iter().enumerate() {
            let ve = gadget(verifier_lift(it.keys, delta));
            v_full.fold(ve.value(), 3, it.chi);
            (if i < 5 { &mut v_lo } else { &mut v_hi }).fold(ve.value(), 3, it.chi);
        }
        v_lo.merge(&v_hi);
        for d in 0..=MAX_DEGREE {
            assert_eq!(
                v_full.buckets[d].reduce(),
                v_lo.buckets[d].reduce(),
                "bucket {d}"
            );
        }
    }

    /// `d_max` smaller than the maximum folded degree is rejected.
    #[test]
    fn d_max_too_small_rejected() {
        let mut rng = StdRng::seed_from_u64(0xD0D0);
        let delta = random_delta(&mut rng);
        let powers = DeltaPowers::new(delta);

        let pairs: [(Gf2_128, Gf2_128); 6] =
            core::array::from_fn(|_| wire(&mut rng, false, delta));
        let macs: [Gf2_128; 6] = core::array::from_fn(|i| pairs[i].0);
        let keys: [Gf2_128; 6] = core::array::from_fn(|i| pairs[i].1);

        let mut prover = ProverPoly::default();
        fold_prover(&mut prover, gadget(prover_lift(macs)), Gf2_128::ONE);
        assert!(prover.coefficients(2).is_err());
        assert!(prover.coefficients(MAX_DEGREE + 1).is_err());

        let mut verifier = VerifierPoly::default();
        verifier.fold(gadget(verifier_lift(keys, delta)).value(), 3, Gf2_128::ONE);
        assert!(
            verifier
                .check(&powers, &[Gf2_128::ZERO; 2], Gf2_128::ZERO)
                .is_err()
        );
    }

    /// The plaintext carrier collapses a gadget to its cleartext bit, matching
    /// the prover expression's top.
    #[test]
    fn plain_matches_top() {
        let mut rng = StdRng::seed_from_u64(0x9);
        let delta = random_delta(&mut rng);
        for _ in 0..64 {
            let bits: [bool; 6] = core::array::from_fn(|_| rng.random());
            let macs: [Gf2_128; 6] = core::array::from_fn(|i| {
                let (m, _) = wire(&mut rng, bits[i], delta);
                m
            });
            let plain: [Expr<PlainCoeffs<Gf2>, U1>; 6] =
                core::array::from_fn(|i| Expr::new(Gf2(bits[i])));
            let pe = gadget(prover_lift(macs));
            let ce: Expr<PlainCoeffs<Gf2>, U3> = gadget(plain);
            assert_eq!(ce.plain(), pe.value());
        }
    }

    /// Reduction tree over 3 selectors and 8 leaves: each level is a 2-to-1
    /// mux `a + sel·(a + b)` that raises the degree by one (degree 2 → 3 → 4),
    /// exercising mixed-degree adds and muls. The degrees are concrete at each
    /// level, so the gadget stays generic over the carrier with no extra
    /// bounds.
    fn mux_tree<C: Coeffs>(s: [Expr<C, U1>; 3], x: [Expr<C, U1>; 8]) -> Expr<C, U4> {
        let m0: [Expr<C, U2>; 4] = core::array::from_fn(|j| x[2 * j] + s[0] * (x[2 * j] + x[2 * j + 1]));
        let m1: [Expr<C, U3>; 2] = core::array::from_fn(|j| m0[2 * j] + s[1] * (m0[2 * j] + m0[2 * j + 1]));
        m1[0] + s[2] * (m1[0] + m1[1])
    }

    /// The degree-4 reduction tree round-trips: prover coefficients at `Δ`
    /// equal the verifier value, on the same carrier-generic gadget.
    #[test]
    fn high_degree_round_trip() {
        let mut rng = StdRng::seed_from_u64(0x600);
        let delta = random_delta(&mut rng);

        for _ in 0..64 {
            let sbits: [bool; 3] = core::array::from_fn(|_| rng.random());
            let xbits: [bool; 8] = core::array::from_fn(|_| rng.random());
            let sw: [(Gf2_128, Gf2_128); 3] =
                core::array::from_fn(|i| wire(&mut rng, sbits[i], delta));
            let xw: [(Gf2_128, Gf2_128); 8] =
                core::array::from_fn(|i| wire(&mut rng, xbits[i], delta));

            let pe = mux_tree(
                core::array::from_fn(|i| {
                    Expr::<ProverCoeffs<Gf2>, U1>::lift_wire(sw[i].0, lsb(sw[i].0))
                }),
                core::array::from_fn(|i| {
                    Expr::<ProverCoeffs<Gf2>, U1>::lift_wire(xw[i].0, lsb(xw[i].0))
                }),
            );
            let ve = mux_tree(
                core::array::from_fn(|i| Expr::<VerifierCoeffs, U1>::lift_key(sw[i].1, delta)),
                core::array::from_fn(|i| Expr::<VerifierCoeffs, U1>::lift_key(xw[i].1, delta)),
            );

            assert_eq!(eval_prover(pe, delta), ve.value());
        }
    }
}
