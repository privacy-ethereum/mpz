//! Circuits over `GF(2^64)` with `GF(2^128)` MACs (a subfield IT-MAC).
//!
//! The boolean path ([`Prover`](crate::Prover)/[`Verifier`](crate::Verifier))
//! packs the committed bit into the MAC's LSB (the pointer-bit trick); a 64-bit
//! value cannot be packed that way, so this path carries the value explicitly.
//!
//! A committed value `x ∈ GF(2^64)` is authenticated by `M = K + embed(x)·Δ`,
//! where `M` (prover MAC) and `K` (verifier key) live in `GF(2^128)`, `Δ` is
//! the verifier's secret, and `embed` is the subfield injection
//! [`ExtensionField<Gf2_64>`](mpz_fields::ExtensionField) of `GF(2^64)` into
//! `GF(2^128)`. The prover wire is [`Auth64`] (value + MAC); the verifier wire
//! is the key alone.
//!
//! The protocol matches the boolean path otherwise: a mask-only commit pass
//! ([`Commit`]) records the per-wire adjustment `adjust = value − choice ∈
//! GF(2^64)`, and the accumulate passes fold each multiplication into the
//! QuickSilver triple check under a streamed challenge. The two specializations
//! relative to the boolean path are (1) the value is tracked in [`Auth64`]
//! rather than the MAC LSB, and (2) the verifier reconstructs keys with
//! `key += embed(adjust)·Δ` (a subfield scaling) instead of a conditional `Δ`
//! add.

use blake3::Hasher;
use mpz_circuits::Context;
use mpz_fields::{
    Accumulator, ExtensionField,
    gf2_64::Gf2_64,
    gf2_128::{Gf2_128, Gf2_128Accumulator},
};
use rand_core::RngCore;
use typenum::{Max, Maximum, U0, U1, Unsigned};
use zerocopy::IntoBytes;

use crate::{
    Error, ProverOutput, Result, VerifierOutput,
    poly::{
        Degree, Expr, PlainCoeffs, PolyContext, ProverCoeffs, ProverPoly, VerifierCoeffs,
        VerifierPoly,
    },
    util::draw_chi,
};

/// `mac · embed(v)` — scale a MAC by a subfield value (`embed` is the subfield
/// injection `GF(2^64) ↪ GF(2^128)`).
#[inline]
fn scale(mac: Gf2_128, v: Gf2_64) -> Gf2_128 {
    <Gf2_128 as ExtensionField<Gf2_64>>::scale_by_subfield(mac, v)
}

/// A prover-side authenticated `GF(2^64)` wire: the cleartext `value` and its
/// MAC `M = K + embed(value)·Δ`.
#[derive(Debug, Clone, Copy)]
pub struct Auth64 {
    /// The cleartext value.
    pub value: Gf2_64,
    /// The MAC over [`value`](Self::value).
    pub mac: Gf2_128,
}

// ===========================================================================
// Commit pass
// ===========================================================================

/// The prover's commit-pass context over `GF(2^64)`.
///
/// Pure cleartext evaluation over the values. Each input and multiplication
/// records its adjustment `value − choice` into the mask tape in place (the
/// tape starts holding the sVOLE `choice` values); the resulting adjustments
/// are sent to the verifier. Circuits must be re-walked with the same inputs in
/// the accumulate pass.
#[derive(Debug)]
pub struct Commit<'a> {
    masks: &'a mut [Gf2_64],
    cursor: usize,
}

impl<'a> Commit<'a> {
    /// Creates a commit-pass context over the mask tape.
    pub fn new(masks: &'a mut [Gf2_64]) -> Self {
        Self { masks, cursor: 0 }
    }

    /// Commits a private input `value`, recording its adjustment, and returns
    /// the cleartext wire.
    ///
    /// # Panics
    ///
    /// Panics if the mask tape has been exhausted.
    pub fn input(&mut self, value: Gf2_64) -> Gf2_64 {
        let i = self.cursor;
        let slot = self
            .masks
            .get_mut(i)
            .expect("mask tape exhausted during input");
        *slot = *slot + value;
        self.cursor = i + 1;
        value
    }

    /// Returns the wire for a public input `value` (consumes no tape entry).
    pub fn input_public(&self, value: Gf2_64) -> Gf2_64 {
        value
    }

    /// Completes the commit pass.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] if the number of consumed tape entries does not match
    /// the tape length.
    pub fn finish(self) -> Result<()> {
        if self.cursor != self.masks.len() {
            return Err(Error::tape_unconsumed(self.cursor, self.masks.len()));
        }
        Ok(())
    }
}

impl Context for Commit<'_> {
    type Error = Error;
    type Wire = Gf2_64;
    type Field = Gf2_64;

    fn add(&mut self, a: Gf2_64, b: Gf2_64) -> Gf2_64 {
        a + b
    }

    fn sub(&mut self, a: Gf2_64, b: Gf2_64) -> Gf2_64 {
        a - b
    }

    fn mul(&mut self, a: Gf2_64, b: Gf2_64) -> Gf2_64 {
        let i = self.cursor;
        let slot = self
            .masks
            .get_mut(i)
            .expect("mask tape exhausted: circuit has more multiplications than the tape");
        let z = a * b;
        *slot = *slot + z;
        self.cursor = i + 1;
        z
    }

    fn constant(&mut self, v: Gf2_64) -> Gf2_64 {
        v
    }

    fn assert_const(&mut self, v: Gf2_64, expected: Gf2_64) -> Result<()> {
        // The proof's assertion binding is built in the accumulate pass; here
        // the check only surfaces witness bugs early.
        if v != expected {
            return Err(Error::assert());
        }
        Ok(())
    }
}

impl PolyContext for Commit<'_> {
    /// Plaintext evaluation: an expression is just its cleartext `GF(2^64)`
    /// value, so polynomial gadgets compile down to field operations.
    type Coeffs = PlainCoeffs<Gf2_64>;

    fn lift(&self, wire: Gf2_64) -> Expr<PlainCoeffs<Gf2_64>, U1> {
        Expr::new(wire)
    }

    fn lift_const(&self, value: Gf2_64) -> Expr<PlainCoeffs<Gf2_64>, U0> {
        Expr::new(value)
    }

    fn materialize<N>(&mut self, expr: Expr<PlainCoeffs<Gf2_64>, N>) -> Gf2_64
    where
        N: Degree + Max<U1>,
        Maximum<N, U1>: Degree,
    {
        self.input(expr.plain())
    }

    fn assert_zero<N: Degree>(&mut self, expr: Expr<PlainCoeffs<Gf2_64>, N>) -> Result<()> {
        if expr.plain() != Gf2_64::ZERO {
            return Err(Error::assert());
        }
        Ok(())
    }
}

// ===========================================================================
// Prover
// ===========================================================================

/// The prover side of the `GF(2^64)` protocol.
///
/// Mirrors [`Prover`](crate::Prover): a mask-only [`Commit`] pass, then an
/// accumulate pass from [`Prover::committed`] that folds every multiplication
/// into the running proof under the installed challenge stream.
/// [`finish`](Prover::finish) yields a [`ProverOutput`], which the caller
/// masks with the VOPE correlation.
#[derive(Debug)]
pub struct Prover<'a, S> {
    macs: &'a [Gf2_128],
    cursor: usize,
    state: S,
}

/// Committed state for the [`Prover`].
#[derive(Debug)]
pub struct Committed;

/// Accumulate-phase state for the [`Prover`].
#[derive(Debug)]
pub struct Accumulate<R> {
    assertions: Hasher,
    rng: R,
    u: Gf2_128Accumulator,
    v: Gf2_128Accumulator,
    poly: ProverPoly,
}

impl<'a> Prover<'a, Committed> {
    /// Creates a prover directly in the committed state over the MAC tape.
    pub fn committed(macs: &'a [Gf2_128]) -> Self {
        Self {
            macs,
            cursor: 0,
            state: Committed,
        }
    }

    /// Begins the accumulate pass, drawing challenge weights from `rng`.
    ///
    /// Each multiplication consumes 16 bytes of the stream, so `rng` must be
    /// positioned to match the gates evaluated.
    pub fn accumulate<R: RngCore>(self, rng: R) -> Prover<'a, Accumulate<R>> {
        Prover {
            macs: self.macs,
            cursor: self.cursor,
            state: Accumulate {
                assertions: Hasher::default(),
                rng,
                u: Gf2_128Accumulator::zero(),
                v: Gf2_128Accumulator::zero(),
                poly: ProverPoly::default(),
            },
        }
    }
}

impl<'a, R> Prover<'a, Accumulate<R>> {
    /// Consumes the next tape entry for a private input `value`, returning its
    /// authenticated wire (the raw sVOLE MAC; the verifier adjusts its key).
    ///
    /// # Panics
    ///
    /// Panics if the MAC tape has been exhausted.
    pub fn input(&mut self, value: Gf2_64) -> Auth64 {
        let i = self.cursor;
        let mac = *self.macs.get(i).expect("mac tape exhausted during input");
        self.cursor = i + 1;
        Auth64 { value, mac }
    }

    /// Returns the authenticated wire for a public input `value` (MAC `0`).
    pub fn input_public(&self, value: Gf2_64) -> Auth64 {
        Auth64 {
            value,
            mac: Gf2_128::ZERO,
        }
    }

    /// Completes the accumulate phase, yielding a [`ProverOutput`].
    ///
    /// `poly` carries the polynomial-check coefficients (empty unless
    /// [`PolyContext`] constraints were recorded); the caller masks them with
    /// the degree-`d_max` VOPE before sending.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] if the consumed tape length does not match the tape.
    pub fn finish(self) -> Result<ProverOutput> {
        if self.cursor != self.macs.len() {
            return Err(Error::tape_unconsumed(self.cursor, self.macs.len()));
        }
        Ok(ProverOutput {
            u: self.state.u.reduce(),
            v: self.state.v.reduce(),
            poly: self.state.poly,
            assertions: *self.state.assertions.finalize().as_bytes(),
        })
    }
}

impl<R: RngCore> Context for Prover<'_, Accumulate<R>> {
    type Error = Error;
    type Wire = Auth64;
    type Field = Gf2_64;

    fn add(&mut self, a: Auth64, b: Auth64) -> Auth64 {
        Auth64 {
            value: a.value + b.value,
            mac: a.mac + b.mac,
        }
    }

    fn sub(&mut self, a: Auth64, b: Auth64) -> Auth64 {
        self.add(a, b)
    }

    fn mul(&mut self, a: Auth64, b: Auth64) -> Auth64 {
        let i = self.cursor;
        let mac = *self
            .macs
            .get(i)
            .expect("mac tape exhausted: circuit has more multiplications than the tape");
        self.cursor = i + 1;

        let value = a.value * b.value;
        let chi = draw_chi(&mut self.state.rng);

        // QuickSilver triple check: u accumulates `M_x·M_y`, v accumulates
        // `embed(x)·M_y + embed(y)·M_x + M_z` (the subfield-scaled body).
        let body_v = scale(b.mac, a.value) + scale(a.mac, b.value) + mac;
        self.state.u.add_product(a.mac * b.mac, chi);
        self.state.v.add_product(body_v, chi);

        Auth64 { value, mac }
    }

    fn constant(&mut self, v: Gf2_64) -> Auth64 {
        self.input_public(v)
    }

    fn assert_const(&mut self, v: Auth64, expected: Gf2_64) -> Result<()> {
        if v.value != expected {
            return Err(Error::assert());
        }
        self.state.assertions.update(v.mac.as_bytes());
        Ok(())
    }
}

impl<R: RngCore> PolyContext for Prover<'_, Accumulate<R>> {
    type Coeffs = ProverCoeffs<Gf2_64>;

    fn lift(&self, wire: Auth64) -> Expr<ProverCoeffs<Gf2_64>, U1> {
        Expr::<ProverCoeffs<Gf2_64>, U1>::lift_wire(wire.mac, wire.value)
    }

    fn lift_const(&self, value: Gf2_64) -> Expr<ProverCoeffs<Gf2_64>, U0> {
        Expr::<ProverCoeffs<Gf2_64>, U0>::constant(value)
    }

    fn materialize<N>(&mut self, expr: Expr<ProverCoeffs<Gf2_64>, N>) -> Auth64
    where
        N: Degree + Max<U1>,
        Maximum<N, U1>: Degree,
    {
        let wire = self.input(expr.value());
        // Pin the fresh wire to the expression: `expr - wire == 0`.
        let constraint = expr - self.lift(wire);
        let chi = draw_chi(&mut self.state.rng);
        self.state.poly.fold_expr(&constraint, chi);
        wire
    }

    fn assert_zero<N: Degree>(&mut self, expr: Expr<ProverCoeffs<Gf2_64>, N>) -> Result<()> {
        let Self { state, .. } = self;
        state.poly.assert_expr(&expr, || draw_chi(&mut state.rng))
    }
}

// ===========================================================================
// Verifier
// ===========================================================================

/// The verifier side of the `GF(2^64)` protocol.
///
/// Mirrors [`Verifier`](crate::Verifier): constructed from the commitment
/// (per-wire adjustments) and the key tape, it installs the challenge stream
/// and folds every multiplication into the check state. [`finish`](Self::finish)
/// yields a [`VerifierOutput`]; the caller accepts iff `w == u + Δ·v` (after
/// VOPE masking) and the assertion hashes match.
#[derive(Debug)]
pub struct Verifier<'a, S> {
    keys: &'a [Gf2_128],
    adjust: &'a [Gf2_64],
    delta: Gf2_128,
    cursor: usize,
    state: S,
}

/// Committed state for the [`Verifier`].
#[derive(Debug)]
pub struct VerifierCommitted;

/// Accumulate-phase state for the [`Verifier`].
#[derive(Debug)]
pub struct VerifierAccumulate<R> {
    assertions: Hasher,
    rng: R,
    xy: Gf2_128Accumulator,
    z: Gf2_128Accumulator,
    poly: VerifierPoly,
}

impl<'a> Verifier<'a, VerifierCommitted> {
    /// Creates a verifier with the global MAC key `delta`, the key tape, and
    /// the adjustment tape received as the commitment.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] if `keys` and `adjust` differ in length.
    pub fn new(delta: Gf2_128, keys: &'a [Gf2_128], adjust: &'a [Gf2_64]) -> Result<Self> {
        if keys.len() != adjust.len() {
            return Err(Error::tape_len("adjust", keys.len(), adjust.len()));
        }
        Ok(Self {
            keys,
            adjust,
            delta,
            cursor: 0,
            state: VerifierCommitted,
        })
    }

    /// Begins the accumulate pass, drawing challenge weights from `rng`.
    pub fn accumulate<R: RngCore>(self, rng: R) -> Verifier<'a, VerifierAccumulate<R>> {
        Verifier {
            keys: self.keys,
            adjust: self.adjust,
            delta: self.delta,
            cursor: self.cursor,
            state: VerifierAccumulate {
                assertions: Hasher::default(),
                rng,
                xy: Gf2_128Accumulator::zero(),
                z: Gf2_128Accumulator::zero(),
                poly: VerifierPoly::default(),
            },
        }
    }
}

impl<'a, R> Verifier<'a, VerifierAccumulate<R>> {
    /// Consumes the next input from the tapes and returns its verifier key,
    /// adjusted by `embed(adjust)·Δ`.
    ///
    /// # Panics
    ///
    /// Panics if a tape has been exhausted.
    pub fn input(&mut self) -> Gf2_128 {
        let i = self.cursor;
        let raw = *self.keys.get(i).expect("key tape exhausted during input");
        let adj = *self
            .adjust
            .get(i)
            .expect("adjust tape exhausted during input");
        self.cursor = i + 1;
        raw + scale(self.delta, adj)
    }

    /// Returns the verifier key for a public input `value`: `embed(value)·Δ`.
    pub fn input_public(&self, value: Gf2_64) -> Gf2_128 {
        scale(self.delta, value)
    }

    /// Completes the accumulate phase, yielding a [`VerifierOutput`].
    ///
    /// `poly` carries the polynomial-check state ([`VerifierPoly::check`]);
    /// empty unless [`PolyContext`] constraints were recorded.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] if the consumed tape length does not match the tape.
    pub fn finish(self) -> Result<VerifierOutput> {
        if self.cursor != self.adjust.len() {
            return Err(Error::tape_unconsumed(self.cursor, self.adjust.len()));
        }
        let w = self.state.xy.reduce() + self.delta * self.state.z.reduce();
        Ok(VerifierOutput {
            w,
            poly: self.state.poly,
            assertions: *self.state.assertions.finalize().as_bytes(),
        })
    }
}

impl<R: RngCore> Context for Verifier<'_, VerifierAccumulate<R>> {
    type Error = Error;
    type Wire = Gf2_128;
    type Field = Gf2_64;

    fn add(&mut self, a: Gf2_128, b: Gf2_128) -> Gf2_128 {
        a + b
    }

    fn sub(&mut self, a: Gf2_128, b: Gf2_128) -> Gf2_128 {
        a - b
    }

    fn mul(&mut self, a: Gf2_128, b: Gf2_128) -> Gf2_128 {
        let i = self.cursor;
        let raw = *self
            .keys
            .get(i)
            .expect("key tape exhausted: circuit has more multiplications than the tape");
        let adj = *self
            .adjust
            .get(i)
            .expect("adjust tape exhausted: circuit has more multiplications than the tape");
        self.cursor = i + 1;

        let key = raw + scale(self.delta, adj);
        let chi = draw_chi(&mut self.state.rng);

        self.state.xy.add_product(a * b, chi);
        self.state.z.add_product(key, chi);

        key
    }

    fn constant(&mut self, v: Gf2_64) -> Gf2_128 {
        self.input_public(v)
    }

    fn assert_const(&mut self, v: Gf2_128, expected: Gf2_64) -> Result<()> {
        // If the committed value is `expected`, the prover's MAC equals
        // `v + embed(expected)·Δ`; hash that to match the prover.
        let mac = v + scale(self.delta, expected);
        self.state.assertions.update(mac.as_bytes());
        Ok(())
    }
}

impl<R: RngCore> PolyContext for Verifier<'_, VerifierAccumulate<R>> {
    type Coeffs = VerifierCoeffs;

    fn lift(&self, wire: Gf2_128) -> Expr<VerifierCoeffs, U1> {
        Expr::<VerifierCoeffs, U1>::lift_key(wire, self.delta)
    }

    fn lift_const(&self, value: Gf2_64) -> Expr<VerifierCoeffs, U0> {
        Expr::<VerifierCoeffs, U0>::constant(value, self.delta)
    }

    fn materialize<N>(&mut self, expr: Expr<VerifierCoeffs, N>) -> Gf2_128
    where
        N: Degree + Max<U1>,
        Maximum<N, U1>: Degree,
    {
        let wire = self.input();
        // Pin the fresh wire to the expression: `expr - wire == 0`.
        let constraint = expr - self.lift(wire);
        let chi = draw_chi(&mut self.state.rng);
        self.state
            .poly
            .fold_expr(&constraint, Maximum::<N, U1>::USIZE, chi);
        wire
    }

    fn assert_zero<N: Degree>(&mut self, expr: Expr<VerifierCoeffs, N>) -> Result<()> {
        let Self { state, .. } = self;
        state.poly.assert_expr(&expr, || draw_chi(&mut state.rng))
    }
}
