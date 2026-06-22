use blake3::Hasher;
use itybity::{GetBit, Lsb0};
use mpz_circuits::Context;
use mpz_fields::{
    Accumulator,
    gf2::Gf2,
    gf2_128::{Gf2_128, Gf2_128Accumulator},
};
use rand_core::RngCore;

use typenum::{Max, Maximum, U0, U1};

use crate::{
    Error, MAC_ONE, MAC_ZERO, ProverOutput, Result,
    poly::{Degree, Expr, PlainCoeffs, PolyContext, ProverCoeffs, ProverPoly},
    util::{draw_chi, lsb, set_lsb},
};

/// The prover side of the zero-knowledge protocol.
///
/// The prover walks the circuits twice. The first pass is the mask-only
/// [`Commit`] context, which never touches the MAC tape. The second pass is
/// `Prover<Accumulate>`: starting from [`Prover::committed`], the caller
/// installs the challenge stream via [`accumulate`](Self::accumulate) and
/// re-evaluates the same circuits in the same order, folding every
/// multiplication and assertion directly into the running proof state.
/// [`finish`](Self::finish) yields a [`ProverOutput`].
///
/// The caller masks `(u, v)` with the VOPE correlation
/// ([`vope_receiver`](crate::vope_receiver)) before sending the proof.
#[derive(Debug)]
pub struct Prover<'a, S> {
    macs: &'a [Gf2_128],
    cursor: usize,
    state: S,
}

/// The prover's commit-pass circuit context.
///
/// Distinct from [`Commitment`](crate::Commitment): this is the evaluation
/// *context*, whereas `Commitment` is the adjustment-bit *message* this pass
/// produces and sends to the verifier.
///
/// Walks the circuits over *pointer-bit wires*: each wire is a [`Gf2_128`]
/// whose LSB carries the plaintext bit and whose remaining bits are
/// meaningless. The commit pass only ever reads wire LSBs, so it needs no MAC
/// tape — each input and AND gate XORs its witness bit into the mask tape in
/// place, producing the adjustment bits sent to the verifier (see
/// [`Commitment`](crate::Commitment)).
///
/// This makes the commit pass pure plaintext evaluation: circuits walked with
/// a `Commit` context must be re-walked with the same inputs in the
/// accumulate pass, which reconstructs the same LSBs on the real MAC wires.
#[derive(Debug)]
pub struct Commit<'a> {
    masks: &'a mut [bool],
    cursor: usize,
}

impl<'a> Commit<'a> {
    /// Creates a commit-pass context over the mask tape.
    ///
    /// The `masks` tape is adjusted in place as circuits are evaluated: entry
    /// `i` is XORed with the bit committed by the `i`-th input or AND gate.
    pub fn new(masks: &'a mut [bool]) -> Self {
        Self { masks, cursor: 0 }
    }

    /// Consumes the next tape entry to commit a private input `bit` and
    /// returns its pointer-bit wire.
    ///
    /// # Panics
    ///
    /// Panics if the mask tape has been exhausted.
    pub fn input(&mut self, bit: bool) -> Gf2_128 {
        let i = self.cursor;
        let slot = self
            .masks
            .get_mut(i)
            .expect("mask tape exhausted during input");
        *slot ^= bit;
        self.cursor = i + 1;
        Gf2_128::new(bit as u128)
    }

    /// Returns the wire for a public input `bit`.
    ///
    /// Public inputs consume no tape entry, since their value is known to both
    /// parties.
    pub fn input_public(&self, bit: bool) -> Gf2_128 {
        if bit { MAC_ONE } else { MAC_ZERO }
    }

    /// Completes the commit pass.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] if the number of consumed tape entries does not match
    /// the tape length, indicating the circuits drew fewer inputs and AND
    /// gates than the tape provides.
    pub fn finish(self) -> Result<()> {
        if self.cursor != self.masks.len() {
            return Err(Error::tape_unconsumed(self.cursor, self.masks.len()));
        }
        Ok(())
    }
}

impl PolyContext for Commit<'_> {
    /// Plaintext evaluation: an expression is just its cleartext bit, so the
    /// commit pass compiles polynomial gadgets down to bit operations.
    type Coeffs = PlainCoeffs<Gf2>;

    fn lift(&self, wire: Gf2_128) -> Expr<PlainCoeffs<Gf2>, U1> {
        Expr::new(lsb(wire))
    }

    fn lift_const(&self, value: Gf2) -> Expr<PlainCoeffs<Gf2>, U0> {
        Expr::new(value)
    }

    fn materialize<N>(&mut self, expr: Expr<PlainCoeffs<Gf2>, N>) -> Gf2_128
    where
        N: Degree + Max<U1>,
        Maximum<N, U1>: Degree,
    {
        self.input(expr.plain().0)
    }

    fn assert_zero<N: Degree>(&mut self, expr: Expr<PlainCoeffs<Gf2>, N>) -> Result<()> {
        // The check binding constraints into the proof is built during the
        // accumulate pass; here the check only surfaces witness bugs early.
        if expr.plain() != Gf2::ZERO {
            return Err(Error::assert());
        }
        Ok(())
    }
}

impl Context for Commit<'_> {
    type Error = Error;
    type Wire = Gf2_128;
    type Field = Gf2;

    fn add(&mut self, a: Gf2_128, b: Gf2_128) -> Gf2_128 {
        a + b
    }

    fn sub(&mut self, a: Gf2_128, b: Gf2_128) -> Gf2_128 {
        a - b
    }

    fn mul(&mut self, a: Gf2_128, b: Gf2_128) -> Gf2_128 {
        let z = GetBit::<Lsb0>::get_bit(&a, 0) & GetBit::<Lsb0>::get_bit(&b, 0);
        let i = self.cursor;
        let slot = self
            .masks
            .get_mut(i)
            .expect("mask tape exhausted: circuit has more AND gates than the tape");
        *slot ^= z;
        self.cursor = i + 1;
        Gf2_128::new(z as u128)
    }

    fn constant(&mut self, v: Gf2) -> Gf2_128 {
        self.input_public(v.0)
    }

    fn assert_const(&mut self, v: Gf2_128, expected: Gf2) -> Result<()> {
        // The hash binding assertions into the proof is built during the
        // accumulate pass; here the check only surfaces witness bugs early.
        let got = GetBit::<Lsb0>::get_bit(&v, 0);
        if got != expected.0 {
            return Err(Error::assert());
        }
        Ok(())
    }
}

/// Committed state for the [`Prover`].
///
/// The witness is committed; the prover awaits the challenge before beginning
/// the accumulate pass.
#[derive(Debug)]
pub struct Committed;

/// Accumulate-phase state for the [`Prover`].
///
/// Holds the challenge stream and the running proof state folded during the
/// second pass. The `u` and `v` accumulators defer reduction to
/// [`finish`](Prover::finish).
#[derive(Debug)]
pub struct Accumulate<R> {
    assertions: Hasher,
    rng: R,
    u: Gf2_128Accumulator,
    v: Gf2_128Accumulator,
    poly: ProverPoly,
}

impl<'a> Prover<'a, Committed> {
    /// Creates a prover directly in the committed state.
    ///
    /// Used to fold a sub-range of a trace whose commitment was produced
    /// elsewhere: `macs` covers the sub-range's tape entries, and the
    /// challenge stream passed to [`accumulate`](Self::accumulate) is
    /// positioned to the sub-range's gate offset. The `(u, v)` outputs of the
    /// sub-ranges sum to the full trace's `(u, v)`, so sub-ranges can be
    /// folded in parallel and combined by field addition.
    pub fn committed(macs: &'a [Gf2_128]) -> Self {
        Self {
            macs,
            cursor: 0,
            state: Committed,
        }
    }

    /// Begins the accumulate pass, drawing challenge weights from `rng`.
    ///
    /// Each multiplication and each polynomial constraint
    /// ([`PolyContext::assert_zero`] of degree ≥ 1, or
    /// [`PolyContext::materialize`]) consumes 16 bytes of the stream, so `rng`
    /// must be positioned to match the trace evaluated: the caller derives it
    /// from the agreed challenge and seeks it when folding a sub-range of the
    /// trace.
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
    /// Consumes the next tape entry for a private input `bit` and returns its
    /// authenticated wire.
    ///
    /// Inputs must be supplied in the same order as during the commit phase.
    ///
    /// # Panics
    ///
    /// Panics if the MAC tape has been exhausted.
    pub fn input(&mut self, bit: bool) -> Gf2_128 {
        let i = self.cursor;
        let mut mac = *self.macs.get(i).expect("mac tape exhausted during input");
        set_lsb(&mut mac, bit);
        self.cursor = i + 1;
        mac
    }

    /// Returns the authenticated wire for a public input `bit`.
    ///
    /// Public inputs consume no tape entry, since their value is known to both
    /// parties; the wire is a fixed constant determined by `bit`.
    pub fn input_public(&self, bit: bool) -> Gf2_128 {
        if bit { MAC_ONE } else { MAC_ZERO }
    }

    /// Completes the accumulate phase, yielding a [`ProverOutput`].
    ///
    /// The caller masks `(u, v)` with the VOPE correlation
    /// ([`vope_receiver`](crate::vope_receiver)) and the polynomial check
    /// coefficients ([`ProverPoly::coefficients`]) with the degree-`d_max`
    /// VOPE coefficients before sending the proof.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] if the number of consumed tape entries does not match
    /// the tape length, indicating the circuits drew fewer inputs and AND
    /// gates than the tape provides.
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
    type Wire = Gf2_128;
    type Field = Gf2;

    fn add(&mut self, a: Gf2_128, b: Gf2_128) -> Gf2_128 {
        a + b
    }

    fn sub(&mut self, a: Gf2_128, b: Gf2_128) -> Gf2_128 {
        a - b
    }

    fn mul(&mut self, a: Gf2_128, b: Gf2_128) -> Gf2_128 {
        let x = GetBit::<Lsb0>::get_bit(&a, 0);
        let y = GetBit::<Lsb0>::get_bit(&b, 0);
        let i = self.cursor;
        let mut mac = *self
            .macs
            .get(i)
            .expect("mac tape exhausted: circuit has more AND gates than the tape");
        set_lsb(&mut mac, x & y);
        self.cursor = i + 1;

        let chi = draw_chi(&mut self.state.rng);

        // `a_10 = b if lsb(a) else 0`, `a_11 = a if lsb(b) else 0`,
        // expressed as `a · mask` with `mask ∈ {0, u128::MAX}` so there
        // is no data-dependent branch.
        let mask_x = (x as u128).wrapping_neg();
        let mask_y = (y as u128).wrapping_neg();
        let body_v =
            Gf2_128::new(b.to_inner() & mask_x) + Gf2_128::new(a.to_inner() & mask_y) + mac;

        self.state.u.add_product(a * b, chi);
        self.state.v.add_product(body_v, chi);

        mac
    }

    fn constant(&mut self, v: Gf2) -> Gf2_128 {
        self.input_public(v.0)
    }

    fn assert_const(&mut self, v: Gf2_128, expected: Gf2) -> Result<()> {
        let got = GetBit::<Lsb0>::get_bit(&v, 0);
        if got != expected.0 {
            return Err(Error::assert());
        }

        self.state.assertions.update(&v.to_inner().to_le_bytes());

        Ok(())
    }
}

impl<R: RngCore> PolyContext for Prover<'_, Accumulate<R>> {
    type Coeffs = ProverCoeffs<Gf2>;

    fn lift(&self, wire: Gf2_128) -> Expr<ProverCoeffs<Gf2>, U1> {
        // The wire's LSB carries its committed bit, so the top is read off it.
        Expr::<ProverCoeffs<Gf2>, U1>::lift_wire(wire, lsb(wire))
    }

    fn lift_const(&self, value: Gf2) -> Expr<ProverCoeffs<Gf2>, U0> {
        Expr::<ProverCoeffs<Gf2>, U0>::constant(value)
    }

    fn materialize<N>(&mut self, expr: Expr<ProverCoeffs<Gf2>, N>) -> Gf2_128
    where
        N: Degree + Max<U1>,
        Maximum<N, U1>: Degree,
    {
        let wire = self.input(expr.value().0);
        // Pin the fresh wire to the expression: `expr - wire == 0`. The
        // constraint's top coefficient is `expr.value + lsb(wire) = 0` by
        // construction, so it folds without a witness check.
        let constraint = expr - self.lift(wire);
        let chi = draw_chi(&mut self.state.rng);
        self.state.poly.fold_expr(&constraint, chi);
        wire
    }

    fn assert_zero<N: Degree>(&mut self, expr: Expr<ProverCoeffs<Gf2>, N>) -> Result<()> {
        let Self { state, .. } = self;
        state.poly.assert_expr(&expr, || draw_chi(&mut state.rng))
    }
}
