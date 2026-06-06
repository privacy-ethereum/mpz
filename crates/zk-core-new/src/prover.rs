
use blake3::Hasher;
use itybity::{GetBit, Lsb0};
use mpz_circuits_new::Context;
use mpz_fields::{
    Accumulator,
    gf2::Gf2,
    gf2_64::{Gf2_64, Gf2_64Accumulator},
};
use rand_core::RngCore;
use zerocopy::IntoBytes;

use crate::{Error, MAC_ONE, MAC_ZERO, Result, util::set_lsb};

/// The prover side of the zero-knowledge protocol.
///
/// A `Prover` walks the circuits twice, with each pass tracked as a typestate.
/// The [`Commit`] and [`Accumulate`] phases implement [`Context`] directly, so
/// the prover itself is passed to circuit evaluation:
///
/// 1. [`Prover<Commit>`](Commit) commits the witness, adjusting the mask tape
///    in place as circuits are evaluated. [`finish`](Self::finish) releases
///    the mask borrow so the commitment can be sent to the verifier.
/// 2. [`Prover<Committed>`](Committed) awaits the challenge.
///    [`accumulate`](Self::accumulate) installs the challenge stream provided
///    by the caller.
/// 3. [`Prover<Accumulate>`](Accumulate) re-evaluates the same circuits in the
///    same order, folding every multiplication and assertion directly into
///    the running proof state. [`finish`](Self::finish) yields
///    `(u, v, assertions)`.
///
/// The caller masks `(u, v)` with the VOPE correlation
/// ([`vope_receiver`](crate::vope_receiver)) before sending the proof.
#[derive(Debug)]
pub struct Prover<'a, S> {
    macs: &'a [Gf2_64],
    cursor: usize,
    state: S,
}

/// Commit-phase state for the [`Prover`].
///
/// Holds the mask tape adjusted in place during evaluation.
#[derive(Debug)]
pub struct Commit<'b> {
    masks: &'b mut [bool],
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
    u: Gf2_64Accumulator,
    v: Gf2_64Accumulator,
}

impl<'a, 'b> Prover<'a, Commit<'b>> {
    /// Creates a new prover in the commit phase.
    ///
    /// The `masks` tape is adjusted in place as circuits are evaluated, and
    /// `macs` supplies the corresponding authentication tags. Both tapes are
    /// indexed in lockstep: entry `i` is consumed by the `i`-th input or AND
    /// gate.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] if `masks` and `macs` differ in length.
    pub fn new(masks: &'b mut [bool], macs: &'a [Gf2_64]) -> Result<Self> {
        if masks.len() != macs.len() {
            return Err(Error::tape_len("macs", masks.len(), macs.len()));
        }
        Ok(Self {
            macs,
            cursor: 0,
            state: Commit { masks },
        })
    }

    /// Consumes the next tape entry to commit a private input `bit` and
    /// returns its authenticated wire.
    ///
    /// The corresponding entry of the mask tape is adjusted in place to encode
    /// `bit`.
    ///
    /// # Panics
    ///
    /// Panics if the mask or MAC tape has been exhausted.
    pub fn input(&mut self, bit: bool) -> Gf2_64 {
        let i = self.cursor;
        let slot = self
            .state
            .masks
            .get_mut(i)
            .expect("mask tape exhausted during input");
        let mut mac = *self
            .macs
            .get(i)
            .expect("mac tape exhausted during input");
        *slot ^= bit;
        set_lsb(&mut mac, bit);
        self.cursor = i + 1;
        mac
    }

    /// Returns the authenticated wire for a public input `bit`.
    ///
    /// Public inputs consume no tape entry, since their value is known to both
    /// parties; the wire is a fixed constant determined by `bit`.
    pub fn input_public(&self, bit: bool) -> Gf2_64 {
        if bit { MAC_ONE } else { MAC_ZERO }
    }

    /// Completes the commit phase.
    ///
    /// Releases the mask borrow so the adjusted masks can be sent to the
    /// verifier as the commitment.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] if the number of consumed tape entries does not match
    /// the tape length, indicating the circuits drew fewer inputs and AND
    /// gates than the tape provides.
    pub fn finish(self) -> Result<Prover<'a, Committed>> {
        if self.cursor != self.macs.len() {
            return Err(Error::tape_unconsumed(self.cursor, self.macs.len()));
        }
        Ok(Prover {
            macs: self.macs,
            cursor: 0,
            state: Committed,
        })
    }
}

impl<'a> Prover<'a, Committed> {
    /// Creates a prover directly in the committed state.
    ///
    /// Used to fold a sub-range of a trace whose commitment was produced
    /// elsewhere: `macs` covers the sub-range's tape entries, and the
    /// challenge stream passed to [`accumulate`](Self::accumulate) is
    /// positioned to the sub-range's gate offset.
    pub fn committed(macs: &'a [Gf2_64]) -> Self {
        Self {
            macs,
            cursor: 0,
            state: Committed,
        }
    }

    /// Begins the accumulate pass, drawing challenge weights from `rng`.
    ///
    /// Each multiplication consumes 8 bytes of the stream, so `rng` must be
    /// positioned to match the gates evaluated: the caller derives it from the
    /// agreed challenge and seeks it when folding a sub-range of the trace.
    pub fn accumulate<R: RngCore>(self, rng: R) -> Prover<'a, Accumulate<R>> {
        Prover {
            macs: self.macs,
            cursor: self.cursor,
            state: Accumulate {
                assertions: Hasher::default(),
                rng,
                u: Gf2_64Accumulator::default(),
                v: Gf2_64Accumulator::default(),
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
    pub fn input(&mut self, bit: bool) -> Gf2_64 {
        let i = self.cursor;
        let mut mac = *self
            .macs
            .get(i)
            .expect("mac tape exhausted during input");
        set_lsb(&mut mac, bit);
        self.cursor = i + 1;
        mac
    }

    /// Returns the authenticated wire for a public input `bit`.
    ///
    /// Public inputs consume no tape entry, since their value is known to both
    /// parties; the wire is a fixed constant determined by `bit`.
    pub fn input_public(&self, bit: bool) -> Gf2_64 {
        if bit { MAC_ONE } else { MAC_ZERO }
    }

    /// Completes the accumulate phase, yielding `(u, v, assertions)`.
    ///
    /// The caller masks `(u, v)` with the VOPE correlation
    /// ([`vope_receiver`](crate::vope_receiver)) before sending the proof.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] if the number of consumed tape entries does not match
    /// the tape length, indicating the circuits drew fewer inputs and AND
    /// gates than the tape provides.
    pub fn finish(self) -> Result<(Gf2_64, Gf2_64, [u8; 32])> {
        if self.cursor != self.macs.len() {
            return Err(Error::tape_unconsumed(self.cursor, self.macs.len()));
        }
        Ok((
            self.state.u.finish(),
            self.state.v.finish(),
            *self.state.assertions.finalize().as_bytes(),
        ))
    }
}

impl Context for Prover<'_, Commit<'_>> {
    type Error = Error;
    type Wire = Gf2_64;
    type Field = Gf2;

    fn add(&mut self, a: Gf2_64, b: Gf2_64) -> Gf2_64 {
        a + b
    }

    fn sub(&mut self, a: Gf2_64, b: Gf2_64) -> Gf2_64 {
        a - b
    }

    fn mul(&mut self, a: Gf2_64, b: Gf2_64) -> Gf2_64 {
        let z = GetBit::<Lsb0>::get_bit(&a, 0) & GetBit::<Lsb0>::get_bit(&b, 0);
        let i = self.cursor;
        let slot = self
            .state
            .masks
            .get_mut(i)
            .expect("mask tape exhausted: circuit has more AND gates than the tape");
        let mut mac = *self
            .macs
            .get(i)
            .expect("mac tape exhausted: circuit has more AND gates than the tape");
        *slot ^= z;
        set_lsb(&mut mac, z);
        self.cursor = i + 1;
        mac
    }

    fn constant(&mut self, v: Gf2) -> Gf2_64 {
        if v.0 { MAC_ONE } else { MAC_ZERO }
    }

    fn assert_const(&mut self, _v: Gf2_64, _expected: Gf2) -> Result<()> {
        // Assertions are checked and hashed during the accumulate pass.
        Ok(())
    }
}

impl<R: RngCore> Context for Prover<'_, Accumulate<R>> {
    type Error = Error;
    type Wire = Gf2_64;
    type Field = Gf2;

    fn add(&mut self, a: Gf2_64, b: Gf2_64) -> Gf2_64 {
        a + b
    }

    fn sub(&mut self, a: Gf2_64, b: Gf2_64) -> Gf2_64 {
        a - b
    }

    fn mul(&mut self, a: Gf2_64, b: Gf2_64) -> Gf2_64 {
        let x = GetBit::<Lsb0>::get_bit(&a, 0);
        let y = GetBit::<Lsb0>::get_bit(&b, 0);
        let i = self.cursor;
        let mut mac = *self
            .macs
            .get(i)
            .expect("mac tape exhausted: circuit has more AND gates than the tape");
        set_lsb(&mut mac, x & y);
        self.cursor = i + 1;

        let mut chi = Gf2_64::new(0);
        self.state.rng.fill_bytes(chi.as_mut_bytes());

        // `a_10 = b if lsb(a) else 0`, `a_11 = a if lsb(b) else 0`,
        // expressed as `a · mask` with `mask ∈ {0, u64::MAX}` so there
        // is no data-dependent branch.
        let mask_x = (x as u64).wrapping_neg();
        let mask_y = (y as u64).wrapping_neg();
        let body_v =
            Gf2_64::new(b.to_inner() & mask_x) + Gf2_64::new(a.to_inner() & mask_y) + mac;

        self.state.u.fma(a * b, chi);
        self.state.v.fma(body_v, chi);

        mac
    }

    fn constant(&mut self, v: Gf2) -> Gf2_64 {
        if v.0 { MAC_ONE } else { MAC_ZERO }
    }

    fn assert_const(&mut self, v: Gf2_64, expected: Gf2) -> Result<()> {
        let got = GetBit::<Lsb0>::get_bit(&v, 0);
        if got != expected.0 {
            return Err(Error::assert());
        }

        self.state.assertions.update(&v.to_inner().to_le_bytes());

        Ok(())
    }
}
