use blake3::Hasher;
use mpz_circuits::Context;
use mpz_fields::{
    Accumulator,
    gf2::Gf2,
    gf2_128::{Gf2_128, Gf2_128Accumulator},
};
use rand_core::RngCore;
use zerocopy::IntoBytes;

use crate::{Error, MAC_ONE, MAC_ZERO, Result, util::set_lsb};

/// The verifier side of the zero-knowledge protocol.
///
/// A `Verifier` holds the global MAC key `delta` and walks the circuits once,
/// with the flow tracked as a typestate:
///
/// 1. [`Verifier<Committed>`](Committed) is constructed from the received
///    commitment (the adjustment bits) and the key tape.
///    [`accumulate`](Self::accumulate) installs the challenge stream provided
///    by the caller.
/// 2. [`Verifier<Accumulate>`](Accumulate) implements [`Context`] directly,
///    folding every multiplication and assertion into the running check state
///    as the circuits are evaluated. [`finish`](Self::finish) yields
///    `(w, assertions)`.
///
/// The caller masks `w` with the VOPE correlation
/// ([`vope_sender`](crate::vope_sender)) and accepts the prover's proof iff
/// `w == u + delta * v` and the assertion hashes match.
#[derive(Debug)]
pub struct Verifier<'a, S> {
    keys: &'a [Gf2_128],
    adjust: &'a [bool],
    delta: Gf2_128,
    key_one: Gf2_128,
    cursor: usize,
    state: S,
}

/// Committed state for the [`Verifier`].
///
/// The prover's commitment has been received; the verifier awaits the
/// challenge stream before beginning the accumulate pass.
#[derive(Debug)]
pub struct Committed;

/// Accumulate-phase state for the [`Verifier`].
///
/// Holds the challenge stream and the running check state folded during
/// evaluation, split into the `Σ χᵢ·xᵢyᵢ` and `Σ χᵢ·zᵢ` accumulators so
/// reduction and the `delta` factor are both applied once at
/// [`finish`](Verifier::finish).
#[derive(Debug)]
pub struct Accumulate<R> {
    assertions: Hasher,
    rng: R,
    xy: Gf2_128Accumulator,
    z: Gf2_128Accumulator,
}

impl<'a> Verifier<'a, Committed> {
    /// Creates a new verifier with the global MAC key `delta`.
    ///
    /// `keys` is the tape of verifier keys, one entry per input bit and per
    /// AND gate, consumed in evaluation order. `adjust` is the corresponding
    /// tape of adjustment bits received from the prover as the commitment;
    /// each entry selects whether the matching key is offset by `delta`.
    ///
    /// When folding a sub-range of a trace, pass the sub-range's tape slices
    /// and seek the challenge stream to the sub-range's gate offset: the `w`
    /// outputs of the sub-ranges sum to the full trace's `w`.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] if `keys` and `adjust` differ in length.
    pub fn new(delta: Gf2_128, keys: &'a [Gf2_128], adjust: &'a [bool]) -> Result<Self> {
        if keys.len() != adjust.len() {
            return Err(Error::tape_len("adjust", keys.len(), adjust.len()));
        }
        Ok(Self {
            keys,
            adjust,
            delta,
            key_one: MAC_ONE + delta,
            cursor: 0,
            state: Committed,
        })
    }

    /// Begins the accumulate pass, drawing challenge weights from `rng`.
    ///
    /// Each multiplication consumes 16 bytes of the stream, so `rng` must be
    /// positioned to match the gates evaluated: the caller derives it from the
    /// challenge it sampled and seeks it when folding a sub-range of the
    /// trace.
    pub fn accumulate<R: RngCore>(self, rng: R) -> Verifier<'a, Accumulate<R>> {
        Verifier {
            keys: self.keys,
            adjust: self.adjust,
            delta: self.delta,
            key_one: self.key_one,
            cursor: self.cursor,
            state: Accumulate {
                assertions: Hasher::default(),
                rng,
                xy: Gf2_128Accumulator::zero(),
                z: Gf2_128Accumulator::zero(),
            },
        }
    }
}

impl<'a, R> Verifier<'a, Accumulate<R>> {
    /// Consumes the next input from the tapes and returns its verifier key.
    ///
    /// The key is offset by `delta` when the corresponding adjustment bit is
    /// set.
    ///
    /// # Panics
    ///
    /// Panics if the key or adjustment tape has been exhausted.
    pub fn input(&mut self) -> Gf2_128 {
        let i = self.cursor;
        let raw = *self.keys.get(i).expect("key tape exhausted during input");
        let adj = *self
            .adjust
            .get(i)
            .expect("adjust tape exhausted during input");
        let mut key = if adj { raw + self.delta } else { raw };
        set_lsb(&mut key, false);
        self.cursor = i + 1;
        key
    }

    /// Returns the verifier key for a public input wire carrying `bit`.
    ///
    /// Public inputs consume no tape entries, since their value is known to
    /// both parties.
    pub fn input_public(&self, bit: bool) -> Gf2_128 {
        if bit { self.key_one } else { MAC_ZERO }
    }

    /// Completes the accumulate phase, yielding `(w, assertions)`.
    ///
    /// The caller masks `w` with the VOPE correlation
    /// ([`vope_sender`](crate::vope_sender)) and accepts the prover's proof
    /// iff `w == u + delta * v` and the assertion hashes match.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] if the number of consumed tape entries does not match
    /// the tape length, indicating the circuits drew fewer inputs and AND
    /// gates than the tape provides.
    pub fn finish(self) -> Result<(Gf2_128, [u8; 32])> {
        if self.cursor != self.adjust.len() {
            return Err(Error::tape_unconsumed(self.cursor, self.adjust.len()));
        }
        let w = self.state.xy.reduce() + self.delta * self.state.z.reduce();
        Ok((w, *self.state.assertions.finalize().as_bytes()))
    }
}

impl<R: RngCore> Context for Verifier<'_, Accumulate<R>> {
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
        let i = self.cursor;
        let mut key = *self
            .keys
            .get(i)
            .expect("key tape exhausted: circuit has more AND gates than the tape");
        let adj = *self
            .adjust
            .get(i)
            .expect("adjust tape exhausted: circuit has more AND gates than the tape");

        if adj {
            key = key + self.delta;
        }
        set_lsb(&mut key, false);
        self.cursor = i + 1;

        let mut chi = Gf2_128::new(0);
        self.state.rng.fill_bytes(chi.as_mut_bytes());

        self.state.xy.add_product(a * b, chi);
        self.state.z.add_product(key, chi);

        key
    }

    fn constant(&mut self, v: Gf2) -> Gf2_128 {
        self.input_public(v.0)
    }

    fn assert_const(&mut self, v: Gf2_128, expected: Gf2) -> Result<()> {
        let mac = if expected.0 { v + self.delta } else { v };
        self.state.assertions.update(&mac.to_inner().to_le_bytes());

        Ok(())
    }
}
