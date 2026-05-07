//! Prover-side accumulator + per-execution handle.
//!
//! [`Prover`] holds the persistent consistency-check state (per-AND-gate
//! triples + the assertions hash). Calling [`Prover::execute`] borrows
//! the caller's gate tape and returns a [`ProverExecute`] which
//! implements [`Context`]; driving a circuit function through that
//! handle records triples and per-gate masked-witness bits directly
//! into the parent `Prover`.
//!
//! The prover exploits the pointer-bit convention — every MAC's LSB
//! carries the authenticated bit — so `mul` computes its witness bit
//! as `a.lsb & b.lsb` with no separate witness tape.

use blake3::Hasher;
use itybity::{GetBit, Lsb0};
use mpz_circuits_new::Context;
use mpz_core::bitvec::{BitSlice, BitVec};
use mpz_fields::{gf2::Gf2, gf2_128::Gf2_128};
use zerocopy::IntoBytes;

use crate::{
    Error, MAC_ONE, MAC_ZERO, MaskedWitness, Proof, Result,
    check::{Triple, check_prover},
    util::set_lsb,
};

/// Persistent prover state. Outlives individual circuit executions;
/// the final [`prove`](Self::prove) consumes the accumulated triples
/// and assertions to produce the prover→verifier message.
#[derive(Debug, Default)]
pub struct Prover {
    triples: Vec<Triple>,
    assertions: Hasher,
}

impl Prover {
    /// Creates an empty prover.
    pub fn new() -> Self {
        Self::default()
    }

    /// Begins one circuit execution. `gate_masks` and `gate_macs` are
    /// the per-AND-gate sVOLE tape slices (caller-owned); the returned
    /// handle implements [`Context`] and writes triples and
    /// masked-witness bits directly into this prover. Returns
    /// `Error::TapeLength` if the two tapes have different lengths.
    pub fn execute<'a>(
        &'a mut self,
        gate_masks: &'a BitSlice,
        gate_macs: &'a [Gf2_128],
    ) -> Result<ProverExecute<'a>> {
        if gate_masks.len() != gate_macs.len() {
            return Err(Error::tape_len(
                "gate_macs",
                gate_masks.len(),
                gate_macs.len(),
            ));
        }
        Ok(ProverExecute {
            triples: &mut self.triples,
            assertions: &mut self.assertions,
            masked_witness: BitVec::with_capacity(gate_masks.len()),
            public_bits: BitVec::new(),
            gate_masks,
            gate_macs,
            counter: 0,
        })
    }

    /// Runs the Fig-5 step-7 batch check on the accumulated state and
    /// returns the proof message. Folds the assertions hash into
    /// `transcript` *before* deriving χ, so χ binds to the public
    /// statement.
    pub fn prove(
        &mut self,
        transcript: &mut Hasher,
        vope_choices: &[bool; 128],
        vope_ev: &[Gf2_128; 128],
    ) -> Proof {
        let (a_0, a_1) = crate::vope::vope_receiver(vope_choices, vope_ev);

        let assertions = *self.assertions.finalize().as_bytes();
        transcript.update(&assertions);

        let chi: [u8; 32] = *transcript.finalize().as_bytes();
        let (u, v) = check_prover(&self.triples, chi, a_0, a_1);

        transcript.update(u.as_bytes());
        transcript.update(v.as_bytes());

        self.assertions.reset();
        self.triples.clear();

        Proof { assertions, u, v }
    }
}

/// Per-execution prover handle. Implements [`Context`].
#[derive(Debug)]
pub struct ProverExecute<'a> {
    triples: &'a mut Vec<Triple>,
    assertions: &'a mut Hasher,
    masked_witness: BitVec,
    /// Public bits accumulated from `assert` calls (one bit per
    /// assertion encoding the `expected` value). Flushed into the
    /// main transcript by `finish`.
    public_bits: BitVec,
    gate_masks: &'a BitSlice,
    gate_macs: &'a [Gf2_128],
    counter: usize,
}

impl ProverExecute<'_> {
    /// Finishes the execution: asserts that the circuit consumed the
    /// full gate tape, updates `transcript` with the masked-witness
    /// bytes followed by the per-`assert` public bits (packed), and
    /// returns the [`MaskedWitness`] to send to the verifier.
    #[must_use = "the masked witness must be sent to the verifier"]
    pub fn finish(self, transcript: &mut Hasher) -> Result<MaskedWitness> {
        if self.counter != self.gate_macs.len() {
            return Err(Error::tape_unconsumed(self.counter, self.gate_macs.len()));
        }
        let bits = self.masked_witness;
        transcript.update(&bits.as_raw_slice().as_bytes()[..bits.len().div_ceil(8)]);
        transcript.update(
            &self.public_bits.as_raw_slice().as_bytes()[..self.public_bits.len().div_ceil(8)],
        );
        Ok(MaskedWitness { bits })
    }
}

impl Context for ProverExecute<'_> {
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
        let i = self.counter;
        let mask = self
            .gate_masks
            .get(i)
            .as_deref()
            .copied()
            .expect("gate_masks tape exhausted: circuit has more AND gates than the tape");
        let mut mac = *self
            .gate_macs
            .get(i)
            .expect("gate_macs tape exhausted: circuit has more AND gates than the tape");
        self.masked_witness.push(z ^ mask);
        set_lsb(&mut mac, z);
        self.triples.push(Triple { x: a, y: b, z: mac });
        self.counter = i + 1;
        mac
    }

    fn constant(&mut self, v: Gf2) -> Gf2_128 {
        if v.0 { MAC_ONE } else { MAC_ZERO }
    }

    fn assert_const(&mut self, v: Gf2_128, expected: Gf2) -> Result<()> {
        let got = GetBit::<Lsb0>::get_bit(&v, 0);
        if got != expected.0 {
            return Err(Error::assert());
        }

        self.assertions.update(&v.to_inner().to_le_bytes());
        self.public_bits.push(expected.0);

        Ok(())
    }
}
