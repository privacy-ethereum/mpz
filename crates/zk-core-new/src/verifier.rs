//! Verifier-side accumulator + per-execution handle.
//!
//! [`Verifier`] mirrors [`crate::Prover`]: persistent state holding
//! per-AND-gate triples and the assertions hash. [`Verifier::execute`]
//! returns a [`VerifierExecute`] that implements [`Context`] over
//! pre-adjusted keys (the per-gate adjustment bit comes from the
//! prover's [`MaskedWitness`]).

use blake3::Hasher;
use mpz_circuits_new::Context;
use mpz_core::bitvec::BitVec;
use mpz_fields::{gf2::Gf2, gf2_128::Gf2_128};
use zerocopy::IntoBytes;

use crate::{
    Error, MAC_ONE, MAC_ZERO, MaskedWitness, Proof, Result,
    check::{Triple, check_verifier},
    util::set_lsb,
};

/// Persistent verifier state. Outlives individual executions; the
/// final [`verify`](Self::verify) consumes the accumulated triples
/// and assertions together with the prover's [`Proof`].
#[derive(Debug)]
pub struct Verifier {
    triples: Vec<Triple>,
    assertions: Hasher,
    delta: Gf2_128,
    key_zero: Gf2_128,
    key_one: Gf2_128,
}

impl Verifier {
    /// Creates a new verifier with the global `delta`.
    pub fn new(delta: Gf2_128) -> Self {
        let key_one = MAC_ONE + delta;
        Self {
            triples: Vec::new(),
            assertions: Hasher::default(),
            delta,
            key_zero: MAC_ZERO,
            key_one,
        }
    }

    /// Begins one circuit execution. `gate_keys` is the per-AND-gate
    /// raw-key tape and `masked_witness` is the prover's per-gate
    /// adjustment bits — both must have the same length, equal to
    /// the number of AND gates the circuit will execute.
    pub fn execute<'a>(
        &'a mut self,
        gate_keys: &'a [Gf2_128],
        masked_witness: MaskedWitness,
    ) -> Result<VerifierExecute<'a>> {
        if gate_keys.len() != masked_witness.len() {
            return Err(Error::witness_len(gate_keys.len(), masked_witness.len()));
        }

        Ok(VerifierExecute {
            triples: &mut self.triples,
            assertions: &mut self.assertions,
            gate_keys,
            masked_witness: masked_witness.bits,
            public_bits: BitVec::new(),
            delta: &self.delta,
            key_zero: &self.key_zero,
            key_one: &self.key_one,
            counter: 0,
        })
    }

    /// Consumes the prover's [`Proof`] and runs the Fig-5 step-7
    /// batch check. Folds the locally-recomputed assertions hash
    /// into `transcript` *before* deriving χ — so χ binds to the
    /// public statement and any prover lie about it shows up as a
    /// failed consistency check (in addition to the explicit
    /// assertions-hash equality check).
    pub fn verify(
        &mut self,
        transcript: &mut Hasher,
        vope_keys: &[Gf2_128; 128],
        proof: Proof,
    ) -> Result<()> {
        let Proof { assertions, u, v } = proof;

        let expected_assertions = *self.assertions.finalize().as_bytes();
        if assertions != expected_assertions {
            return Err(Error::assert());
        }
        transcript.update(&expected_assertions);

        let chi: [u8; 32] = *transcript.finalize().as_bytes();

        transcript.update(u.as_bytes());
        transcript.update(v.as_bytes());

        let b = crate::vope::vope_sender(vope_keys);
        check_verifier(&self.triples, self.delta, chi, b, u, v)?;

        self.assertions.reset();
        self.triples.clear();

        Ok(())
    }
}

/// Per-execution verifier handle. Implements [`Context`] over
/// pre-adjusted keys.
#[derive(Debug)]
pub struct VerifierExecute<'a> {
    triples: &'a mut Vec<Triple>,
    assertions: &'a mut Hasher,
    gate_keys: &'a [Gf2_128],
    masked_witness: BitVec,
    /// Public bits accumulated from `assert` calls (one bit per
    /// assertion encoding the `expected` value). Flushed into the
    /// main transcript by `finish`, matching the prover's order.
    public_bits: BitVec,
    delta: &'a Gf2_128,
    key_zero: &'a Gf2_128,
    key_one: &'a Gf2_128,
    counter: usize,
}

impl VerifierExecute<'_> {
    /// Finishes the execution: asserts that the circuit consumed the
    /// full gate / masked-witness tape and updates `transcript` with
    /// the masked-witness bytes followed by the per-`assert` public
    /// bits (packed, matching the prover's `finish`).
    pub fn finish(self, transcript: &mut Hasher) -> Result<()> {
        if self.counter != self.gate_keys.len() {
            return Err(Error::tape_unconsumed(self.counter, self.gate_keys.len()));
        }
        let bits = &self.masked_witness;
        transcript.update(&bits.as_raw_slice().as_bytes()[..bits.len().div_ceil(8)]);
        transcript.update(
            &self.public_bits.as_raw_slice().as_bytes()[..self.public_bits.len().div_ceil(8)],
        );
        Ok(())
    }
}

impl Context for VerifierExecute<'_> {
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
        let i = self.counter;
        let mut key = *self
            .gate_keys
            .get(i)
            .expect("gate_keys tape exhausted: circuit has more AND gates than the tape");
        let adjust = *self
            .masked_witness
            .get(i)
            .as_deref()
            .expect("masked_witness exhausted: circuit has more AND gates than the witness");

        if adjust {
            key = key + *self.delta;
        }
        // Force LSB to 0 to match the prover's pointer-bit
        // convention (prover sets mac LSB = z; with delta.lsb = 1
        // the IT-MAC mac = key + b·delta then requires key.lsb = 0).
        set_lsb(&mut key, false);

        self.triples.push(Triple { x: a, y: b, z: key });
        self.counter = i + 1;

        key
    }

    fn constant(&mut self, v: Gf2) -> Gf2_128 {
        if v.0 { *self.key_one } else { *self.key_zero }
    }

    fn assert_const(&mut self, v: Gf2_128, expected: Gf2) -> Result<()> {
        let mac = if expected.0 { v + *self.delta } else { v };
        self.assertions.update(&mac.to_inner().to_le_bytes());
        self.public_bits.push(expected.0);

        Ok(())
    }
}
