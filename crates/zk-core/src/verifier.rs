
use blake3::Hasher;
use mpz_circuits::Context;
use mpz_fields::{gf2::Gf2, gf2_128::Gf2_128};

use crate::{
    Error, MAC_ONE, MAC_ZERO, Proof, Result,
    check::{Triple, check_verifier},
    util::set_lsb,
};

/// The verifier in the VOLE-based zero-knowledge proof protocol.
///
/// A `Verifier` holds the global MAC key `delta` and accumulates the state
/// produced while evaluating a circuit. Evaluation is performed against a
/// [`VerifierExecute`] obtained from [`execute`](Self::execute), after which
/// [`verify`](Self::verify) checks the prover's [`Proof`].
///
/// A single `Verifier` may be reused across proofs: [`verify`](Self::verify)
/// clears the accumulated state on completion.
#[derive(Debug)]
pub struct Verifier {
    triples: Vec<Triple>,
    assertions: Hasher,
    delta: Gf2_128,
    key_zero: Gf2_128,
    key_one: Gf2_128,
}

impl Verifier {
    /// Creates a new `Verifier` with the global MAC key `delta`.
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

    /// Key of a public bit: `key_one` (`MAC_ONE + delta`) for `true`,
    /// `key_zero` ([`MAC_ZERO`]) for `false`.
    pub fn public_bit(&self, bit: bool) -> Gf2_128 {
        if bit {
            self.key_one
        } else {
            self.key_zero
        }
    }

    /// Begins evaluating a circuit, returning a [`VerifierExecute`] that records
    /// evaluation state into this verifier.
    ///
    /// `keys` is the tape of verifier keys, one entry per input bit and per AND
    /// gate, consumed in evaluation order. `adjust` is the corresponding tape of
    /// adjustment bits received from the prover; each entry selects whether the
    /// matching key is offset by `delta`.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] if `keys` and `adjust` differ in length.
    pub fn execute<'a>(
        &'a mut self,
        keys: &'a [Gf2_128],
        adjust: &'a [bool],
    ) -> Result<VerifierExecute<'a>> {
        if keys.len() != adjust.len() {
            return Err(Error::tape_len("adjust", keys.len(), adjust.len()));
        }
        Ok(VerifierExecute {
            triples: &mut self.triples,
            assertions: &mut self.assertions,
            keys,
            adjust,
            delta: &self.delta,
            key_zero: &self.key_zero,
            key_one: &self.key_one,
            cursor: 0,
        })
    }

    /// Verifies `proof` against the state accumulated during evaluation.
    ///
    /// `chi` is the random challenge used to batch the check, and `vope_keys`
    /// are the verifier's keys used to mask it. On success, the accumulated
    /// state is cleared so this verifier can be reused.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] if the assertions in `proof` do not match the
    /// assertions recorded during evaluation, or if the consistency check
    /// fails.
    pub fn verify(
        &mut self,
        chi: [u8; 32],
        vope_keys: &[Gf2_128; 128],
        proof: Proof,
    ) -> Result<()> {
        let Proof { assertions, u, v } = proof;

        let expected_assertions = *self.assertions.finalize().as_bytes();
        if assertions != expected_assertions {
            return Err(Error::assert());
        }

        let b = crate::vope::vope_sender(vope_keys);
        check_verifier(&self.triples, self.delta, chi, b, u, v)?;

        self.assertions.reset();
        self.triples.clear();

        Ok(())
    }
}

/// An in-progress circuit evaluation on the verifier side.
///
/// Returned by [`Verifier::execute`], a `VerifierExecute` implements
/// [`Context`] so a circuit can be evaluated over verifier keys. It consumes
/// the key and adjustment tapes as input and AND gates are encountered,
/// recording the state needed to check the proof. Call
/// [`finish`](Self::finish) once evaluation completes to confirm the tapes were
/// fully consumed.
#[derive(Debug)]
pub struct VerifierExecute<'a> {
    triples: &'a mut Vec<Triple>,
    assertions: &'a mut Hasher,
    keys: &'a [Gf2_128],
    adjust: &'a [bool],
    delta: &'a Gf2_128,
    key_zero: &'a Gf2_128,
    key_one: &'a Gf2_128,
    cursor: usize,
}

impl VerifierExecute<'_> {
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
        let raw = *self
            .keys
            .get(i)
            .expect("key tape exhausted during input");
        let adj = *self
            .adjust
            .get(i)
            .expect("adjust tape exhausted during input");
        let mut key = if adj { raw + *self.delta } else { raw };
        set_lsb(&mut key, false);
        self.cursor = i + 1;
        key
    }

    /// Returns the verifier key for a public input wire carrying `bit`.
    ///
    /// Public inputs consume no tape entries, since their value is known to both
    /// parties.
    pub fn input_public(&self, bit: bool) -> Gf2_128 {
        if bit { *self.key_one } else { *self.key_zero }
    }

    /// Completes evaluation, confirming that the adjustment tape was fully
    /// consumed.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] if the circuit consumed fewer tape entries than were
    /// provided, indicating a mismatch between the circuit and the tapes.
    pub fn finish(self) -> Result<()> {
        if self.cursor != self.adjust.len() {
            return Err(Error::tape_unconsumed(self.cursor, self.adjust.len()));
        }
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
        let i = self.cursor;
        let mut key = *self
            .keys
            .get(i)
            .expect("key tape exhausted: circuit has more AND gates than the tape");
        let adj = *self
            .adjust
            .get(i)
            .expect("adjust tape exhausted: circuit has more AND gates than the witness");

        if adj {
            key = key + *self.delta;
        }
        set_lsb(&mut key, false);

        self.triples.push(Triple { x: a, y: b, z: key });
        self.cursor = i + 1;

        key
    }

    fn constant(&mut self, v: Gf2) -> Gf2_128 {
        if v.0 { *self.key_one } else { *self.key_zero }
    }

    fn assert_const(&mut self, v: Gf2_128, expected: Gf2) -> Result<()> {
        let mac = if expected.0 { v + *self.delta } else { v };
        self.assertions.update(&mac.to_inner().to_le_bytes());

        Ok(())
    }
}
