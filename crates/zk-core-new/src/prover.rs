
use blake3::Hasher;
use itybity::{GetBit, Lsb0};
use mpz_circuits_new::Context;
use mpz_fields::{gf2::Gf2, gf2_128::Gf2_128};

use crate::{
    Error, MAC_ONE, MAC_ZERO, Proof, ProverVope, Result,
    check::{Triple, check_prover},
    poly::{PolyContext, ProverExpr, lsb},
    poly_check,
    util::set_lsb,
};

/// The prover side of the zero-knowledge protocol.
///
/// A `Prover` accumulates the state produced while evaluating one or more
/// circuits, then condenses it into a single [`Proof`] via
/// [`prove`](Self::prove).
///
/// Evaluate a circuit by obtaining a [`ProverExecute`] context from
/// [`execute`](Self::execute), feeding it through a circuit, and calling
/// [`ProverExecute::finish`]. State accumulated across executions is consumed
/// and reset by [`prove`](Self::prove).
#[derive(Debug, Default)]
pub struct Prover {
    triples: Vec<Triple>,
    assertions: Hasher,
    poly: Vec<ProverExpr>,
}

impl Prover {
    /// Creates a new prover with no accumulated state.
    pub fn new() -> Self {
        Self::default()
    }

    /// MAC of a public bit: [`MAC_ONE`] for `true`, [`MAC_ZERO`] for `false`.
    pub fn public_bit(&self, bit: bool) -> Gf2_128 {
        if bit {
            MAC_ONE
        } else {
            MAC_ZERO
        }
    }

    /// Returns a [`ProverExecute`] context for evaluating a circuit.
    ///
    /// The `masks` tape is adjusted in place as the circuit is evaluated, and
    /// `macs` supplies the corresponding authentication tags. Both tapes are
    /// indexed in lockstep: entry `i` is consumed by the `i`-th input or AND
    /// gate.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] if `masks` and `macs` differ in length.
    pub fn execute<'a>(
        &'a mut self,
        masks: &'a mut [bool],
        macs: &'a [Gf2_128],
    ) -> Result<ProverExecute<'a>> {
        if masks.len() != macs.len() {
            return Err(Error::tape_len("macs", masks.len(), macs.len()));
        }
        Ok(ProverExecute {
            triples: &mut self.triples,
            assertions: &mut self.assertions,
            poly: &mut self.poly,
            masks,
            macs,
            cursor: 0,
        })
    }

    /// Produces a [`Proof`] over all state accumulated so far.
    ///
    /// The random challenge `chi` and the correlation (`vope_choices`,
    /// `vope_ev`) mask the proof so it reveals nothing about the witness. The
    /// accumulated state is cleared, leaving the prover ready to be reused.
    pub fn prove(
        &mut self,
        chi: [u8; 32],
        vope_choices: &[bool; 128],
        vope_ev: &[Gf2_128; 128],
        poly_vope: &ProverVope,
    ) -> Proof {
        let (a_0, a_1) = crate::vope::vope_receiver(vope_choices, vope_ev);

        let assertions = *self.assertions.finalize().as_bytes();

        let (u, v) = check_prover(&self.triples, chi, a_0, a_1);
        let coefficients = poly_check::check_prover(&self.poly, chi, &poly_vope.coeffs);

        self.assertions.reset();
        self.triples.clear();
        self.poly.clear();

        Proof {
            assertions,
            u,
            v,
            coefficients,
        }
    }
}

/// A circuit evaluation context for the [`Prover`].
///
/// Implements [`Context`] so a circuit can be evaluated over authenticated
/// wires, recording the state needed for the proof. Wire
/// inputs are supplied with [`input`](Self::input) and
/// [`input_public`](Self::input_public); [`finish`](Self::finish) validates
/// that the entire tape was consumed.
#[derive(Debug)]
pub struct ProverExecute<'a> {
    triples: &'a mut Vec<Triple>,
    assertions: &'a mut Hasher,
    poly: &'a mut Vec<ProverExpr>,
    masks: &'a mut [bool],
    macs: &'a [Gf2_128],
    cursor: usize,
}

impl ProverExecute<'_> {
    /// Consumes the next tape entry to commit `bit`, adjusting the `masks` tape
    /// in place and returning the authenticated wire (MAC with `lsb = bit`).
    ///
    /// Shared by [`input`](Self::input), AND gates, and [`materialize`].
    ///
    /// # Panics
    ///
    /// Panics if the mask or MAC tape has been exhausted.
    ///
    /// [`materialize`]: PolyContext::materialize
    fn commit(&mut self, bit: bool) -> Gf2_128 {
        let i = self.cursor;
        let slot = self
            .masks
            .get_mut(i)
            .expect("mask tape exhausted during commit");
        let mut mac = *self.macs.get(i).expect("mac tape exhausted during commit");
        *slot ^= bit;
        set_lsb(&mut mac, bit);
        self.cursor = i + 1;
        mac
    }

    /// Consumes the next tape entry to commit a private input `bit` and returns
    /// its authenticated wire.
    ///
    /// The corresponding entry of the `masks` tape is adjusted in place to
    /// encode `bit`.
    ///
    /// # Panics
    ///
    /// Panics if the mask or MAC tape has been exhausted.
    pub fn input(&mut self, bit: bool) -> Gf2_128 {
        self.commit(bit)
    }

    /// Returns the authenticated wire for a public input `bit`.
    ///
    /// Public inputs consume no tape entry, since their value is known to both
    /// parties; the wire is a fixed constant determined by `bit`.
    pub fn input_public(&self, bit: bool) -> Gf2_128 {
        if bit { MAC_ONE } else { MAC_ZERO }
    }

    /// Finalizes the evaluation, validating that the entire tape was consumed.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] if the number of consumed tape entries does not match
    /// the tape length, indicating the circuit drew fewer inputs and AND gates
    /// than the tape provides.
    pub fn finish(self) -> Result<()> {
        if self.cursor != self.masks.len() {
            return Err(Error::tape_unconsumed(self.cursor, self.masks.len()));
        }
        Ok(())
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
        let mac = self.commit(z);
        self.triples.push(Triple { x: a, y: b, z: mac });
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

        Ok(())
    }
}

impl PolyContext for ProverExecute<'_> {
    type Expr = ProverExpr;

    fn lift(&self, wire: Gf2_128) -> ProverExpr {
        ProverExpr::lift(wire, lsb(wire))
    }

    fn constant(&self, value: Gf2) -> ProverExpr {
        ProverExpr::constant(value)
    }

    fn materialize(&mut self, expr: ProverExpr) -> Gf2_128 {
        let value = expr.value();
        let mac = self.commit(value.0);
        // Pin the committed output to the expression: `expr - out == 0`.
        let constraint = expr - ProverExpr::lift(mac, value);
        self.poly.push(constraint);
        mac
    }

    fn assert_zero(&mut self, expr: ProverExpr) -> Result<()> {
        if expr.value() != Gf2::ZERO {
            return Err(Error::assert());
        }
        self.poly.push(expr);
        Ok(())
    }
}
