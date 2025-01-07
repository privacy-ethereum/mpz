use std::sync::{Arc, Mutex};

use mpz_circuits::{Circuit, Gate};
use mpz_core::{bitvec::BitVec, Block};
use mpz_memory_core::correlated::{Delta, Key};

use crate::check::{Check, CheckError, Triple, UV};

type Result<T> = core::result::Result<T, VerifierError>;

pub struct Verifier {
    delta: Delta,
    check: Arc<Mutex<Check>>,
}

impl Verifier {
    /// Creates a new verifier.
    pub fn new(delta: Delta) -> Self {
        Self {
            delta,
            check: Arc::new(Mutex::new(Check::default())),
        }
    }

    /// Returns `true` if there are gates to check.
    pub fn wants_check(&self) -> bool {
        self.check.lock().unwrap().wants_check()
    }

    pub fn execute<'a>(
        &mut self,
        circ: Arc<Circuit>,
        input_keys: &[Key],
        gate_keys: &[Key],
    ) -> Result<VerifierExecute> {
        if input_keys.len() != circ.input_len() {
            return Err(ErrorRepr::InputKeyCount {
                expected: circ.input_len(),
                actual: input_keys.len(),
            }
            .into());
        } else if gate_keys.len() != circ.and_count() {
            return Err(ErrorRepr::GateKeyCount {
                expected: circ.and_count(),
                actual: gate_keys.len(),
            }
            .into());
        }

        let check_idx = self.check.lock().unwrap().reserve(circ.and_count());

        let mut keys = vec![Key::default(); input_keys.len()];
        let mut input_keys = input_keys.into_iter();
        for input in circ.inputs() {
            for (node, key) in input.iter().zip(input_keys.by_ref()) {
                keys[node.id()] = *key;
            }
        }

        Ok(VerifierExecute::new(
            circ,
            self.delta,
            keys,
            gate_keys.to_vec(),
            self.check.clone(),
            check_idx,
        ))
    }

    /// Executes the consistency check.
    pub fn check(&mut self, svole_keys: &[Block], uv: UV) -> Result<()> {
        if Arc::strong_count(&self.check) > 1 {
            return Err(ErrorRepr::Inprogress.into());
        }

        self.check
            .lock()
            .unwrap()
            .check_verifier(self.delta.as_block(), svole_keys, uv)
            .map_err(From::from)
    }
}

/// Verifier circuit execution.
#[derive(Debug)]
pub struct VerifierExecute {
    circ: Arc<Circuit>,
    delta: Delta,
    keys: Vec<Key>,
    gate_keys: Vec<Key>,
    triples: Vec<Triple>,
    adjust: BitVec<u8>,
    check: Arc<Mutex<Check>>,
    check_idx: usize,

    counter: usize,
    and_count: usize,
}

impl VerifierExecute {
    fn new(
        circ: Arc<Circuit>,
        delta: Delta,
        keys: Vec<Key>,
        gate_keys: Vec<Key>,
        check: Arc<Mutex<Check>>,
        check_idx: usize,
    ) -> Self {
        let and_count = circ.and_count();
        Self {
            circ,
            delta,
            keys,
            gate_keys,
            triples: Vec::default(),
            adjust: BitVec::default(),
            check,
            check_idx,
            counter: 0,
            and_count,
        }
    }

    pub fn and_count(&self) -> usize {
        self.circ.and_count()
    }

    pub fn consumer(&mut self) -> VerifierConsumer<'_, std::slice::Iter<'_, Gate>> {
        // Allocate space for all the keys.
        self.keys
            .resize_with(self.circ.feed_count(), Default::default);

        if self.triples.capacity() < self.circ.and_count() {
            self.triples.reserve_exact(self.circ.and_count());
        }

        if self.adjust.capacity() < self.circ.and_count() {
            self.adjust.reserve_exact(self.circ.and_count());
        }

        // Reset counter in case this is called multiple times by mistake.
        self.counter = 0;

        let mut consumer = VerifierConsumer {
            keys: &mut self.keys,
            gate_keys: &self.gate_keys,
            delta: self.delta,
            gates: self.circ.gates().iter(),
            triples: &mut self.triples,
            adjust: &mut self.adjust,
            counter: &mut self.counter,
            and_count: self.and_count,
        };

        // If there are no AND gates, we can process the circuit immediately.
        if self.and_count == 0 {
            consumer.next(Default::default());
        }

        consumer
    }

    pub fn finish(self) -> Result<Vec<Key>> {
        if self.counter < self.and_count {
            return Err(ErrorRepr::Incomplete.into());
        }

        let outputs = self
            .circ
            .outputs()
            .iter()
            .flat_map(|output| output.iter().map(|node| self.keys[node.id()]))
            .collect();

        // Flush check state.
        self.check
            .lock()
            .unwrap()
            .write(self.check_idx, &self.triples, &self.adjust);

        Ok(outputs)
    }
}

/// Consumer accepting adjustment bits from the prover for each AND gate.
#[must_use = "consumer does nothing unless `next` is called"]
pub struct VerifierConsumer<'a, I> {
    keys: &'a mut [Key],
    gate_keys: &'a [Key],
    delta: Delta,
    gates: I,
    triples: &'a mut Vec<Triple>,
    adjust: &'a mut BitVec<u8>,
    counter: &'a mut usize,
    and_count: usize,
}

impl<'a, I> VerifierConsumer<'a, I>
where
    I: Iterator<Item = &'a Gate>,
{
    /// Returns `true` if the verifier wants more adjustment bits.
    #[inline]
    pub fn wants_adjust(&self) -> bool {
        *self.counter < self.and_count
    }

    /// Processes the next gate in the circuit.
    #[inline]
    pub fn next(&mut self, adjust: bool) {
        while let Some(gate) = self.gates.next() {
            match gate {
                Gate::Xor {
                    x: node_x,
                    y: node_y,
                    z: node_z,
                } => {
                    let x = self.keys[node_x.id()];
                    let y = self.keys[node_y.id()];
                    self.keys[node_z.id()] = x + y;
                }
                Gate::And {
                    x: node_x,
                    y: node_y,
                    z: node_z,
                } => {
                    let key_x = self.keys[node_x.id()];
                    let key_y = self.keys[node_y.id()];
                    let mut key_z = self.gate_keys[*self.counter];

                    key_z.adjust(adjust, &self.delta);

                    self.keys[node_z.id()] = key_z;
                    self.triples.push(Triple {
                        x: key_x.into(),
                        y: key_y.into(),
                        z: key_z.into(),
                    });
                    self.adjust.push(adjust);
                    *self.counter += 1;

                    // If we have more AND gates, return.
                    if self.wants_adjust() {
                        return;
                    }
                }
                Gate::Inv {
                    x: node_x,
                    z: node_z,
                } => {
                    let mut x = self.keys[node_x.id()];
                    x.adjust(true, &self.delta);
                    self.keys[node_z.id()] = x;
                }
            }
        }
    }
}

#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct VerifierError(#[from] ErrorRepr);

#[derive(Debug, thiserror::Error)]
enum ErrorRepr {
    #[error("invalid input key count: expected {expected}, got {actual}")]
    InputKeyCount { expected: usize, actual: usize },
    #[error("invalid gate key count: expected {expected}, got {actual}")]
    GateKeyCount { expected: usize, actual: usize },
    #[error("execution is incomplete")]
    Incomplete,
    #[error("cannot run consistency check while execution is in progress")]
    Inprogress,
    #[error(transparent)]
    Check(CheckError),
}

impl From<CheckError> for VerifierError {
    fn from(err: CheckError) -> Self {
        Self(ErrorRepr::Check(err))
    }
}
