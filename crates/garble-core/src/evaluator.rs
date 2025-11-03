use core::fmt;
use std::{marker::PhantomData, ops::Range, sync::Arc};

use cfg_if::cfg_if;
use mpz_memory_core::correlated::Mac;

use crate::{
    DEFAULT_BATCH_SIZE, EncryptedGateBatch, GarbledCircuit, SetupMsg, circuit::EncryptedGate,
};
use mpz_circuits::{Circuit, Gate};
use mpz_core::{Block, aes::FixedKeyAes};

/// Errors that can occur during garbled circuit evaluation.
#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum EvaluatorError {
    #[error("input length mismatch: expected {expected}, got {actual}")]
    InputLength { expected: usize, actual: usize },
    #[error("evaluator not finished")]
    NotFinished,
    #[error("attempted to set up evaluator twice")]
    AlreadySetup,
    #[error("evaluator was not in set up state as expected")]
    NotSetup,
    #[error("AND gate count mismatch: expected no more than {expected}, got {actual}")]
    GateCountMismatch { expected: usize, actual: usize },
}

/// Evaluates half-gate garbled AND gate.
#[inline]
pub(crate) fn and_gate(
    cipher: &FixedKeyAes,
    x: &Block,
    y: &Block,
    encrypted_gate: &EncryptedGate,
    gid: u128,
) -> Block {
    let s_a = x.lsb();
    let s_b = y.lsb();

    let j = Block::new(gid.to_be_bytes());
    let k = Block::new((gid + 1).to_be_bytes());

    let mut h = [*x, *y];
    cipher.tccr_many(&[j, k], &mut h);

    let [hx, hy] = h;

    let w_g = hx ^ (encrypted_gate[0] & Block::SELECT_MASK[s_a as usize]);
    let w_e = hy ^ (Block::SELECT_MASK[s_b as usize] & (encrypted_gate[1] ^ x));

    w_g ^ w_e
}

/// Output of the evaluator.
#[derive(Debug)]
pub struct EvaluatorOutput {
    /// Output MACs of the circuit.
    pub outputs: Vec<Mac>,
}

/// Garbled circuit evaluator.
#[derive(Debug)]
pub struct Evaluator {
    state: State,
}

impl Default for Evaluator {
    fn default() -> Self {
        Self {
            state: State::Initialized,
        }
    }
}

impl Evaluator {
    /// Creates a new evaluator.
    pub fn new() -> Self {
        Self {
            state: State::Initialized,
        }
    }

    /// Sets up the evaluator with the given `setup` message.
    pub fn setup(&mut self, setup: SetupMsg) -> Result<(), EvaluatorError> {
        if !matches!(self.state, State::Initialized) {
            return Err(EvaluatorError::AlreadySetup);
        }

        let SetupMsg { initial_gid, key } = setup;

        self.state = State::Setup(Setup {
            current_gid: initial_gid,
            key,
        });

        Ok(())
    }

    /// Allocates a worker for the given `count` of AND gates.
    pub fn alloc_worker(&mut self, count: usize) -> Result<EvaluatorWorker, EvaluatorError> {
        let mut state = if let State::Setup(state) = self.state.take() {
            state
        } else {
            return Err(EvaluatorError::NotSetup);
        };

        let worker = EvaluatorWorker {
            initial_id: state.alloc(count),
            count,
            key: state.key,
        };

        self.state = State::Setup(state);

        Ok(worker)
    }

    /// Returns a consumer over the encrypted gates of a circuit.
    ///
    /// # Arguments
    ///
    /// * `circ` - The circuit to evaluate.
    /// * `inputs` - The input labels to the circuit.
    pub fn evaluate<'a>(
        &'a mut self,
        circ: &'a Circuit,
        inputs: &[Mac],
    ) -> Result<EncryptedGateConsumer<'a, std::slice::Iter<'a, Gate>>, EvaluatorError> {
        self.alloc_worker(circ.and_count())?.evaluate(circ, inputs)
    }

    /// Returns a consumer over batched encrypted gates of a circuit.
    ///
    /// # Arguments
    ///
    /// * `circ` - The circuit to evaluate.
    /// * `inputs` - The input labels to the circuit.
    pub fn evaluate_batched<'a>(
        &'a mut self,
        circ: &'a Circuit,
        inputs: &[Mac],
    ) -> Result<EncryptedGateBatchConsumer<'a, std::slice::Iter<'a, Gate>>, EvaluatorError> {
        self.evaluate(circ, inputs).map(EncryptedGateBatchConsumer)
    }

    /// Returns whether evaluator was set up.
    pub fn is_setup(&self) -> bool {
        matches!(self.state, State::Setup(_))
    }
}

#[derive(Debug)]
pub(crate) enum State {
    Initialized,
    Setup(Setup),
    Error,
}

impl State {
    pub(crate) fn take(&mut self) -> State {
        std::mem::replace(self, State::Error)
    }
}

#[derive(Debug)]
pub(crate) struct Setup {
    /// The id to be assigned to the next evaluated AND gate.
    pub current_gid: u128,
    /// Key for the cipher used to encrypt the gates.
    pub key: [u8; 16],
}

impl Setup {
    /// Allocates ids for the given `count` of AND gates, returning the
    /// current id.
    fn alloc(&mut self, count: usize) -> u128 {
        let old = self.current_gid;
        // Each AND gates consumes 2 ids.
        self.current_gid += (count * 2) as u128;
        old
    }
}

/// A worker responsible for evaluating a single circuit.
///
/// Multiple workers can be run in paraller to evaluate multiple circuits.
pub struct EvaluatorWorker {
    /// Initial AND gate id of the circuit.
    initial_id: u128,
    /// AND gate count to be evaluated.
    count: usize,
    /// Key for the cipher used to encrypt the gates.
    key: [u8; 16],
}

impl EvaluatorWorker {
    /// Returns a consumer over the encrypted gates of a circuit, consuming
    /// the worker.
    ///
    /// # Arguments
    ///
    /// * `circ` - The circuit to evaluate.
    /// * `inputs` - The input labels to the circuit.
    pub fn evaluate<'a>(
        self,
        circ: &'a Circuit,
        inputs: &[Mac],
    ) -> Result<EncryptedGateConsumer<'a, std::slice::Iter<'a, Gate>>, EvaluatorError> {
        if inputs.len() != circ.inputs().len() {
            return Err(EvaluatorError::InputLength {
                expected: circ.inputs().len(),
                actual: inputs.len(),
            });
        }

        if circ.and_count() > self.count {
            return Err(EvaluatorError::GateCountMismatch {
                expected: self.count,
                actual: circ.and_count(),
            });
        }

        let mut buffer = vec![Default::default(); circ.feed_count()];
        buffer[..inputs.len()].copy_from_slice(Mac::as_blocks(inputs));

        Ok(EncryptedGateConsumer::new(
            circ.gates().iter(),
            buffer,
            circ.and_count(),
            circ.outputs(),
            self.initial_id,
            FixedKeyAes::new(self.key),
        ))
    }

    /// Returns a consumer over batched encrypted gates of a circuit, consuming
    /// the worker.
    ///
    /// # Arguments
    ///
    /// * `circ` - The circuit to evaluate.
    /// * `inputs` - The input labels to the circuit.
    pub fn evaluate_batched<'a>(
        self,
        circ: &'a Circuit,
        inputs: &[Mac],
    ) -> Result<EncryptedGateBatchConsumer<'a, std::slice::Iter<'a, Gate>>, EvaluatorError> {
        self.evaluate(circ, inputs).map(EncryptedGateBatchConsumer)
    }
}

/// Consumer over the encrypted gates of a circuit.
pub struct EncryptedGateConsumer<'a, I: Iterator> {
    /// Cipher to use to encrypt the gates.
    cipher: FixedKeyAes,
    /// Buffer for the active labels.
    labels: Vec<Block>,
    /// Iterator over the gates.
    gates: I,
    /// Current AND gate id.
    gid: u128,
    /// Number of AND gates evaluated.
    counter: usize,
    /// Total number of AND gates in the circuit.
    and_count: usize,
    /// Range of the outputs in the buffer.
    outputs: Range<usize>,
    /// Whether the entire circuit has been garbled.
    complete: bool,
    pd: PhantomData<&'a ()>,
}

impl<I: Iterator> fmt::Debug for EncryptedGateConsumer<'_, I> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "EncryptedGateConsumer {{ .. }}")
    }
}

impl<'a, I> EncryptedGateConsumer<'a, I>
where
    I: Iterator<Item = &'a Gate>,
{
    fn new(
        gates: I,
        labels: Vec<Block>,
        and_count: usize,
        outputs: Range<usize>,
        gid: u128,
        cipher: FixedKeyAes,
    ) -> Self {
        Self {
            cipher,
            gates,
            labels,
            gid,
            counter: 0,
            and_count,
            outputs,
            complete: false,
            pd: PhantomData::default(),
        }
    }

    /// Returns `true` if the evaluator wants more encrypted gates.
    #[inline]
    pub fn wants_gates(&self) -> bool {
        self.counter != self.and_count
    }

    /// Evaluates the next encrypted gate in the circuit.
    #[inline]
    pub fn next(&mut self, encrypted_gate: EncryptedGate) {
        while let Some(gate) = self.gates.next() {
            match gate {
                Gate::Xor {
                    x: node_x,
                    y: node_y,
                    z: node_z,
                } => {
                    let x = self.labels[node_x.id()];
                    let y = self.labels[node_y.id()];
                    self.labels[node_z.id()] = x ^ y;
                }
                Gate::And {
                    x: node_x,
                    y: node_y,
                    z: node_z,
                } => {
                    let x = self.labels[node_x.id()];
                    let y = self.labels[node_y.id()];
                    let z = and_gate(&self.cipher, &x, &y, &encrypted_gate, self.gid);
                    self.labels[node_z.id()] = z;

                    self.gid += 2;
                    self.counter += 1;

                    // If we have more AND gates to evaluate, return.
                    if self.wants_gates() {
                        return;
                    }
                }
                Gate::Inv {
                    x: node_x,
                    z: node_z,
                } => {
                    let x = self.labels[node_x.id()];
                    self.labels[node_z.id()] = x;
                }
                Gate::Id {
                    x: node_x,
                    z: node_z,
                } => {
                    let x = self.labels[node_x.id()];
                    self.labels[node_z.id()] = x;
                }
            }
        }

        self.complete = true;
    }

    /// Returns the encoded outputs of the circuit.
    pub fn finish(mut self) -> Result<EvaluatorOutput, EvaluatorError> {
        if self.wants_gates() {
            return Err(EvaluatorError::NotFinished);
        }

        // If there were 0 AND gates in the circuit, we need to evaluate the "free"
        // gates now.
        if !self.complete {
            self.next(Default::default());
        }

        Ok(EvaluatorOutput {
            outputs: Mac::from_blocks(self.labels[self.outputs].to_vec()),
        })
    }
}

/// Consumer returned by [`Evaluator::evaluate_batched`].
#[derive(Debug)]
pub struct EncryptedGateBatchConsumer<'a, I: Iterator, const N: usize = DEFAULT_BATCH_SIZE>(
    EncryptedGateConsumer<'a, I>,
);

impl<'a, I, const N: usize> EncryptedGateBatchConsumer<'a, I, N>
where
    I: Iterator<Item = &'a Gate>,
{
    /// Returns `true` if the evaluator wants more encrypted gates.
    pub fn wants_gates(&self) -> bool {
        self.0.wants_gates()
    }

    /// Evaluates the next batch of gates in the circuit.
    #[inline]
    pub fn next(&mut self, batch: EncryptedGateBatch<N>) {
        for encrypted_gate in batch.into_array() {
            self.0.next(encrypted_gate);
            if !self.0.wants_gates() {
                // Skipping any remaining gates which may have been used to pad the last batch.
                return;
            }
        }
    }

    /// Returns the encoded outputs of the circuit, and the hash of the
    /// encrypted gates if present.
    pub fn finish(self) -> Result<EvaluatorOutput, EvaluatorError> {
        self.0.finish()
    }
}

/// Evaluates multiple garbled circuits in bulk.
pub fn evaluate_garbled_circuits(
    circs: Vec<(Arc<Circuit>, Vec<Mac>, GarbledCircuit)>,
    workers: Vec<EvaluatorWorker>,
) -> Result<Vec<EvaluatorOutput>, EvaluatorError> {
    debug_assert!(circs.len() == workers.len());
    cfg_if! {
        if #[cfg(feature = "rayon")] {
            use rayon::prelude::*;

            circs.into_par_iter().zip(workers.into_par_iter()).map(|((circ, inputs, garbled_circuit), wrk)| {
                let mut consumer = wrk.evaluate(&circ, &inputs)?;
                for gate in garbled_circuit.gates {
                    consumer.next(gate);
                }
                consumer.finish()
            }).collect::<Result<Vec<_>, _>>()
        } else {
            let mut outputs = Vec::with_capacity(circs.len());
            for ((circ, inputs, garbled_circuit), wrk) in circs.into_iter().zip(workers.into_iter()) {
                let mut consumer = wrk.evaluate(&circ, &inputs)?;
                for gate in garbled_circuit.gates {
                    consumer.next(gate);
                }
                outputs.push(consumer.finish()?);
            }

            Ok(outputs)
        }
    }
}
