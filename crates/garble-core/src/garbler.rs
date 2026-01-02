use core::fmt;
use rand::{Rng, rng};
use std::{marker::PhantomData, ops::Range};

use crate::{DEFAULT_BATCH_SIZE, EncryptedGateBatch, SetupMsg, circuit::EncryptedGate};
use mpz_circuits::{Circuit, Gate};
use mpz_core::{Block, aes::FixedKeyAes};
use mpz_memory_core::correlated::{Delta, Key};

/// Errors that can occur during garbled circuit generation.
#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum GarblerError {
    #[error("input length mismatch: expected {expected}, got {actual}")]
    InputLength { expected: usize, actual: usize },
    #[error("garbler not finished")]
    NotFinished,
    #[error("attempted to set up garbler twice")]
    AlreadySetup,
    #[error("garbler was not in set up state as expected")]
    NotSetup,
    #[error("AND gate count mismatch: expected no more than {expected}, got {actual}")]
    GateCountMismatch { expected: usize, actual: usize },
}

/// Computes half-gate garbled AND gate.
#[inline]
pub(crate) fn and_gate(
    cipher: &FixedKeyAes,
    x_0: &Block,
    y_0: &Block,
    delta: &Delta,
    gid: u128,
) -> (Block, EncryptedGate) {
    let delta = delta.as_block();
    let x_1 = x_0 ^ delta;
    let y_1 = y_0 ^ delta;

    let p_a = x_0.lsb();
    let p_b = y_0.lsb();
    let j = Block::new(gid.to_be_bytes());
    let k = Block::new((gid + 1).to_be_bytes());

    let mut h = [*x_0, *y_0, x_1, y_1];
    cipher.tccr_many(&[j, k, j, k], &mut h);

    let [hx_0, hy_0, hx_1, hy_1] = h;

    // Garbled row of garbler half-gate
    let t_g = hx_0 ^ hx_1 ^ (Block::SELECT_MASK[p_b as usize] & delta);
    let w_g = hx_0 ^ (Block::SELECT_MASK[p_a as usize] & t_g);

    // Garbled row of evaluator half-gate
    let t_e = hy_0 ^ hy_1 ^ x_0;
    let w_e = hy_0 ^ (Block::SELECT_MASK[p_b as usize] & (t_e ^ x_0));

    let z_0 = w_g ^ w_e;

    (z_0, EncryptedGate::new([t_g, t_e]))
}

/// Output of the garbler.
#[derive(Debug)]
pub struct GarblerOutput {
    /// Output keys of the circuit.
    pub outputs: Vec<Key>,
}

/// Garbled circuit generator.
#[derive(Debug)]
pub struct Garbler {
    delta: Delta,
    state: State,
}

impl Garbler {
    /// Creates a new garbler with the given `delta`.
    pub fn new(delta: Delta) -> Self {
        Self {
            state: State::Initialized(Initialized::default()),
            delta,
        }
    }

    /// Sets up the garbler returning a setup message.
    pub fn setup(&mut self) -> Result<SetupMsg, GarblerError> {
        let state = if let State::Initialized(state) = self.state.take() {
            state
        } else {
            return Err(GarblerError::AlreadySetup);
        };

        let msg = SetupMsg {
            initial_gid: state.initial_gid,
            key: state.key,
        };

        self.state = State::Setup(Setup {
            current_gid: state.initial_gid,
            key: state.key,
        });

        Ok(msg)
    }

    /// Allocates a worker for the given `count` of AND gates.
    pub fn alloc_worker(&mut self, count: usize) -> Result<GarblerWorker, GarblerError> {
        let mut state = if let State::Setup(state) = self.state.take() {
            state
        } else {
            return Err(GarblerError::NotSetup);
        };

        let worker = GarblerWorker {
            initial_id: state.alloc(count),
            count,
            key: state.key,
            delta: self.delta,
        };

        self.state = State::Setup(state);

        Ok(worker)
    }

    /// Returns an iterator over the encrypted gates of a circuit.
    ///
    /// # Arguments
    ///
    /// * `circ` - The circuit to garble.
    /// * `inputs` - The input labels to the circuit.
    pub fn generate<'a>(
        &'a mut self,
        circ: &'a Circuit,
        inputs: &[Key],
    ) -> Result<EncryptedGateIter<'a, std::slice::Iter<'a, Gate>>, GarblerError> {
        self.alloc_worker(circ.and_count())?.generate(circ, inputs)
    }

    /// Returns an iterator over batched encrypted gates of a circuit.
    ///
    /// # Arguments
    ///
    /// * `circ` - The circuit to garble.
    /// * `inputs` - The input labels to the circuit.
    pub fn generate_batched<'a>(
        &'a mut self,
        circ: &'a Circuit,
        inputs: &[Key],
    ) -> Result<EncryptedGateBatchIter<'a, std::slice::Iter<'a, Gate>>, GarblerError> {
        self.alloc_worker(circ.and_count())?
            .generate(circ, inputs)
            .map(EncryptedGateBatchIter)
    }

    /// Returns whether garbler was set up.
    pub fn is_setup(&self) -> bool {
        matches!(self.state, State::Setup(_))
    }
}

/// A worker responsible for garbling a single circuit.
///
/// Multiple workers can be run in paraller to garble multiple circuits.
pub struct GarblerWorker {
    /// Initial AND gate id of the circuit.
    initial_id: u128,
    /// AND gate count to be garbled.
    count: usize,
    /// Key for the cipher used to encrypt the gates.
    key: [u8; 16],
    delta: Delta,
}

impl GarblerWorker {
    /// Returns an iterator over the encrypted gates of a circuit, consuming
    /// the worker.
    ///
    /// # Arguments
    ///
    /// * `circ` - The circuit to garble.
    /// * `inputs` - The input labels to the circuit.
    pub fn generate<'a>(
        self,
        circ: &'a Circuit,
        inputs: &[Key],
    ) -> Result<EncryptedGateIter<'a, std::slice::Iter<'a, Gate>>, GarblerError> {
        if inputs.len() != circ.inputs().len() {
            return Err(GarblerError::InputLength {
                expected: circ.inputs().len(),
                actual: inputs.len(),
            });
        }

        if circ.and_count() > self.count {
            return Err(GarblerError::GateCountMismatch {
                expected: self.count,
                actual: circ.and_count(),
            });
        }

        let mut buffer = vec![Default::default(); circ.feed_count()];
        buffer[..inputs.len()].copy_from_slice(Key::as_blocks(inputs));

        Ok(EncryptedGateIter::new(
            self.delta,
            circ.gates().iter(),
            buffer,
            self.initial_id,
            circ.and_count(),
            circ.outputs(),
            FixedKeyAes::new(self.key),
        ))
    }

    /// Returns an iterator over batched encrypted gates of a circuit,
    /// consuming the worker.
    ///
    /// # Arguments
    ///
    /// * `circ` - The circuit to garble.
    /// * `inputs` - The input labels to the circuit.
    pub fn generate_batched<'a>(
        self,
        circ: &'a Circuit,
        inputs: &[Key],
    ) -> Result<EncryptedGateBatchIter<'a, std::slice::Iter<'a, Gate>>, GarblerError> {
        self.generate(circ, inputs)
            .map(EncryptedGateBatchIter)
    }
}

#[derive(Debug)]
enum State {
    Initialized(Initialized),
    Setup(Setup),
    Error,
}

impl State {
    pub(crate) fn take(&mut self) -> State {
        std::mem::replace(self, State::Error)
    }
}

#[derive(Debug)]
struct Initialized {
    /// Initial gate id.
    pub(super) initial_gid: u128,
    /// Key for the cipher used to encrypt the gates.
    pub(super) key: [u8; 16],
}

impl Default for Initialized {
    fn default() -> Self {
        Self {
            // Randomize gate id for better multi-instance security
            // https://eprint.iacr.org/2019/1168 Section 5.
            initial_gid: rng().random(),
            // Randomize the key of the fixed-key cipher to confine
            // security degradation to a single instance, preventing
            // it from compounding across multiple instances
            // (see Fig. 4 in https://eprint.iacr.org/2019/1168).
            key: rng().random(),
        }
    }
}

#[derive(Debug)]
struct Setup {
    /// The id to be assigned to the next garbled AND gate.
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

/// Iterator over encrypted gates of a garbled circuit.
pub struct EncryptedGateIter<'a, I> {
    /// Cipher to use to encrypt the gates.
    cipher: FixedKeyAes,
    /// Global offset.
    delta: Delta,
    /// Buffer for the 0-bit labels.
    labels: Vec<Block>,
    /// Iterator over the gates.
    gates: I,
    /// Current AND gate id.
    gid: u128,
    /// Number of AND gates generated.
    counter: usize,
    /// Number of AND gates in the circuit.
    and_count: usize,
    /// Range of the outputs in the buffer.
    outputs: Range<usize>,
    /// Whether the entire circuit has been garbled.
    complete: bool,
    pd: PhantomData<&'a ()>,
}

impl<I> fmt::Debug for EncryptedGateIter<'_, I> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "EncryptedGateIter {{ .. }}")
    }
}

impl<'a, I> EncryptedGateIter<'a, I>
where
    I: Iterator<Item = &'a Gate>,
{
    fn new(
        delta: Delta,
        gates: I,
        labels: Vec<Block>,
        gid: u128,
        and_count: usize,
        outputs: Range<usize>,
        cipher: FixedKeyAes,
    ) -> Self {
        Self {
            cipher,
            delta,
            gates,
            labels,
            gid,
            counter: 0,
            and_count,
            outputs,
            complete: false,
            pd: PhantomData,
        }
    }

    /// Returns `true` if the garbler has more encrypted gates to generate.
    #[inline]
    pub fn has_gates(&self) -> bool {
        self.counter != self.and_count
    }

    /// Returns the encoded outputs of the circuit, and the hash of the
    /// encrypted gates if present.
    pub fn finish(mut self) -> Result<GarblerOutput, GarblerError> {
        if self.has_gates() {
            return Err(GarblerError::NotFinished);
        }

        // Finish computing any "free" gates.
        if !self.complete {
            assert_eq!(self.next(), None);
        }

        Ok(GarblerOutput {
            outputs: Key::from_blocks(self.labels[self.outputs].to_vec()),
        })
    }
}

impl<'a, I> Iterator for EncryptedGateIter<'a, I>
where
    I: Iterator<Item = &'a Gate>,
{
    type Item = EncryptedGate;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        while let Some(gate) = self.gates.next() {
            match gate {
                Gate::Xor {
                    x: node_x,
                    y: node_y,
                    z: node_z,
                } => {
                    let x_0 = self.labels[node_x.id()];
                    let y_0 = self.labels[node_y.id()];
                    self.labels[node_z.id()] = x_0 ^ y_0;
                }
                Gate::And {
                    x: node_x,
                    y: node_y,
                    z: node_z,
                } => {
                    let x_0 = self.labels[node_x.id()];
                    let y_0 = self.labels[node_y.id()];
                    let (z_0, encrypted_gate) =
                        and_gate(&self.cipher, &x_0, &y_0, &self.delta, self.gid);
                    self.labels[node_z.id()] = z_0;

                    self.gid += 2;
                    self.counter += 1;

                    // If we have generated all AND gates, we can compute
                    // the rest of the "free" gates.
                    if !self.has_gates() {
                        assert!(self.next().is_none());

                        self.complete = true;
                    }

                    return Some(encrypted_gate);
                }
                Gate::Inv {
                    x: node_x,
                    z: node_z,
                } => {
                    let x_0 = self.labels[node_x.id()];
                    self.labels[node_z.id()] = x_0 ^ self.delta.as_block();
                }
                Gate::Id {
                    x: node_x,
                    z: node_z,
                } => {
                    let x_0 = self.labels[node_x.id()];
                    self.labels[node_z.id()] = x_0;
                }
            }
        }

        None
    }
}

/// Iterator returned by [`Garbler::generate_batched`].
#[derive(Debug)]
pub struct EncryptedGateBatchIter<'a, I: Iterator, const N: usize = DEFAULT_BATCH_SIZE>(
    EncryptedGateIter<'a, I>,
);

impl<'a, I, const N: usize> EncryptedGateBatchIter<'a, I, N>
where
    I: Iterator<Item = &'a Gate>,
{
    /// Returns `true` if the garbler has more encrypted gates to generate.
    pub fn has_gates(&self) -> bool {
        self.0.has_gates()
    }

    /// Returns the encoded outputs of the circuit, and the hash of the
    /// encrypted gates if present.
    pub fn finish(self) -> Result<GarblerOutput, GarblerError> {
        self.0.finish()
    }
}

impl<'a, I, const N: usize> Iterator for EncryptedGateBatchIter<'a, I, N>
where
    I: Iterator<Item = &'a Gate>,
{
    type Item = EncryptedGateBatch<N>;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        if !self.has_gates() {
            return None;
        }

        let mut batch = [EncryptedGate::default(); N];
        let mut i = 0;
        for gate in self.0.by_ref() {
            batch[i] = gate;
            i += 1;

            if i == N {
                break;
            }
        }

        Some(EncryptedGateBatch::new(batch))
    }
}
