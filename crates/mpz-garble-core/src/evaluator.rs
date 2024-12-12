use core::fmt;

use blake3::Hasher;

use crate::{
    circuit::EncryptedGate,
    encoding::{state, EncodedValue, Label},
    EncryptedGateBatch, DEFAULT_BATCH_SIZE,
};
use mpz_circuits::{
    types::{BinaryRepr, TypeError},
    Circuit, CircuitError, Gate,
};
use mpz_core::{
    aes::{FixedKeyAes, FIXED_KEY_AES},
    hash::Hash,
    Block,
};

/// Errors that can occur during garbled circuit evaluation.
#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum EvaluatorError {
    #[error(transparent)]
    TypeError(#[from] TypeError),
    #[error(transparent)]
    CircuitError(#[from] CircuitError),
    #[error("evaluator not finished")]
    NotFinished,
}

/// Evaluates half-gate garbled AND gate
#[inline]
pub(crate) fn and_gate(
    cipher: &FixedKeyAes,
    x: &Label,
    y: &Label,
    encrypted_gate: &EncryptedGate,
    gid: usize,
) -> Label {
    let x = x.to_inner();
    let y = y.to_inner();

    let s_a = x.lsb();
    let s_b = y.lsb();

    let j = Block::new((gid as u128).to_be_bytes());
    let k = Block::new(((gid + 1) as u128).to_be_bytes());

    let mut h = [x, y];
    cipher.tccr_many(&[j, k], &mut h);

    let [hx, hy] = h;

    let w_g = hx ^ (encrypted_gate[0] & Block::SELECT_MASK[s_a]);
    let w_e = hy ^ (Block::SELECT_MASK[s_b] & (encrypted_gate[1] ^ x));

    Label::new(w_g ^ w_e)
}

/// Output of the evaluator.
#[derive(Debug)]
pub struct EvaluatorOutput {
    /// Encoded outputs of the circuit.
    pub outputs: Vec<EncodedValue<state::Active>>,
    /// Hash of the encrypted gates.
    pub hash: Option<Hash>,
}

/// Garbled circuit evaluator.
#[derive(Debug, Default)]
pub struct Evaluator {
    /// Buffer for the active labels.
    buffer: Vec<Label>,
}

impl Evaluator {
    /// Returns a consumer over the encrypted gates of a circuit.
    ///
    /// # Arguments
    ///
    /// * `circ` - The circuit to evaluate.
    /// * `inputs` - The input values to the circuit.
    pub fn evaluate<'a>(
        &'a mut self,
        circ: &'a Circuit,
        inputs: Vec<EncodedValue<state::Active>>,
    ) -> Result<EncryptedGateConsumer<'a, std::slice::Iter<'a, Gate>>, EvaluatorError> {
        if inputs.len() != circ.inputs().len() {
            return Err(CircuitError::InvalidInputCount(
                circ.inputs().len(),
                inputs.len(),
            ))?;
        }

        // Expand the buffer to fit the circuit
        if circ.feed_count() > self.buffer.len() {
            self.buffer.resize(circ.feed_count(), Default::default());
        }

        for (encoded, input) in inputs.into_iter().zip(circ.inputs()) {
            if encoded.value_type() != input.value_type() {
                return Err(TypeError::UnexpectedType {
                    expected: input.value_type(),
                    actual: encoded.value_type(),
                })?;
            }

            for (label, node) in encoded.iter().zip(input.iter()) {
                self.buffer[node.id()] = *label;
            }
        }

        Ok(EncryptedGateConsumer::new(
            circ.gates().iter(),
            circ.outputs(),
            &mut self.buffer,
            circ.and_count(),
        ))
    }

    /// Returns a consumer over batched encrypted gates of a circuit.
    ///
    /// # Arguments
    ///
    /// * `circ` - The circuit to evaluate.
    /// * `inputs` - The input values to the circuit.
    pub fn evaluate_batched<'a>(
        &'a mut self,
        circ: &'a Circuit,
        inputs: Vec<EncodedValue<state::Active>>,
    ) -> Result<EncryptedGateBatchConsumer<'a, std::slice::Iter<'a, Gate>>, EvaluatorError> {
        self.evaluate(circ, inputs).map(EncryptedGateBatchConsumer)
    }
}

/// Consumer over the encrypted gates of a circuit.
pub struct EncryptedGateConsumer<'a, I: Iterator> {
    /// Cipher to use to encrypt the gates.
    cipher: &'static FixedKeyAes,
    /// Buffer for the active labels.
    labels: &'a mut [Label],
    /// Iterator over the gates.
    gates: I,
    /// Circuit outputs.
    outputs: &'a [BinaryRepr],
    /// Current gate id.
    gid: usize,
    /// Hasher to use to hash the encrypted gates.
    hasher: Option<Hasher>,
    /// Number of AND gates evaluated.
    counter: usize,
    /// Total number of AND gates in the circuit.
    and_count: usize,
    /// Whether the entire circuit has been garbled.
    complete: bool,
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
    fn new(gates: I, outputs: &'a [BinaryRepr], labels: &'a mut [Label], and_count: usize) -> Self {
        Self {
            cipher: &(*FIXED_KEY_AES),
            gates,
            outputs,
            labels,
            gid: 1,
            hasher: None,
            counter: 0,
            and_count,
            complete: false,
        }
    }

    /// Enables hashing of the encrypted gates.
    pub fn enable_hasher(&mut self) {
        self.hasher = Some(Hasher::new());
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
                    let z = and_gate(self.cipher, &x, &y, &encrypted_gate, self.gid);
                    self.labels[node_z.id()] = z;

                    self.gid += 2;
                    self.counter += 1;

                    if let Some(hasher) = &mut self.hasher {
                        hasher.update(&encrypted_gate.to_bytes());
                    }

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
            }
        }

        self.complete = true;
    }

    /// Returns the encoded outputs of the circuit.
    pub fn finish(mut self) -> Result<EvaluatorOutput, EvaluatorError> {
        if self.wants_gates() {
            return Err(EvaluatorError::NotFinished);
        }

        // If there were 0 AND gates in the circuit, we need to evaluate the "free" gates now.
        if !self.complete {
            self.next(Default::default());
        }

        let outputs = self
            .outputs
            .iter()
            .map(|output| {
                let labels: Vec<Label> = output.iter().map(|node| self.labels[node.id()]).collect();

                EncodedValue::<state::Active>::from_labels(output.value_type(), &labels)
                    .expect("encoding should be correct")
            })
            .collect();

        Ok(EvaluatorOutput {
            outputs,
            hash: self.hasher.as_ref().map(|hasher| {
                let hash: [u8; 32] = hasher.finalize().into();
                Hash::from(hash)
            }),
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
    /// Enables hashing of the encrypted gates.
    pub fn enable_hasher(&mut self) {
        self.0.enable_hasher()
    }

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

    /// Returns the encoded outputs of the circuit, and the hash of the encrypted gates if present.
    pub fn finish(self) -> Result<EvaluatorOutput, EvaluatorError> {
        self.0.finish()
    }
}
