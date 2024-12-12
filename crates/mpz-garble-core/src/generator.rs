use core::fmt;

use blake3::Hasher;

use crate::{
    circuit::EncryptedGate,
    encoding::{state, Delta, EncodedValue, Label},
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

/// Errors that can occur during garbled circuit generation.
#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum GeneratorError {
    #[error(transparent)]
    TypeError(#[from] TypeError),
    #[error(transparent)]
    CircuitError(#[from] CircuitError),
    #[error("generator not finished")]
    NotFinished,
}

/// Computes half-gate garbled AND gate
#[inline]
pub(crate) fn and_gate(
    cipher: &FixedKeyAes,
    x_0: &Label,
    y_0: &Label,
    delta: &Delta,
    gid: usize,
) -> (Label, EncryptedGate) {
    let delta = delta.into_inner();
    let x_0 = x_0.to_inner();
    let x_1 = x_0 ^ delta;
    let y_0 = y_0.to_inner();
    let y_1 = y_0 ^ delta;

    let p_a = x_0.lsb();
    let p_b = y_0.lsb();
    let j = Block::new((gid as u128).to_be_bytes());
    let k = Block::new(((gid + 1) as u128).to_be_bytes());

    let mut h = [x_0, y_0, x_1, y_1];
    cipher.tccr_many(&[j, k, j, k], &mut h);

    let [hx_0, hy_0, hx_1, hy_1] = h;

    // Garbled row of generator half-gate
    let t_g = hx_0 ^ hx_1 ^ (Block::SELECT_MASK[p_b] & delta);
    let w_g = hx_0 ^ (Block::SELECT_MASK[p_a] & t_g);

    // Garbled row of evaluator half-gate
    let t_e = hy_0 ^ hy_1 ^ x_0;
    let w_e = hy_0 ^ (Block::SELECT_MASK[p_b] & (t_e ^ x_0));

    let z_0 = Label::new(w_g ^ w_e);

    (z_0, EncryptedGate::new([t_g, t_e]))
}

/// Output of the generator.
#[derive(Debug)]
pub struct GeneratorOutput {
    /// Encoded outputs of the circuit.
    pub outputs: Vec<EncodedValue<state::Full>>,
    /// Hash of the encrypted gates.
    pub hash: Option<Hash>,
}

/// Garbled circuit generator.
#[derive(Debug, Default)]
pub struct Generator {
    /// Buffer for the 0-bit labels.
    buffer: Vec<Label>,
}

impl Generator {
    /// Returns an iterator over the encrypted gates of a circuit.
    ///
    /// # Arguments
    ///
    /// * `circ` - The circuit to garble.
    /// * `delta` - The delta value to use for garbling.
    /// * `inputs` - The input values to the circuit.
    pub fn generate<'a>(
        &'a mut self,
        circ: &'a Circuit,
        delta: Delta,
        inputs: Vec<EncodedValue<state::Full>>,
    ) -> Result<EncryptedGateIter<'a, std::slice::Iter<'a, Gate>>, GeneratorError> {
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

        Ok(EncryptedGateIter::new(
            delta,
            circ.gates().iter(),
            circ.outputs(),
            &mut self.buffer,
            circ.and_count(),
        ))
    }

    /// Returns an iterator over batched encrypted gates of a circuit.
    ///
    /// # Arguments
    ///
    /// * `circ` - The circuit to garble.
    /// * `delta` - The delta value to use for garbling.
    /// * `inputs` - The input values to the circuit.
    pub fn generate_batched<'a>(
        &'a mut self,
        circ: &'a Circuit,
        delta: Delta,
        inputs: Vec<EncodedValue<state::Full>>,
    ) -> Result<EncryptedGateBatchIter<'a, std::slice::Iter<'a, Gate>>, GeneratorError> {
        self.generate(circ, delta, inputs)
            .map(EncryptedGateBatchIter)
    }
}

/// Iterator over encrypted gates of a garbled circuit.
pub struct EncryptedGateIter<'a, I> {
    /// Cipher to use to encrypt the gates.
    cipher: &'static FixedKeyAes,
    /// Global offset.
    delta: Delta,
    /// Buffer for the 0-bit labels.
    labels: &'a mut [Label],
    /// Iterator over the gates.
    gates: I,
    /// Circuit outputs.
    outputs: &'a [BinaryRepr],
    /// Current gate id.
    gid: usize,
    /// Hasher to use to hash the encrypted gates.
    hasher: Option<Hasher>,
    /// Number of AND gates generated.
    counter: usize,
    /// Number of AND gates in the circuit.
    and_count: usize,
    /// Whether the entire circuit has been garbled.
    complete: bool,
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
        outputs: &'a [BinaryRepr],
        labels: &'a mut [Label],
        and_count: usize,
    ) -> Self {
        Self {
            cipher: &(*FIXED_KEY_AES),
            delta,
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

    /// Returns `true` if the generator has more encrypted gates to generate.
    #[inline]
    pub fn has_gates(&self) -> bool {
        self.counter != self.and_count
    }

    /// Returns the encoded outputs of the circuit, and the hash of the encrypted gates if present.
    pub fn finish(mut self) -> Result<GeneratorOutput, GeneratorError> {
        if self.has_gates() {
            return Err(GeneratorError::NotFinished);
        }

        // Finish computing any "free" gates.
        if !self.complete {
            assert_eq!(self.next(), None);
        }

        let outputs = self
            .outputs
            .iter()
            .map(|output| {
                let labels: Vec<Label> = output.iter().map(|node| self.labels[node.id()]).collect();

                EncodedValue::<state::Full>::from_labels(output.value_type(), self.delta, &labels)
                    .expect("encoding should be correct")
            })
            .collect();

        Ok(GeneratorOutput {
            outputs,
            hash: self.hasher.as_ref().map(|hasher| {
                let hash: [u8; 32] = hasher.finalize().into();
                Hash::from(hash)
            }),
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
                        and_gate(self.cipher, &x_0, &y_0, &self.delta, self.gid);
                    self.labels[node_z.id()] = z_0;

                    self.gid += 2;
                    self.counter += 1;

                    if let Some(hasher) = &mut self.hasher {
                        hasher.update(&encrypted_gate.to_bytes());
                    }

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
                    self.labels[node_z.id()] = x_0 ^ self.delta;
                }
            }
        }

        None
    }
}

/// Iterator returned by [`Generator::generate_batched`].
#[derive(Debug)]
pub struct EncryptedGateBatchIter<'a, I: Iterator, const N: usize = DEFAULT_BATCH_SIZE>(
    EncryptedGateIter<'a, I>,
);

impl<'a, I, const N: usize> EncryptedGateBatchIter<'a, I, N>
where
    I: Iterator<Item = &'a Gate>,
{
    /// Enables hashing of the encrypted gates.
    pub fn enable_hasher(&mut self) {
        self.0.enable_hasher()
    }

    /// Returns `true` if the generator has more encrypted gates to generate.
    pub fn has_gates(&self) -> bool {
        self.0.has_gates()
    }

    /// Returns the encoded outputs of the circuit, and the hash of the encrypted gates if present.
    pub fn finish(self) -> Result<GeneratorOutput, GeneratorError> {
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

#[cfg(test)]
mod tests {
    use crate::{ChaChaEncoder, Encoder};
    use mpz_circuits::{circuits::AES128, CircuitBuilder};
    use pretty_assertions::assert_eq;

    use super::*;

    #[test]
    fn test_generator() {
        let encoder = ChaChaEncoder::new([0; 32]);
        let inputs: Vec<_> = AES128
            .inputs()
            .iter()
            .map(|input| encoder.encode_by_type(0, &input.value_type()))
            .collect();

        let mut gen = Generator::default();
        let mut gate_iter = gen.generate(&AES128, encoder.delta(), inputs).unwrap();

        let enc_gates: Vec<EncryptedGate> = gate_iter.by_ref().collect();

        assert!(!gate_iter.has_gates());
        assert_eq!(enc_gates.len(), AES128.and_count());

        _ = gate_iter.finish().unwrap();
    }

    #[test]
    fn test_generator_no_and() {
        let encoder = ChaChaEncoder::new([0; 32]);

        let builder = CircuitBuilder::new();
        let a = builder.add_input::<u8>();
        let b = builder.add_input::<u8>();

        let c = a ^ b;
        builder.add_output(c);

        let circ = builder.build().unwrap();

        let inputs: Vec<_> = circ
            .inputs()
            .iter()
            .map(|input| encoder.encode_by_type(0, &input.value_type()))
            .collect();

        let mut gen = Generator::default();
        let mut gate_iter = gen
            .generate_batched(&circ, encoder.delta(), inputs)
            .unwrap();

        let enc_gates: Vec<_> = gate_iter.by_ref().collect();

        assert!(enc_gates.is_empty());
    }
}
