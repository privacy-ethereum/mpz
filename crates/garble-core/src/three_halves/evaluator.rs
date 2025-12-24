//! Evaluator for Three Halves Scheme
//!
//! This module implements the evaluation function for circuits using the
//! Three Halves technique from Rosulek & Roy 2021.

use core::fmt;
use std::{ops::Range, sync::Arc};

use mpz_circuits::{Circuit, Gate};
use mpz_core::{
    Block,
    aes::{FIXED_KEY_AES, FixedKeyAes},
};
use mpz_memory_core::correlated::Mac;

use super::{
    ControlBits, EncryptedGate, EncryptedGateBatch, ThreeHalvesGate,
    control::{expand_marginal, extract_r_p_marginal},
    garbler::xor_assign_8,
    slicing::SlicedLabel,
};

use crate::DEFAULT_BATCH_SIZE;

/// Precomputed bitmasks indicating which gate ciphertexts to XOR for each row.
///
/// This is derived from columns 2, 3, 4 of matrix V (the G₀, G₁, G₂ columns).
/// For each of the 8 rows, the bitmask indicates which gate components to
/// include:
/// - bit 0 (LSB): include G₀ if set
/// - bit 1:       include G₁ if set
/// - bit 2:       include G₂ if set
///
/// Row-by-row breakdown from V matrix:
/// - Row 0 (0,0)L: [0,0,0] → 0b000 = 0 (no gate components)
/// - Row 1 (0,0)R: [0,0,0] → 0b000 = 0 (no gate components)
/// - Row 2 (0,1)L: [0,0,1] → 0b100 = 4 (only G₂)
/// - Row 3 (0,1)R: [0,1,1] → 0b110 = 6 (G₁ ⊕ G₂)
/// - Row 4 (1,0)L: [1,0,1] → 0b101 = 5 (G₀ ⊕ G₂)
/// - Row 5 (1,0)R: [0,0,1] → 0b100 = 4 (only G₂)
/// - Row 6 (1,1)L: [1,0,0] → 0b001 = 1 (only G₀)
/// - Row 7 (1,1)R: [0,1,0] → 0b010 = 2 (only G₁)
const GATE_CONTRIBUTION_MASKS: [u8; 8] = [0, 0, 4, 6, 5, 4, 1, 2];

/// Precomputed bitmasks indicating which hash outputs to XOR for each row.
///
/// This is derived from the M matrix pattern. Each row needs to XOR specific
/// hash outputs based on the input combination (i, j):
/// - bit 0 (LSB): include h_a (H(A_i)) if set
/// - bit 1:       include h_b (H(B_j)) if set
/// - bit 2:       include h_ab (H(A_i ⊕ B_j)) if set
///
/// Pattern from M matrix:
/// - Even rows (left halves):  Always H(A_i) ⊕ H(A_i⊕B_j) → 0b101 = 5
/// - Odd rows (right halves):  Always H(B_j) ⊕ H(A_i⊕B_j) → 0b110 = 6
///
/// Row-by-row breakdown:
/// - Row 0 (0,0)L: H(A₀) ⊕ H(A₀⊕B₀) → h_a ⊕ h_ab = 0b101 = 5
/// - Row 1 (0,0)R: H(B₀) ⊕ H(A₀⊕B₀) → h_b ⊕ h_ab = 0b110 = 6
/// - Row 2 (0,1)L: H(A₀) ⊕ H(A₀⊕B₁) → h_a ⊕ h_ab = 0b101 = 5
/// - Row 3 (0,1)R: H(B₁) ⊕ H(A₀⊕B₁) → h_b ⊕ h_ab = 0b110 = 6
/// - Row 4 (1,0)L: H(A₁) ⊕ H(A₀⊕B₁) → h_a ⊕ h_ab = 0b101 = 5
/// - Row 5 (1,0)R: H(B₀) ⊕ H(A₀⊕B₁) → h_b ⊕ h_ab = 0b110 = 6
/// - Row 6 (1,1)L: H(A₁) ⊕ H(A₀⊕B₀) → h_a ⊕ h_ab = 0b101 = 5
/// - Row 7 (1,1)R: H(B₁) ⊕ H(A₀⊕B₀) → h_b ⊕ h_ab = 0b110 = 6
const HASH_CONTRIBUTION_MASKS: [u8; 8] = [5, 6, 5, 6, 5, 6, 5, 6];

/// Evaluator for Three Halves scheme.
#[derive(Debug, Default)]
pub struct Evaluator {
    /// Buffer for the active labels.
    buffer: Vec<Block>,
}

impl Evaluator {
    /// Creates a new evaluator with a buffer of the given capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            buffer: Vec::with_capacity(capacity),
        }
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
        if inputs.len() != circ.inputs().len() {
            return Err(EvaluatorError::InputLength {
                expected: circ.inputs().len(),
                actual: inputs.len(),
            });
        }

        // Expand the buffer to fit the circuit
        if circ.feed_count() > self.buffer.len() {
            self.buffer.resize(circ.feed_count(), Default::default());
        }

        self.buffer[..inputs.len()].copy_from_slice(Mac::as_blocks(inputs));

        Ok(EncryptedGateConsumer::new(
            circ.gates().iter(),
            &mut self.buffer,
            circ.and_count(),
            circ.outputs(),
        ))
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
}

/// Consumer over the encrypted gates of a circuit.
pub struct EncryptedGateConsumer<'a, I: Iterator> {
    /// Cipher to use to evaluate the gates.
    cipher: &'static FixedKeyAes,
    /// Buffer for the active labels.
    labels: &'a mut [Block],
    /// Iterator over the gates.
    gates: I,
    /// Current gate id.
    gid: usize,
    /// Number of AND gates evaluated.
    counter: usize,
    /// Total number of AND gates in the circuit.
    and_count: usize,
    /// Range of the outputs in the buffer.
    outputs: Range<usize>,
    /// Whether the entire circuit has been evaluated.
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
    fn new(gates: I, labels: &'a mut [Block], and_count: usize, outputs: Range<usize>) -> Self {
        Self {
            cipher: &(*FIXED_KEY_AES),
            gates,
            labels,
            gid: 1,
            counter: 0,
            and_count,
            outputs,
            complete: false,
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
                    let z = and_gate(
                        self.cipher,
                        &x,
                        &y,
                        &encrypted_gate.gate,
                        &encrypted_gate.control_bits,
                        self.gid,
                    );
                    self.labels[node_z.id()] = z;

                    self.gid += 1;
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

        // If there were 0 AND gates, evaluate the "free" gates now.
        if !self.complete {
            self.next(Default::default());
        }

        Ok(EvaluatorOutput {
            outputs: Mac::from_blocks(self.labels[self.outputs.clone()].to_vec()),
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
                return;
            }
        }
    }

    /// Returns the encoded outputs of the circuit.
    pub fn finish(self) -> Result<EvaluatorOutput, EvaluatorError> {
        self.0.finish()
    }
}

// ============================================================================
// Single gate evaluation (internal)
// ============================================================================

/// Evaluate a single AND gate using the Three Halves scheme.
///
/// # Arguments
/// * `cipher` - The fixed-key AES cipher
/// * `a` - The active label for input A
/// * `b` - The active label for input B
/// * `gate` - The gate ciphertexts (G₀, G₁, G₂)
/// * `control_bits` - The compressed control bits from the garbler
/// * `gid` - The gate ID
///
/// # Returns
/// The output label C
#[inline]
fn and_gate(
    cipher: &FixedKeyAes,
    a: &Block,
    b: &Block,
    gate: &ThreeHalvesGate,
    control_bits: &ControlBits,
    gid: usize,
) -> Block {
    // Determine input combination (i, j) from color bits
    let i = a.lsb() as usize;
    let j = b.lsb() as usize;
    let ij = (i << 1) | j;

    // Compute the three hashes the evaluator has access to
    let tweak = Block::new((gid as u128).to_be_bytes());
    let mut hash_inputs = [*a, *b, *a ^ *b];
    cipher.rtccr_many(&[tweak; 3], &mut hash_inputs);

    let h_a = SlicedLabel::from_block(hash_inputs[0]);
    let h_b = SlicedLabel::from_block(hash_inputs[1]);
    let h_ab = SlicedLabel::from_block(hash_inputs[2]);

    // Slice the input labels
    let a_sliced = SlicedLabel::from_block(*a);
    let b_sliced = SlicedLabel::from_block(*b);

    // Expand compressed r_bar to full marginal (includes R_P for ODD mode)
    let marginal = expand_evaluator_marginal(control_bits, i, j);

    // Get the two rows for this input combination
    let row_l = 2 * ij;
    let row_r = 2 * ij + 1;

    // Compute contributions for each half
    let hash_contrib_l = compute_hash_contribution(row_l, &h_a, &h_b, &h_ab);
    let hash_contrib_r = compute_hash_contribution(row_r, &h_a, &h_b, &h_ab);

    let input_contrib_l = compute_input_contribution(&marginal, 0, &a_sliced, &b_sliced);
    let input_contrib_r = compute_input_contribution(&marginal, 1, &a_sliced, &b_sliced);

    let gate_contrib_l = compute_gate_contribution(row_l, gate);
    let gate_contrib_r = compute_gate_contribution(row_r, gate);

    // Combine all contributions
    let mut c_l = hash_contrib_l;
    xor_assign_8(&mut c_l, &input_contrib_l);
    xor_assign_8(&mut c_l, &gate_contrib_l);

    let mut c_r = hash_contrib_r;
    xor_assign_8(&mut c_r, &input_contrib_r);
    xor_assign_8(&mut c_r, &gate_contrib_r);

    SlicedLabel::new(c_l, c_r).to_block()
}

/// Expand evaluator's marginal from compressed control bits.
fn expand_evaluator_marginal(control_bits: &ControlBits, i: usize, j: usize) -> [[u8; 4]; 2] {
    let ij = (i << 1) | j;
    let r_bar_ij = control_bits.get(ij);

    let mut marginal = expand_marginal(&r_bar_ij);

    // Add R_P's marginal (ODD mode)
    let r_p_marginal = extract_r_p_marginal(i, j);
    for row in 0..2 {
        for col in 0..4 {
            marginal[row][col] ^= r_p_marginal[row][col];
        }
    }

    marginal
}

/// Compute hash contribution using precomputed bitmask.
///
/// Instead of checking 3 conditional branches against M matrix columns and
/// dynamically computing which hash to use, we use a precomputed bitmask.
/// The M matrix has a simple pattern: even rows always XOR h_a ⊕ h_ab,
/// odd rows always XOR h_b ⊕ h_ab.
fn compute_hash_contribution(
    row: usize,
    h_a: &SlicedLabel,
    h_b: &SlicedLabel,
    h_ab: &SlicedLabel,
) -> [u8; 8] {
    let mut result = [0u8; 8];
    let mask = HASH_CONTRIBUTION_MASKS[row];

    // Check each bit of the mask to determine which hash outputs to XOR
    if mask & 0b001 != 0 {
        xor_assign_8(&mut result, &h_a.left);
    }
    if mask & 0b010 != 0 {
        xor_assign_8(&mut result, &h_b.left);
    }
    if mask & 0b100 != 0 {
        xor_assign_8(&mut result, &h_ab.left);
    }

    result
}

/// Compute input contribution from expanded marginal.
fn compute_input_contribution(
    r_bar_expanded: &[[u8; 4]; 2],
    half: usize,
    a: &SlicedLabel,
    b: &SlicedLabel,
) -> [u8; 8] {
    let coeffs = r_bar_expanded[half];
    let mut result = [0u8; 8];

    if coeffs[0] == 1 {
        xor_assign_8(&mut result, &a.left);
    }
    if coeffs[1] == 1 {
        xor_assign_8(&mut result, &a.right);
    }
    if coeffs[2] == 1 {
        xor_assign_8(&mut result, &b.left);
    }
    if coeffs[3] == 1 {
        xor_assign_8(&mut result, &b.right);
    }

    result
}

/// Compute gate ciphertext contribution using precomputed bitmask.
///
/// Instead of checking 3 conditional branches against V matrix columns,
/// we use a precomputed bitmask to determine which gate ciphertexts (g0, g1,
/// g2) to XOR together for this row's evaluation equation.
fn compute_gate_contribution(row: usize, gate: &ThreeHalvesGate) -> [u8; 8] {
    let mut result = [0u8; 8];
    let mask = GATE_CONTRIBUTION_MASKS[row];

    // Check each bit of the mask to determine which components to XOR
    if mask & 0b001 != 0 {
        xor_assign_8(&mut result, &gate.g0);
    }
    if mask & 0b010 != 0 {
        xor_assign_8(&mut result, &gate.g1);
    }
    if mask & 0b100 != 0 {
        xor_assign_8(&mut result, &gate.g2);
    }

    result
}

/// Errors that can occur during garbled circuit evaluation.
#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum EvaluatorError {
    #[error("input length mismatch: expected {expected}, got {actual}")]
    InputLength { expected: usize, actual: usize },
    #[error("evaluator not finished")]
    NotFinished,
}

/// Output of the evaluator.
#[derive(Debug)]
pub struct EvaluatorOutput {
    /// Output MACs of the circuit.
    pub outputs: Vec<Mac>,
}

/// Evaluates multiple garbled circuits, potentially in parallel using rayon.
///
/// # Arguments
///
/// * `circs` - Vector of (circuit, input MACs, garbled circuit) tuples
///
/// # Returns
///
/// Vector of evaluation outputs (one per circuit)
pub fn evaluate_garbled_circuits(
    circs: Vec<(Arc<Circuit>, Vec<Mac>, super::GarbledCircuit)>,
) -> Result<Vec<EvaluatorOutput>, EvaluatorError> {
    cfg_if::cfg_if! {
        if #[cfg(feature = "rayon")] {
            use rayon::prelude::*;

            circs.into_par_iter().map(|(circ, inputs, garbled_circuit)| {
                let mut ev = Evaluator::with_capacity(circ.feed_count());
                let mut consumer = ev.evaluate(&circ, &inputs)?;
                for gate in garbled_circuit.gates {
                    consumer.next(gate);
                }
                consumer.finish()
            }).collect::<Result<Vec<_>, _>>()
        } else {
            let mut ev = Evaluator::default();
            let mut outputs = Vec::with_capacity(circs.len());
            for (circ, inputs, garbled_circuit) in circs {
                let mut consumer = ev.evaluate(&circ, &inputs)?;
                for gate in garbled_circuit.gates {
                    consumer.next(gate);
                }
                outputs.push(consumer.finish()?);
            }

            Ok(outputs)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mpz_circuits::CircuitBuilder;
    use mpz_core::Block;
    use mpz_memory_core::correlated::{Delta, Key};
    use rand::SeedableRng;
    use rand_chacha::ChaCha12Rng;

    use crate::three_halves::{Garbler, GarblerOutput};

    /// Test fixture containing pre-generated encrypted gates for a single AND
    /// gate.
    ///
    /// This fixture allows testing the evaluator in isolation without requiring
    /// a garbler instance.
    struct AndGateFixture {
        /// The encrypted gate (3 blocks: G₀, G₁, G₂)
        encrypted_gate: EncryptedGate,
        /// Input keys (0-labels)
        input_keys: Vec<Key>,
        /// Output 0-label
        output_label: Key,
        /// Delta for computing 1-label
        delta: Delta,
        /// The circuit being garbled
        circuit: Circuit,
    }

    impl AndGateFixture {
        /// Generate a fixture for a single AND gate using a fixed seed.
        ///
        /// This uses seed=12345 for reproducible test fixtures.
        fn generate() -> Self {
            let mut rng = ChaCha12Rng::seed_from_u64(12345);
            let delta = Delta::random(&mut rng);

            // Create single AND gate circuit
            let mut builder = CircuitBuilder::new();
            let a = builder.add_input();
            let b = builder.add_input();
            let out = builder.add_and_gate(a, b);
            builder.add_output(out);
            let circuit = builder.build().unwrap();

            let input_keys: Vec<Key> = (0..2)
                .map(|_| {
                    let block: Block = Block::random(&mut rng);
                    block.into()
                })
                .collect();

            // Garble the circuit
            let mut gb = Garbler::default();
            let mut gb_iter = gb.generate(&circuit, delta, &input_keys, &mut rng).unwrap();

            // Extract the single encrypted gate
            let encrypted_gate = gb_iter.next().expect("should have one gate");
            assert!(gb_iter.next().is_none(), "should only have one gate");

            let GarblerOutput {
                outputs: output_labels,
            } = gb_iter.finish().unwrap();

            Self {
                encrypted_gate,
                input_keys,
                output_label: output_labels[0],
                delta,
                circuit,
            }
        }
    }

    /// Unit test: Evaluator with pre-generated fixture for all AND gate inputs
    ///
    /// Tests all 4 input combinations: (0,0), (0,1), (1,0), (1,1)
    #[test]
    fn test_evaluate_and_gate_all_inputs() {
        let fixture = AndGateFixture::generate();

        // Test cases: (a_bit, b_bit, expected_output_bit)
        let test_cases = [
            (false, false, false), // AND(0,0) = 0
            (false, true, false),  // AND(0,1) = 0
            (true, false, false),  // AND(1,0) = 0
            (true, true, true),    // AND(1,1) = 1
        ];

        for (a_bit, b_bit, expected_output) in test_cases {
            // Select input MACs based on input bits
            // Key is 0-label, Key ⊕ Δ is 1-label
            let delta_block = *fixture.delta.as_block();
            let input_macs = vec![
                if a_bit {
                    Mac::from(*fixture.input_keys[0].as_block() ^ delta_block)
                } else {
                    Mac::from(*fixture.input_keys[0].as_block())
                },
                if b_bit {
                    Mac::from(*fixture.input_keys[1].as_block() ^ delta_block)
                } else {
                    Mac::from(*fixture.input_keys[1].as_block())
                },
            ];

            // Evaluate
            let mut ev = Evaluator::default();
            let mut ev_consumer = ev.evaluate(&fixture.circuit, &input_macs).unwrap();
            ev_consumer.next(fixture.encrypted_gate);

            let EvaluatorOutput { outputs } = ev_consumer.finish().unwrap();

            // Verify output: compute 1-label as 0-label XOR delta
            let false_mac = Mac::from(*fixture.output_label.as_block());
            let true_mac = Mac::from(*fixture.output_label.as_block() ^ *fixture.delta.as_block());
            let expected_mac = if expected_output { true_mac } else { false_mac };

            assert_eq!(
                outputs[0], expected_mac,
                "AND({},{}) should be {}",
                a_bit as u8, b_bit as u8, expected_output as u8
            );
        }
    }
}
