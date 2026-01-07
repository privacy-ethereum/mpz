//! Garbler for Three Halves Scheme
//!
//! This module implements the garbling function for circuits using the
//! Three Halves technique from Rosulek & Roy 2021.

use core::fmt;
use std::ops::Range;

use mpz_circuits::{Circuit, Gate};
use mpz_core::{
    Block,
    aes::{FIXED_KEY_AES, FixedKeyAes},
};
use mpz_memory_core::correlated::{Delta, Key};
use rand::{CryptoRng, Rng};

use super::{
    ControlBits, EncryptedGate, EncryptedGateBatch, ThreeHalvesGate,
    control::sample_r_odd,
    garbler_tables::{M_COLUMN_MASKS, R_COLUMN_MASKS},
    random_bits::RandomBitSource,
    slicing::SlicedLabel,
};

use crate::DEFAULT_BATCH_SIZE;

/// Garbler for Three Halves scheme.
#[derive(Debug, Default)]
pub struct Garbler {
    /// Wire labels W_k (color bit 0) for each wire.
    buffer: Vec<Block>,
}

impl Garbler {
    /// Returns an iterator over the encrypted gates of a circuit.
    ///
    /// # Arguments
    ///
    /// * `circ` - The circuit to garble.
    /// * `delta` - The delta value to use for garbling.
    /// * `inputs` - The input labels to the circuit.
    /// * `rng` - Random number generator for control matrix randomization.
    pub fn generate<'a, R: Rng + CryptoRng>(
        &'a mut self,
        circ: &'a Circuit,
        delta: Delta,
        inputs: &[Key],
        rng: &mut R,
    ) -> Result<EncryptedGateIter<'a, std::slice::Iter<'a, Gate>>, GarblerError> {
        if inputs.len() != circ.inputs().len() {
            return Err(GarblerError::InputLength {
                expected: circ.inputs().len(),
                actual: inputs.len(),
            });
        }

        // Expand the buffer to fit the circuit
        if circ.feed_count() > self.buffer.len() {
            self.buffer.resize(circ.feed_count(), Default::default());
        }

        // Initialize permute bits for all wires
        let mut permute_bits = vec![false; circ.feed_count()];

        // Pre-generate random bits for control matrix randomization (2 bits per AND
        // gate)
        let total_random_bits = 2 * circ.and_count();
        let random_bits = RandomBitSource::new(total_random_bits, rng);

        let delta_block = *delta.as_block();

        // For input wires: π = Key.lsb(), W_k = Key ⊕ (π·Δ)
        for (i, key) in inputs.iter().enumerate() {
            let key_block = *key.as_block();
            let pi = key_block.lsb();
            let w_k = if pi {
                key_block ^ delta_block
            } else {
                key_block
            };
            self.buffer[i] = w_k;
            permute_bits[i] = pi;
        }

        Ok(EncryptedGateIter::new(
            delta,
            circ.gates().iter(),
            &mut self.buffer,
            permute_bits,
            circ.and_count(),
            circ.outputs(),
            random_bits,
        ))
    }

    /// Returns an iterator over batched encrypted gates of a circuit.
    ///
    /// # Arguments
    ///
    /// * `circ` - The circuit to garble.
    /// * `delta` - The delta value to use for garbling.
    /// * `inputs` - The input labels to the circuit.
    /// * `rng` - Random number generator for control matrix randomization.
    pub fn generate_batched<'a, R: Rng + CryptoRng>(
        &'a mut self,
        circ: &'a Circuit,
        delta: Delta,
        inputs: &[Key],
        rng: &mut R,
    ) -> Result<EncryptedGateBatchIter<'a, std::slice::Iter<'a, Gate>>, GarblerError> {
        self.generate(circ, delta, inputs, rng)
            .map(EncryptedGateBatchIter)
    }
}

/// Errors that can occur during garbled circuit generation.
#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum GarblerError {
    #[error("input length mismatch: expected {expected}, got {actual}")]
    InputLength { expected: usize, actual: usize },
    #[error("garbler not finished")]
    NotFinished,
}

/// Output of the garbler.
#[derive(Debug)]
pub struct GarblerOutput {
    /// Output labels for each output wire (0-label only).
    pub outputs: Vec<Key>,
}

/// Iterator over encrypted gates of a garbled circuit.
pub struct EncryptedGateIter<'a, I> {
    /// Cipher to use to encrypt the gates.
    cipher: &'static FixedKeyAes,
    /// Global offset.
    delta: Delta,
    /// Wire labels W_k (color bit 0) for each wire.
    labels: &'a mut [Block],
    /// Buffer for the point-and-permute bits (tracked separately from labels).
    permute_bits: Vec<bool>,
    /// Iterator over the gates.
    gates: I,
    /// Current gate id.
    gid: usize,
    /// Number of AND gates generated.
    counter: usize,
    /// Number of AND gates in the circuit.
    and_count: usize,
    /// Range of the outputs in the buffer.
    outputs: Range<usize>,
    /// Whether the entire circuit has been garbled.
    complete: bool,
    /// Pre-generated random bits for control matrix randomization.
    random_bits: RandomBitSource,
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
        labels: &'a mut [Block],
        permute_bits: Vec<bool>,
        and_count: usize,
        outputs: Range<usize>,
        random_bits: RandomBitSource,
    ) -> Self {
        Self {
            cipher: &(*FIXED_KEY_AES),
            delta,
            gates,
            labels,
            permute_bits,
            gid: 1,
            counter: 0,
            and_count,
            outputs,
            complete: false,
            random_bits,
        }
    }

    /// Returns `true` if the garbler has more encrypted gates to generate.
    #[inline]
    pub fn has_gates(&self) -> bool {
        self.counter != self.and_count
    }

    /// Returns the encoded outputs of the circuit.
    pub fn finish(mut self) -> Result<GarblerOutput, GarblerError> {
        if self.has_gates() {
            return Err(GarblerError::NotFinished);
        }

        // Finish computing any "free" gates.
        if !self.complete {
            assert_eq!(self.next(), None);
        }

        let delta_block = *self.delta.as_block();

        // Return output keys.
        let output_labels: Vec<Key> = self
            .outputs
            .clone()
            .map(|i| {
                let w_k = self.labels[i];
                let pi_k = self.permute_bits[i];
                // 0-label = W_k ⊕ (π_k · Δ)
                if pi_k {
                    (w_k ^ delta_block).into()
                } else {
                    w_k.into()
                }
            })
            .collect();

        Ok(GarblerOutput {
            outputs: output_labels,
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
                    // Free XOR: output label = XOR of input labels
                    let x_0 = self.labels[node_x.id()];
                    let y_0 = self.labels[node_y.id()];
                    self.labels[node_z.id()] = x_0 ^ y_0;
                    // Permute bit of output = XOR of input permute bits
                    self.permute_bits[node_z.id()] =
                        self.permute_bits[node_x.id()] ^ self.permute_bits[node_y.id()];
                }
                Gate::And {
                    x: node_x,
                    y: node_y,
                    z: node_z,
                } => {
                    let x_0 = self.labels[node_x.id()];
                    let y_0 = self.labels[node_y.id()];
                    let pi_a = self.permute_bits[node_x.id()];
                    let pi_b = self.permute_bits[node_y.id()];

                    // Get pre-generated random bits for this AND gate
                    let rand_bits = self.random_bits.next_two_bits();

                    let (c, pi_c, encrypted_gate) = and_gate(
                        self.cipher,
                        &x_0,
                        &y_0,
                        pi_a,
                        pi_b,
                        &self.delta,
                        self.gid,
                        rand_bits,
                    );
                    // c already has LSB = 0 (adjusted in and_gate)
                    self.labels[node_z.id()] = c;
                    self.permute_bits[node_z.id()] = pi_c;

                    self.gid += 1;
                    self.counter += 1;

                    // If we have generated all AND gates, compute remaining free gates.
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
                    // INV: W_k stays the same, but the permute bit flips
                    let x_0 = self.labels[node_x.id()];
                    self.labels[node_z.id()] = x_0;
                    self.permute_bits[node_z.id()] = !self.permute_bits[node_x.id()];
                }
                Gate::Id {
                    x: node_x,
                    z: node_z,
                } => {
                    let x_0 = self.labels[node_x.id()];
                    self.labels[node_z.id()] = x_0;
                    self.permute_bits[node_z.id()] = self.permute_bits[node_x.id()];
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

    /// Returns the encoded outputs of the circuit.
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

// ============================================================================
// Single gate garbling (internal)
// ============================================================================

/// Garble a single AND gate using the Three Halves scheme.
///
/// # Arguments
/// * `cipher` - The fixed-key AES cipher
/// * `w_a` - Wire label W_a (color bit 0)
/// * `w_b` - Wire label W_b (color bit 0)
/// * `pi_a` - The permute bit for input A
/// * `pi_b` - The permute bit for input B
/// * `delta` - The global offset
/// * `gid` - The gate ID
/// * `rand_bits` - Pre-generated random bits for control matrix
///
/// # Returns
/// * `(W_c, pi_c, gate)` where W_c has LSB = 0 and pi_c is the output permute
///   bit
fn and_gate(
    cipher: &FixedKeyAes,
    w_a: &Block,
    w_b: &Block,
    pi_a: bool,
    pi_b: bool,
    delta: &Delta,
    gid: usize,
    rand_bits: [bool; 2],
) -> (Block, bool, EncryptedGate) {
    let delta_block = *delta.as_block();

    // Compute the 6 hash values from W_a, W_b, and Δ
    let hashes = compute_hashes(cipher, *w_a, *w_b, delta_block, gid);

    // Slice the input labels
    let a0_sliced = SlicedLabel::from_block(*w_a);
    let b0_sliced = SlicedLabel::from_block(*w_b);
    let delta_sliced = SlicedLabel::from_block(delta_block);

    // Sample the randomized control matrix R for AND gate (ODD mode)
    //
    // The permute bits define the relationship between color bits and logical
    // values:
    // - Color bit i corresponds to logical value (i ⊕ π_a) for input A
    // - Color bit j corresponds to logical value (j ⊕ π_b) for input B
    //
    // Compute the R matrix index
    let r_index = (pi_a as usize) << 3
        | (pi_b as usize) << 2
        | (rand_bits[0] as usize) << 1
        | rand_bits[1] as usize;
    let r_bar = sample_r_odd(pi_a, pi_b, rand_bits);

    // Compute M · H⃗ (hash contribution)
    let m_times_h = apply_m_to_hashes(&hashes);

    // Compute R · [A₀; B₀; Δ] (input contribution)
    let r_times_input = apply_r_to_inputs(r_index, &a0_sliced, &b0_sliced, &delta_sliced);

    // Compute RHS = M·H ⊕ R·input
    let mut rhs = [[0u8; 8]; 8];
    for i in 0..8 {
        rhs[i] = m_times_h[i];
        xor_assign_8(&mut rhs[i], &r_times_input[i]);
    }

    // Solve for [C; G⃗]
    let output = solve_for_output(&rhs, &delta_sliced, pi_a, pi_b);

    // Extract output label C from the linear algebra
    let c = SlicedLabel::new(output[0], output[1]).to_block();

    // Per the paper (Section 5.3):
    // π_c := lsb(C)
    // W_c := C ⊕ π_c·Δ
    // This ensures W_c has LSB = 0
    let pi_c = c.lsb();
    let w_c = if pi_c { c ^ delta_block } else { c };

    let gate = ThreeHalvesGate::new(output[2], output[3], output[4]);
    let control_bits = ControlBits::new(r_bar);

    (w_c, pi_c, EncryptedGate::new(gate, control_bits))
}

/// Compute the 6 hash values needed for garbling.
fn compute_hashes(
    cipher: &FixedKeyAes,
    a0: Block,
    b0: Block,
    delta: Block,
    gid: usize,
) -> [SlicedLabel; 6] {
    let a1 = a0 ^ delta;
    let b1 = b0 ^ delta;

    let tweak = Block::new((gid as u128).to_be_bytes());
    let mut blocks = [a0, a1, b0, b1, a0 ^ b0, a0 ^ b1];
    cipher.rtccr_many(&[tweak; 6], &mut blocks);

    [
        SlicedLabel::from_block(blocks[0]),
        SlicedLabel::from_block(blocks[1]),
        SlicedLabel::from_block(blocks[2]),
        SlicedLabel::from_block(blocks[3]),
        SlicedLabel::from_block(blocks[4]),
        SlicedLabel::from_block(blocks[5]),
    ]
}

/// Apply matrix M to hash vector using precomputed branchless operations.
///
/// Uses M_COLUMN_MASKS from garbler_tables for branchless matrix
/// multiplication.
///
/// Returns M × H⃗ as 8×8 byte array, where each row is a 64-bit value.
#[inline]
fn apply_m_to_hashes(hashes: &[SlicedLabel; 6]) -> [[u8; 8]; 8] {
    // Pack hash left-halves as u64 for efficient XOR operations
    let inputs: [u64; 6] = [
        u64::from_le_bytes(hashes[0].left),
        u64::from_le_bytes(hashes[1].left),
        u64::from_le_bytes(hashes[2].left),
        u64::from_le_bytes(hashes[3].left),
        u64::from_le_bytes(hashes[4].left),
        u64::from_le_bytes(hashes[5].left),
    ];

    let mut result = [[0u8; 8]; 8];

    for row in 0..8 {
        let m = M_COLUMN_MASKS[row] as u64;

        // Branchless expansion: convert each bit to a full u64 mask
        // ((m >> bit) & 1) is 0 or 1
        // .wrapping_neg() converts: 0 → 0, 1 → 0xFFFFFFFFFFFFFFFF
        let row_result = (inputs[0] & ((m >> 0) & 1).wrapping_neg())
            ^ (inputs[1] & ((m >> 1) & 1).wrapping_neg())
            ^ (inputs[2] & ((m >> 2) & 1).wrapping_neg())
            ^ (inputs[3] & ((m >> 3) & 1).wrapping_neg())
            ^ (inputs[4] & ((m >> 4) & 1).wrapping_neg())
            ^ (inputs[5] & ((m >> 5) & 1).wrapping_neg());

        result[row] = row_result.to_le_bytes();
    }

    result
}

/// Apply control matrix R to input labels using precomputed branchless
/// operations.
///
/// Uses R_COLUMN_MASKS[r_index] from garbler_tables for branchless matrix
/// multiplication.
///
/// Returns R × [A₀; B₀; Δ] as 8×8 byte array, where each row is a 64-bit value.
#[inline]
fn apply_r_to_inputs(
    r_index: usize,
    a0: &SlicedLabel,
    b0: &SlicedLabel,
    delta: &SlicedLabel,
) -> [[u8; 8]; 8] {
    // Pack inputs as u64 for efficient XOR operations (instead of byte-by-byte)
    let inputs: [u64; 6] = [
        u64::from_le_bytes(a0.left),
        u64::from_le_bytes(a0.right),
        u64::from_le_bytes(b0.left),
        u64::from_le_bytes(b0.right),
        u64::from_le_bytes(delta.left),
        u64::from_le_bytes(delta.right),
    ];

    let masks = &R_COLUMN_MASKS[r_index];
    let mut result = [[0u8; 8]; 8];

    for row in 0..8 {
        let m = masks[row] as u64;

        // Branchless expansion: convert each bit to a full u64 mask
        // ((m >> bit) & 1) is 0 or 1
        // .wrapping_neg() converts: 0 → 0, 1 → 0xFFFFFFFFFFFFFFFF
        let row_result = (inputs[0] & ((m >> 0) & 1).wrapping_neg())
            ^ (inputs[1] & ((m >> 1) & 1).wrapping_neg())
            ^ (inputs[2] & ((m >> 2) & 1).wrapping_neg())
            ^ (inputs[3] & ((m >> 3) & 1).wrapping_neg())
            ^ (inputs[4] & ((m >> 4) & 1).wrapping_neg())
            ^ (inputs[5] & ((m >> 5) & 1).wrapping_neg());

        result[row] = row_result.to_le_bytes();
    }

    result
}

/// Solve for [C_L, C_R, G₀, G₁, G₂] from RHS.
fn solve_for_output(
    rhs: &[[u8; 8]; 8],
    delta: &SlicedLabel,
    pi_a: bool,
    pi_b: bool,
) -> [[u8; 8]; 5] {
    let mut rhs_adjusted = *rhs;

    // For AND gates, the identity block (true output) is at position (!pi_a, !pi_b)
    let true_i = !pi_a as usize;
    let true_j = !pi_b as usize;
    let true_ij = (true_i << 1) | true_j;
    let row_l = 2 * true_ij;
    let row_r = 2 * true_ij + 1;
    xor_assign_8(&mut rhs_adjusted[row_l], &delta.left);
    xor_assign_8(&mut rhs_adjusted[row_r], &delta.right);

    let mut result = [[0u8; 8]; 5];

    // C_L = RHS[0]
    result[0] = rhs_adjusted[0];
    // C_R = RHS[1]
    result[1] = rhs_adjusted[1];
    // G₀ = RHS[0] ⊕ RHS[1] ⊕ RHS[4] ⊕ RHS[5]
    for k in 0..8 {
        result[2][k] =
            rhs_adjusted[0][k] ^ rhs_adjusted[1][k] ^ rhs_adjusted[4][k] ^ rhs_adjusted[5][k];
    }
    // G₁ = RHS[0] ⊕ RHS[1] ⊕ RHS[2] ⊕ RHS[3]
    for k in 0..8 {
        result[3][k] =
            rhs_adjusted[0][k] ^ rhs_adjusted[1][k] ^ rhs_adjusted[2][k] ^ rhs_adjusted[3][k];
    }
    // G₂ = RHS[4] ⊕ RHS[6]
    for k in 0..8 {
        result[4][k] = rhs_adjusted[4][k] ^ rhs_adjusted[6][k];
    }

    result
}

/// XOR-assign two 8-byte arrays.
#[inline]
pub(crate) fn xor_assign_8(a: &mut [u8; 8], b: &[u8; 8]) {
    for i in 0..8 {
        a[i] ^= b[i];
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mpz_circuits::circuits::xor;
    use mpz_core::aes::FIXED_KEY_AES;
    use rand::SeedableRng;
    use rand_chacha::ChaCha12Rng;

    #[test]
    fn test_garbling_deterministic() {
        let cipher = &(*FIXED_KEY_AES);
        let mut rng = ChaCha12Rng::seed_from_u64(42);

        let mut a0 = Block::random(&mut rng);
        let mut b0 = Block::random(&mut rng);
        let mut delta = Block::random(&mut rng);
        a0.set_lsb(false);
        b0.set_lsb(false);
        delta.set_lsb(true);

        // Use the same random bits for both calls
        let rand_bits = [true, false];

        // Test with permute bits both false (since labels have LSB=0)
        let (z1, pi_z1, gate1) = and_gate(
            cipher,
            &a0,
            &b0,
            false,
            false,
            &Delta::new(delta),
            1,
            rand_bits,
        );
        let (z2, pi_z2, gate2) = and_gate(
            cipher,
            &a0,
            &b0,
            false,
            false,
            &Delta::new(delta),
            1,
            rand_bits,
        );

        assert_eq!(z1, z2);
        assert_eq!(pi_z1, pi_z2);
        assert_eq!(gate1, gate2);
    }

    #[test]
    fn test_garble_xor_circuit() {
        let mut rng = ChaCha12Rng::seed_from_u64(42);
        let circ = xor(8);

        let mut delta = Block::random(&mut rng);
        delta.set_lsb(true);
        let delta = Delta::new(delta);

        let input_keys: Vec<Key> = (0..circ.inputs().len())
            .map(|_| {
                let block: Block = rng.random();
                block.into()
            })
            .collect();

        let mut gb = Garbler::default();
        let iter = gb.generate(&circ, delta, &input_keys, &mut rng).unwrap();

        // XOR circuit has no AND gates
        assert!(!iter.has_gates());

        let output = iter.finish().unwrap();
        assert_eq!(output.outputs.len(), circ.outputs().len());
    }
}
