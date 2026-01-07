//! Precomputed Lookup Tables for Garbler Optimizations
//!
//! This module contains precomputed bitmask tables used by the garbler for
//! branchless matrix application. These tables eliminate conditional branches
//! that would otherwise cause significant performance overhead.

// ============================================================================
// Precomputed M Matrix Application
// ============================================================================
//
// # Why This Optimization Exists
//
// Similar to `apply_r_to_inputs`, the naive `apply_m_to_hashes` function has
// 48 conditional branches (8 rows × 6 columns). While M is a fixed matrix
// (unlike R which has 16 variants), we can still eliminate branches using
// precomputed bitmasks.
//
// # The M Matrix (from Paper Page 10, Table 2)
//
// M specifies which hash values to XOR for each evaluation equation:
//
// ```text
// M = [ 1 0 0 0 1 0 ]  <- (0,0) left:  H(A₀) ⊕ H(A₀⊕B₀)
//     [ 0 0 1 0 1 0 ]  <- (0,0) right: H(B₀) ⊕ H(A₀⊕B₀)
//     [ 1 0 0 0 0 1 ]  <- (0,1) left:  H(A₀) ⊕ H(A₀⊕B₁)
//     [ 0 0 0 1 0 1 ]  <- (0,1) right: H(B₁) ⊕ H(A₀⊕B₁)
//     [ 0 1 0 0 0 1 ]  <- (1,0) left:  H(A₁) ⊕ H(A₀⊕B₁)
//     [ 0 0 1 0 0 1 ]  <- (1,0) right: H(B₀) ⊕ H(A₀⊕B₁)
//     [ 0 1 0 0 1 0 ]  <- (1,1) left:  H(A₁) ⊕ H(A₀⊕B₀)
//     [ 0 0 0 1 1 0 ]  <- (1,1) right: H(B₁) ⊕ H(A₀⊕B₀)
// ```
//
// Columns: [H(A₀), H(A₁), H(B₀), H(B₁), H(A₀⊕B₀), H(A₀⊕B₁)]
//
// # Bitmask Encoding
//
// Each u8 bitmask has bits [0..5] indicating which columns to XOR:
//   bit 0 = H(A₀)
//   bit 1 = H(A₁)
//   bit 2 = H(B₀)
//   bit 3 = H(B₁)
//   bit 4 = H(A₀⊕B₀)
//   bit 5 = H(A₀⊕B₁)

/// Precomputed column bitmasks for the M matrix.
///
/// Since M is a fixed constant matrix, we only need one set of 8 bitmasks
/// (one per row), unlike R which has 16 variants.
///
/// Generated from the M matrix in matrices.rs at compile time.
pub(super) const M_COLUMN_MASKS: [u8; 8] = {
    // Convert M matrix rows to bitmasks
    // M[row][col] == 1 means bit `col` is set in the mask
    //
    // M = [[1,0,0,0,1,0], [0,0,1,0,1,0], [1,0,0,0,0,1], [0,0,0,1,0,1],
    //      [0,1,0,0,0,1], [0,0,1,0,0,1], [0,1,0,0,1,0], [0,0,0,1,1,0]]
    [
        0b_010001, // Row 0: cols 0,4 → bits 0,4 = 1 + 16 = 17 = 0x11
        0b_010100, // Row 1: cols 2,4 → bits 2,4 = 4 + 16 = 20 = 0x14
        0b_100001, // Row 2: cols 0,5 → bits 0,5 = 1 + 32 = 33 = 0x21
        0b_101000, // Row 3: cols 3,5 → bits 3,5 = 8 + 32 = 40 = 0x28
        0b_100010, // Row 4: cols 1,5 → bits 1,5 = 2 + 32 = 34 = 0x22
        0b_100100, // Row 5: cols 2,5 → bits 2,5 = 4 + 32 = 36 = 0x24
        0b_010010, // Row 6: cols 1,4 → bits 1,4 = 2 + 16 = 18 = 0x12
        0b_011000, // Row 7: cols 3,4 → bits 3,4 = 8 + 16 = 24 = 0x18
    ]
};

// ============================================================================
// Precomputed R Matrix Application
// ============================================================================
//
// # Why This Optimization Exists
//
// The naive `apply_r_to_inputs` function performs an 8×6 matrix-vector multiply
// where each entry is a conditional XOR:
//
//   for row in 0..8:
//       for col in 0..6:
//           if R[row][col]:
//               result[row] ^= inputs[col]
//
// This results in 48 conditional branches per AND gate. With millions of gates,
// branch mispredictions become a significant bottleneck (~33% of garbling time
// in profiling).
//
// # The Optimization
//
// The control matrix R comes from `sample_r_odd`, which returns one of only
// **16 possible matrices** (4 permute bit combinations × 4 random bit
// combinations). Instead of runtime conditionals, we:
//
// 1. Precompute a bitmask for each row of each R variant, indicating which
//    columns (inputs) to XOR together
// 2. At runtime, use branchless masking: `result ^= input & mask`
//
// This eliminates all branches and reduces the operation to pure XOR/AND.
//
// # Bitmask Format
//
// Each u8 bitmask has bits [0..5] corresponding to the 6 input columns:
//   bit 0 = A₀_L (a0.left)
//   bit 1 = A₀_R (a0.right)
//   bit 2 = B₀_L (b0.left)
//   bit 3 = B₀_R (b0.right)
//   bit 4 = Δ_L  (delta.left)
//   bit 5 = Δ_R  (delta.right)
//
// # Table Index
//
// Index = (pi_a << 3) | (pi_b << 2) | (r0 << 1) | r1
// Same indexing as sample_r_odd in control.rs.

/// Precomputed column bitmasks for each R matrix variant.
///
/// `R_COLUMN_MASKS[variant][row]` is a u8 where bit `col` indicates whether
/// R[row][col] is true (i.e., whether to XOR input[col] into result[row]).
///
/// Generated from the 16 possible R matrices from sample_r_odd - each entry is
/// the same R matrix but encoded as bitmasks for branchless application.
pub(super) const R_COLUMN_MASKS: [[u8; 8]; 16] = {
    // Helper to convert a u8 row [c0,c1,c2,c3,c4,c5] to bitmask
    const fn row_to_mask(row: [u8; 6]) -> u8 {
        row[0] | (row[1] << 1) | (row[2] << 2) | (row[3] << 3) | (row[4] << 4) | (row[5] << 5)
    }

    // Helper to convert full 8×6 R matrix to 8 bitmasks
    const fn matrix_to_masks(r: [[u8; 6]; 8]) -> [u8; 8] {
        [
            row_to_mask(r[0]),
            row_to_mask(r[1]),
            row_to_mask(r[2]),
            row_to_mask(r[3]),
            row_to_mask(r[4]),
            row_to_mask(r[5]),
            row_to_mask(r[6]),
            row_to_mask(r[7]),
        ]
    }

    // These are the 16 possible R matrices from sample_r_odd (control.rs),
    // precomputed and converted to bitmask form at compile time for branchless
    // application.
    [
        // Index 0: pi_a=0, pi_b=0, r0=0, r1=0
        matrix_to_masks([
            [0, 0, 1, 0, 0, 0],
            [0, 1, 0, 0, 0, 0],
            [1, 0, 1, 1, 1, 1],
            [0, 1, 1, 1, 1, 1],
            [1, 1, 1, 0, 1, 1],
            [1, 1, 0, 1, 1, 1],
            [0, 1, 1, 1, 1, 0],
            [1, 1, 1, 0, 0, 1],
        ]),
        // Index 1: pi_a=0, pi_b=0, r0=0, r1=1
        matrix_to_masks([
            [1, 0, 1, 1, 0, 0],
            [0, 0, 1, 1, 0, 0],
            [0, 0, 1, 0, 1, 0],
            [0, 0, 0, 0, 0, 0],
            [0, 1, 1, 1, 0, 1],
            [1, 0, 1, 0, 1, 0],
            [1, 1, 1, 0, 0, 1],
            [1, 0, 0, 1, 1, 1],
        ]),
        // Index 2: pi_a=0, pi_b=0, r0=1, r1=0
        matrix_to_masks([
            [1, 1, 0, 0, 0, 0],
            [1, 1, 0, 1, 0, 0],
            [0, 1, 0, 1, 0, 1],
            [1, 1, 1, 0, 1, 0],
            [0, 0, 0, 0, 0, 0],
            [0, 1, 0, 0, 0, 1],
            [1, 0, 0, 1, 1, 1],
            [0, 1, 1, 1, 1, 0],
        ]),
        // Index 3: pi_a=0, pi_b=0, r0=1, r1=1
        matrix_to_masks([
            [0, 1, 0, 1, 0, 0],
            [1, 0, 1, 0, 0, 0],
            [1, 1, 0, 0, 0, 0],
            [1, 0, 0, 1, 0, 1],
            [1, 0, 0, 1, 1, 0],
            [0, 0, 1, 1, 0, 0],
            [0, 0, 0, 0, 0, 0],
            [0, 0, 0, 0, 0, 0],
        ]),
        // Index 4: pi_a=0, pi_b=1, r0=0, r1=0
        matrix_to_masks([
            [0, 0, 1, 0, 0, 0],
            [0, 1, 0, 0, 0, 0],
            [0, 1, 0, 1, 0, 1],
            [1, 1, 1, 0, 1, 0],
            [1, 0, 0, 1, 1, 0],
            [0, 0, 1, 1, 0, 0],
            [1, 1, 1, 0, 0, 1],
            [1, 0, 0, 1, 1, 1],
        ]),
        // Index 5: pi_a=0, pi_b=1, r0=0, r1=1
        matrix_to_masks([
            [1, 0, 1, 1, 0, 0],
            [0, 0, 1, 1, 0, 0],
            [1, 1, 0, 0, 0, 0],
            [1, 0, 0, 1, 0, 1],
            [0, 0, 0, 0, 0, 0],
            [0, 1, 0, 0, 0, 1],
            [0, 1, 1, 1, 1, 0],
            [1, 1, 1, 0, 0, 1],
        ]),
        // Index 6: pi_a=0, pi_b=1, r0=1, r1=0
        matrix_to_masks([
            [1, 1, 0, 0, 0, 0],
            [1, 1, 0, 1, 0, 0],
            [1, 0, 1, 1, 1, 1],
            [0, 1, 1, 1, 1, 1],
            [0, 1, 1, 1, 0, 1],
            [1, 0, 1, 0, 1, 0],
            [0, 0, 0, 0, 0, 0],
            [0, 0, 0, 0, 0, 0],
        ]),
        // Index 7: pi_a=0, pi_b=1, r0=1, r1=1
        matrix_to_masks([
            [0, 1, 0, 1, 0, 0],
            [1, 0, 1, 0, 0, 0],
            [0, 0, 1, 0, 1, 0],
            [0, 0, 0, 0, 0, 0],
            [1, 1, 1, 0, 1, 1],
            [1, 1, 0, 1, 1, 1],
            [1, 0, 0, 1, 1, 1],
            [0, 1, 1, 1, 1, 0],
        ]),
        // Index 8: pi_a=1, pi_b=0, r0=0, r1=0
        matrix_to_masks([
            [0, 0, 1, 0, 0, 0],
            [0, 1, 0, 0, 0, 0],
            [1, 1, 0, 0, 0, 0],
            [1, 0, 0, 1, 0, 1],
            [0, 1, 1, 1, 0, 1],
            [1, 0, 1, 0, 1, 0],
            [1, 0, 0, 1, 1, 1],
            [0, 1, 1, 1, 1, 0],
        ]),
        // Index 9: pi_a=1, pi_b=0, r0=0, r1=1
        matrix_to_masks([
            [1, 0, 1, 1, 0, 0],
            [0, 0, 1, 1, 0, 0],
            [0, 1, 0, 1, 0, 1],
            [1, 1, 1, 0, 1, 0],
            [1, 1, 1, 0, 1, 1],
            [1, 1, 0, 1, 1, 1],
            [0, 0, 0, 0, 0, 0],
            [0, 0, 0, 0, 0, 0],
        ]),
        // Index 10: pi_a=1, pi_b=0, r0=1, r1=0
        matrix_to_masks([
            [1, 1, 0, 0, 0, 0],
            [1, 1, 0, 1, 0, 0],
            [0, 0, 1, 0, 1, 0],
            [0, 0, 0, 0, 0, 0],
            [1, 0, 0, 1, 1, 0],
            [0, 0, 1, 1, 0, 0],
            [0, 1, 1, 1, 1, 0],
            [1, 1, 1, 0, 0, 1],
        ]),
        // Index 11: pi_a=1, pi_b=0, r0=1, r1=1
        matrix_to_masks([
            [0, 1, 0, 1, 0, 0],
            [1, 0, 1, 0, 0, 0],
            [1, 0, 1, 1, 1, 1],
            [0, 1, 1, 1, 1, 1],
            [0, 0, 0, 0, 0, 0],
            [0, 1, 0, 0, 0, 1],
            [1, 1, 1, 0, 0, 1],
            [1, 0, 0, 1, 1, 1],
        ]),
        // Index 12: pi_a=1, pi_b=1, r0=0, r1=0
        matrix_to_masks([
            [0, 0, 1, 0, 0, 0],
            [0, 1, 0, 0, 0, 0],
            [0, 0, 1, 0, 1, 0],
            [0, 0, 0, 0, 0, 0],
            [0, 0, 0, 0, 0, 0],
            [0, 1, 0, 0, 0, 1],
            [0, 0, 0, 0, 0, 0],
            [0, 0, 0, 0, 0, 0],
        ]),
        // Index 13: pi_a=1, pi_b=1, r0=0, r1=1
        matrix_to_masks([
            [1, 0, 1, 1, 0, 0],
            [0, 0, 1, 1, 0, 0],
            [1, 0, 1, 1, 1, 1],
            [0, 1, 1, 1, 1, 1],
            [1, 0, 0, 1, 1, 0],
            [0, 0, 1, 1, 0, 0],
            [1, 0, 0, 1, 1, 1],
            [0, 1, 1, 1, 1, 0],
        ]),
        // Index 14: pi_a=1, pi_b=1, r0=1, r1=0
        matrix_to_masks([
            [1, 1, 0, 0, 0, 0],
            [1, 1, 0, 1, 0, 0],
            [1, 1, 0, 0, 0, 0],
            [1, 0, 0, 1, 0, 1],
            [1, 1, 1, 0, 1, 1],
            [1, 1, 0, 1, 1, 1],
            [1, 1, 1, 0, 0, 1],
            [1, 0, 0, 1, 1, 1],
        ]),
        // Index 15: pi_a=1, pi_b=1, r0=1, r1=1
        matrix_to_masks([
            [0, 1, 0, 1, 0, 0],
            [1, 0, 1, 0, 0, 0],
            [0, 1, 0, 1, 0, 1],
            [1, 1, 1, 0, 1, 0],
            [0, 1, 1, 1, 0, 1],
            [1, 0, 1, 0, 1, 0],
            [0, 1, 1, 1, 1, 0],
            [1, 1, 1, 0, 0, 1],
        ]),
    ]
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::three_halves::{matrices::M, slicing::SlicedLabel};
    use mpz_core::Block;
    use rand::SeedableRng;
    use rand_chacha::ChaCha12Rng;

    /// XOR assign 8 bytes at a time
    fn xor_assign_8(dst: &mut [u8; 8], src: &[u8; 8]) {
        for i in 0..8 {
            dst[i] ^= src[i];
        }
    }

    /// Verification tests for precomputed lookup tables.
    ///
    /// These verify that optimized LUTs match their specifications:
    /// - R_COLUMN_MASKS: Precomputed column masks for R matrix application
    /// - M_COLUMN_MASKS: Precomputed column masks for M matrix application
    ///
    /// These tests only need to run once to verify correctness after changes.
    ///
    /// Run with: `cargo test garbler_tables::tests::table_verification --
    /// --ignored`
    mod table_verification {
        use super::*;
        use crate::three_halves::control::{
            R_P, sample_r_odd,
            tests::table_verification::{R_A, R_B, R_DOLLAR_BASIS_0, R_DOLLAR_BASIS_1},
        };

        /// Sample control matrix R for ODD mode gates (test version that
        /// returns R).
        ///
        /// Computes R dynamically using the formula:
        /// R = r0·R$_BASIS_0 ⊕ r1·R$_BASIS_1 ⊕ a·R_A ⊕ b·R_B ⊕ R_P
        fn sample_r_odd_with_r(
            pi_a: bool,
            pi_b: bool,
            rand_bits: [bool; 2],
        ) -> ([[u8; 6]; 8], [[u8; 2]; 4]) {
            let (a, b) = (!pi_a, !pi_b);
            let r0 = rand_bits[0] as u8;
            let r1 = rand_bits[1] as u8;

            let mut r = [[0u8; 6]; 8];
            for i in 0..8 {
                for j in 0..6 {
                    r[i][j] = (r0 * R_DOLLAR_BASIS_0[i][j])
                        ^ (r1 * R_DOLLAR_BASIS_1[i][j])
                        ^ (a as u8 * R_A[i][j])
                        ^ (b as u8 * R_B[i][j])
                        ^ R_P[i][j];
                }
            }

            let r_bar = sample_r_odd(pi_a, pi_b, rand_bits);
            (r, r_bar)
        }

        /// Naive implementation of apply_r_to_inputs for testing
        fn apply_r_to_inputs_naive(
            r: &[[u8; 6]; 8],
            a0: &SlicedLabel,
            b0: &SlicedLabel,
            delta: &SlicedLabel,
        ) -> [[u8; 8]; 8] {
            let inputs: [[u8; 8]; 6] = [
                a0.left,
                a0.right,
                b0.left,
                b0.right,
                delta.left,
                delta.right,
            ];

            let mut result = [[0u8; 8]; 8];
            for row in 0..8 {
                for col in 0..6 {
                    if r[row][col] != 0 {
                        xor_assign_8(&mut result[row], &inputs[col]);
                    }
                }
            }
            result
        }

        /// Apply R matrix using precomputed masks (production implementation
        /// replica)
        fn apply_r_to_inputs_fast(
            r_index: usize,
            a0: &SlicedLabel,
            b0: &SlicedLabel,
            delta: &SlicedLabel,
        ) -> [[u8; 8]; 8] {
            let inputs: [[u8; 8]; 6] = [
                a0.left,
                a0.right,
                b0.left,
                b0.right,
                delta.left,
                delta.right,
            ];

            let mut result = [[0u8; 8]; 8];
            let masks = R_COLUMN_MASKS[r_index];

            for row in 0..8 {
                let mask = masks[row];
                for col in 0..6 {
                    let active = (mask >> col) & 1;
                    let masked_input = inputs[col].map(|b| b & active.wrapping_neg());
                    xor_assign_8(&mut result[row], &masked_input);
                }
            }
            result
        }

        /// Naive implementation of apply_m_to_hashes for testing
        fn apply_m_to_hashes_naive(hashes: &[SlicedLabel; 6]) -> [[u8; 8]; 8] {
            let mut result = [[0u8; 8]; 8];
            for row in 0..8 {
                for col in 0..6 {
                    if M[row][col] == 1 {
                        xor_assign_8(&mut result[row], &hashes[col].left);
                    }
                }
            }
            result
        }

        /// Apply M matrix using precomputed masks (production implementation
        /// replica)
        fn apply_m_to_hashes_fast(hashes: &[SlicedLabel; 6]) -> [[u8; 8]; 8] {
            let inputs: [[u8; 8]; 6] = hashes.map(|h| h.left);

            let mut result = [[0u8; 8]; 8];

            for row in 0..8 {
                let mask = M_COLUMN_MASKS[row];
                for col in 0..6 {
                    let active = (mask >> col) & 1;
                    let masked_input = inputs[col].map(|b| b & active.wrapping_neg());
                    xor_assign_8(&mut result[row], &masked_input);
                }
            }
            result
        }

        /// Verify R_COLUMN_MASKS matches the original sample_r_odd matrices
        #[test]
        #[ignore]
        fn verify_r_column_masks() {
            // Test all 16 variants with random inputs
            let mut rng = ChaCha12Rng::seed_from_u64(12345);
            let a0 = SlicedLabel::from_block(Block::random(&mut rng));
            let b0 = SlicedLabel::from_block(Block::random(&mut rng));
            let delta = SlicedLabel::from_block(Block::random(&mut rng));

            for pi_a in [false, true] {
                for pi_b in [false, true] {
                    for r0 in [false, true] {
                        for r1 in [false, true] {
                            let r_index = (pi_a as usize) << 3
                                | (pi_b as usize) << 2
                                | (r0 as usize) << 1
                                | r1 as usize;

                            let (r_matrix, _) = sample_r_odd_with_r(pi_a, pi_b, [r0, r1]);

                            let naive_result = apply_r_to_inputs_naive(&r_matrix, &a0, &b0, &delta);
                            let fast_result = apply_r_to_inputs_fast(r_index, &a0, &b0, &delta);

                            assert_eq!(
                                naive_result, fast_result,
                                "R_COLUMN_MASKS[{}] incorrect for pi_a={}, pi_b={}, r0={}, r1={}",
                                r_index, pi_a, pi_b, r0, r1
                            );
                        }
                    }
                }
            }
        }

        /// Verify M_COLUMN_MASKS matches the original M matrix
        #[test]
        #[ignore]
        fn verify_m_column_masks() {
            let mut rng = ChaCha12Rng::seed_from_u64(54321);

            // Generate random hashes
            let hashes: [SlicedLabel; 6] = [
                SlicedLabel::from_block(Block::random(&mut rng)),
                SlicedLabel::from_block(Block::random(&mut rng)),
                SlicedLabel::from_block(Block::random(&mut rng)),
                SlicedLabel::from_block(Block::random(&mut rng)),
                SlicedLabel::from_block(Block::random(&mut rng)),
                SlicedLabel::from_block(Block::random(&mut rng)),
            ];

            let naive_result = apply_m_to_hashes_naive(&hashes);
            let fast_result = apply_m_to_hashes_fast(&hashes);

            assert_eq!(
                naive_result, fast_result,
                "M_COLUMN_MASKS doesn't match M matrix"
            );
        }
    }
}
