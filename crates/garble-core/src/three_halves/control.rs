//! # Control Matrix System for Three-Halves Garbling
//!
//! This module implements the "dicing" technique from the paper.
//! The control matrix R determines which linear combinations of input label
//! pieces the evaluator uses to compute output label halves.
//!
//! ## Overview
//!
//! The control matrix R is an 8×6 matrix that specifies, for each of the 8
//! evaluation equations (4 input combinations × 2 halves), which pieces of
//! the input labels [A₀; B₀; Δ] to include.
//!
//! ### The Problem (Paper Section 4.3)
//!
//! The matrix R must satisfy the constraint:
//! ```text
//! KR = K[0 0 t]
//! ```
//! where t is the truth table. But this constraint depends on t, which must
//! be hidden from the evaluator!
//!
//! ### The Solution: Randomization
//!
//! R is sampled from a distribution R(t) such that:
//! 1. KR = K[0 0 t] always holds (correctness)
//! 2. Each marginal view R_ij is uniform and independent of t (security)
//!
//! ### Marginal Views
//!
//! When the evaluator has input (A_i, B_j), they only see/need the 2×4
//! submatrix:
//! R_ij = [R_ijA  R_ijB]  (rows 2i, 2i+1 and columns for A, B parts)

//! The full R is never revealed - only one marginal view per evaluation.
//!
//! ## Compression with Basis {S₁, S₂}
//!
//! Instead of encrypting 8-bit marginal views, we express them in a 2D basis:
//!
//! R_ij = c₁·S₁ ⊕ c₂·S₂
//!
//! This reduces overhead to 2 bits per marginal view × 4 views = 8 bits,
//! but we encode it as 5 bits total (see paper Section 5.2).

// ============================================================================
// Basis Matrices for Marginal View Compression
// ============================================================================

/// Basis matrix S₁ for expressing marginal views
///
/// From Paper Figure 3, Page 14:
/// ```text
/// S₁ = [ 1 1 | 1 0 ]
///      [ 1 0 | 0 1 ]
/// ```
///
/// **Interpretation**: A 2×4 matrix where:
/// - Row 0 is coefficients for the left half computation
/// - Row 1 is coefficients for the right half computation
/// - Columns are [A_L, A_R, B_L, B_R] (the four input label halves)
///
/// The vertical bar separates the A-part from the B-part.
pub const S1: [[u8; 4]; 2] = [
    //  A_L  A_R  B_L  B_R
    [1, 1, 1, 0], // Left half computation
    [1, 0, 0, 1], // Right half computation
];

/// Basis matrix S₂ for expressing marginal views
///
/// From Paper Figure 3, Page 14:
/// ```text
/// S₂ = [ 1 0 | 0 1 ]
///      [ 0 1 | 1 1 ]
/// ```
pub const S2: [[u8; 4]; 2] = [
    //  A_L  A_R  B_L  B_R
    [1, 0, 0, 1], // Left half computation
    [0, 1, 1, 1], // Right half computation
];

// ============================================================================
// Fixed Control Matrices for ODD-Parity Gates (AND, OR, NAND, NOR)
// ============================================================================

/// Matrix R_p: Added for odd-parity gates
///
/// From Paper Figure 4, Page 14:
/// ```text
/// R_p = [ 0 0 | 1 0 | 0 0 ]
///       [ 0 1 | 0 0 | 0 0 ]
///       [ 0 0 | 1 0 | 1 0 ]
///       [ 0 0 | 0 0 | 0 0 ]
///       [ 0 0 | 0 0 | 0 0 ]
///       [ 0 1 | 0 0 | 0 1 ]
///       [ 0 0 | 0 0 | 0 0 ]
///       [ 0 0 | 0 0 | 0 0 ]
/// ```
///
/// **Purpose**: When garbling an odd-parity gate (like AND), we add R_p to
/// the sampled R. The evaluator knows to add the corresponding (R_p)_ij to
/// their marginal view since parity is public in ODD mode.
///
/// **Constraint** (Paper Equation 7):
/// ```text
/// K·R_p = [ 0 0 0 0 | 1 0 ]
///         [ 0 0 0 0 | 0 1 ]
///         [ 0 0 0 0 | 0 0 ]
/// ```
/// This contributes the "p" (parity) term to the K·R constraint.
///
/// **Column layout**: [A₀_L, A₀_R, B₀_L, B₀_R, Δ_L, Δ_R]
pub const R_P: [[u8; 6]; 8] = [
    // (0,0) left
    [0, 0, 1, 0, 0, 0],
    // (0,0) right
    [0, 1, 0, 0, 0, 0],
    // (0,1) left
    [0, 0, 1, 0, 1, 0],
    // (0,1) right
    [0, 0, 0, 0, 0, 0],
    // (1,0) left
    [0, 0, 0, 0, 0, 0],
    // (1,0) right
    [0, 1, 0, 0, 0, 1],
    // (1,1) left
    [0, 0, 0, 0, 0, 0],
    // (1,1) right
    [0, 0, 0, 0, 0, 0],
];

// ============================================================================
// Compressed Representation (R̄)
// ============================================================================

/// Compressed representation of R_a in terms of basis {S₁, S₂}
///
/// From Paper Figure 3, Page 14:
/// ```text
/// R̄_a = [ 0 0 ]   <- (0,0): 0·S₁ ⊕ 0·S₂
///       [ 1 1 ]   <- (0,1): 1·S₁ ⊕ 1·S₂
///       [ 0 1 ]   <- (1,0): 0·S₁ ⊕ 1·S₂
///       [ 1 0 ]   <- (1,1): 1·S₁ ⊕ 0·S₂
/// ```
///
/// Each row gives the coefficients [c₁, c₂] such that R_ij = c₁·S₁ ⊕ c₂·S₂
pub const R_BAR_A: [[u8; 2]; 4] = [
    [0, 0], // (0,0)
    [1, 1], // (0,1)
    [0, 1], // (1,0)
    [1, 0], // (1,1)
];

/// Compressed representation of R_b in terms of basis {S₁, S₂}
///
/// From Paper Figure 3, Page 14:
/// ```text
/// R̄_b = [ 0 0 ]
///       [ 1 0 ]
///       [ 1 1 ]
///       [ 0 1 ]
/// ```
pub const R_BAR_B: [[u8; 2]; 4] = [
    [0, 0], // (0,0)
    [1, 0], // (0,1)
    [1, 1], // (1,0)
    [0, 1], // (1,1)
];

/// Compressed representation of R$ basis vectors
///
/// From Paper Figure 3, Page 14:
/// ```text
/// R̄$ ← span { [ 1 0 ]   [ 0 1 ] }
///             [ 1 0 ] , [ 0 1 ]
///             [ 1 0 ]   [ 0 1 ]
///             [ 1 0 ]   [ 0 1 ]
/// ```
///
/// **Key insight**: Both basis vectors have the same value in every row!
/// This means sampling random R$ in compressed form just picks a random
/// pair (c₁, c₂) and uses it for ALL four marginal views.
///
/// This is what makes each marginal view individually uniform while
/// maintaining the correlation needed for KR$ = 0.
pub const R_BAR_DOLLAR_BASIS_0: [[u8; 2]; 4] = [
    [1, 0], // (0,0)
    [1, 0], // (0,1)
    [1, 0], // (1,0)
    [1, 0], // (1,1)
];

/// Second basis vector for compressed R$ randomization
///
/// From Paper Figure 3, Page 14.
/// Same pattern as R_BAR_DOLLAR_BASIS_0 but with [0,1] instead of [1,0].
pub const R_BAR_DOLLAR_BASIS_1: [[u8; 2]; 4] = [
    [0, 1], // (0,0)
    [0, 1], // (0,1)
    [0, 1], // (1,0)
    [0, 1], // (1,1)
];

// ============================================================================
// Control Matrix Operations
// ============================================================================

/// Precomputed lookup table for compressed control matrices R_bar.
///
/// Indexed by: `(pi_a as usize) << 3 | (pi_b as usize) << 2 | (r0 as usize) <<
/// 1 | r1 as usize`
///
/// Each entry is the compressed R_bar representation where:
/// - `a = !pi_a` (true position bit for input A in AND gate)
/// - `b = !pi_b` (true position bit for input B in AND gate)
/// - `p = true` (AND gate has odd parity, exactly one true output)
/// - `R_bar = r0·R̄$_BASIS_0 ⊕ r1·R̄$_BASIS_1 ⊕ a·R̄_A ⊕ b·R̄_B`
///
/// Note: R_P is NOT included in R_bar because it's not in the span of {S₁, S₂}.
/// The evaluator adds R_P separately since parity is public.
const SAMPLE_R_BAR_TABLE: [[[u8; 2]; 4]; 16] = [
    [[0, 0], [0, 1], [1, 0], [1, 1]], // Index 0
    [[0, 1], [0, 0], [1, 1], [1, 0]], // Index 1
    [[1, 0], [1, 1], [0, 0], [0, 1]], // Index 2
    [[1, 1], [1, 0], [0, 1], [0, 0]], // Index 3
    [[0, 0], [1, 1], [0, 1], [1, 0]], // Index 4
    [[0, 1], [1, 0], [0, 0], [1, 1]], // Index 5
    [[1, 0], [0, 1], [1, 1], [0, 0]], // Index 6
    [[1, 1], [0, 0], [1, 0], [0, 1]], // Index 7
    [[0, 0], [1, 0], [1, 1], [0, 1]], // Index 8
    [[0, 1], [1, 1], [1, 0], [0, 0]], // Index 9
    [[1, 0], [0, 0], [0, 1], [1, 1]], // Index 10
    [[1, 1], [0, 1], [0, 0], [1, 0]], // Index 11
    [[0, 0], [0, 0], [0, 0], [0, 0]], // Index 12
    [[0, 1], [0, 1], [0, 1], [0, 1]], // Index 13
    [[1, 0], [1, 0], [1, 0], [1, 0]], // Index 14
    [[1, 1], [1, 1], [1, 1], [1, 1]], // Index 15
];

/// Sample a control matrix R for an AND gate (ODD mode)
///
/// Uses precomputed lookup table for all 16 combinations of inputs.
///
/// Paper Section 5.1, Algorithm:
/// ```text
/// R = p·R_p ⊕ a·R_a ⊕ b·R_b ⊕ R$
/// ```
///
/// where:
/// - `a = !pi_a` (position bit derived from permute bit)
/// - `b = !pi_b` (position bit derived from permute bit)
/// - `p = true` (AND gates have odd parity)
/// - `R$` is sampled uniformly from span{R$_BASIS_0, R$_BASIS_1}
///
/// # Arguments
/// * `pi_a` - Permute bit for input A
/// * `pi_b` - Permute bit for input B
/// * `rand_bits` - Two random bits [r₀, r₁] for sampling R$
///
/// # Returns
/// * `r_bar` - The 4×2 compressed representation for encryption (u8 values 0 or
///   1)
#[inline]
pub fn sample_r_odd(pi_a: bool, pi_b: bool, rand_bits: [bool; 2]) -> [[u8; 2]; 4] {
    let index = (pi_a as usize) << 3
        | (pi_b as usize) << 2
        | (rand_bits[0] as usize) << 1
        | rand_bits[1] as usize;
    SAMPLE_R_BAR_TABLE[index]
}

/// Precomputed lookup table for all possible marginal view expansions
///
/// Since [c₁, c₂] are binary (0 or 1), there are only 4 possible combinations.
/// This table precomputes R_ij = c₁·S₁ ⊕ c₂·S₂ for all 4 cases:
///
/// - Index 0 ([0,0]): 0·S₁ ⊕ 0·S₂ = zero matrix
/// - Index 1 ([0,1]): 0·S₁ ⊕ 1·S₂ = S₂
/// - Index 2 ([1,0]): 1·S₁ ⊕ 0·S₂ = S₁
/// - Index 3 ([1,1]): 1·S₁ ⊕ 1·S₂ = S₁ ⊕ S₂
///
/// This optimization replaces nested loops with a single array lookup.
const EXPANDED_MARGINALS: [[[u8; 4]; 2]; 4] = [
    // [c₁=0, c₂=0]: zero matrix
    [[0, 0, 0, 0], [0, 0, 0, 0]],
    // [c₁=0, c₂=1]: S₂
    [[1, 0, 0, 1], [0, 1, 1, 1]],
    // [c₁=1, c₂=0]: S₁
    [[1, 1, 1, 0], [1, 0, 0, 1]],
    // [c₁=1, c₂=1]: S₁ ⊕ S₂
    [[0, 1, 1, 1], [1, 1, 1, 0]],
];

/// Expand compressed marginal view R̄_ij to full R_ij
///
/// Given coefficients [c₁, c₂], compute R_ij = c₁·S₁ ⊕ c₂·S₂
///
/// # Arguments
/// * `r_bar_ij` - The 2-element compressed representation [c₁, c₂]
///
/// # Returns
/// The 2×4 marginal view matrix
///
/// # Implementation Note
/// Since [c₁, c₂] can only be [0,0], [0,1], [1,0], or [1,1], this function
/// uses a precomputed lookup table instead of computing the linear combination
/// at runtime, which is faster and avoids loops/XOR operations.
pub fn expand_marginal(r_bar_ij: &[u8; 2]) -> [[u8; 4]; 2] {
    let index = (r_bar_ij[0] << 1) | r_bar_ij[1];
    EXPANDED_MARGINALS[index as usize]
}

/// Precomputed R_P marginals for all 4 input combinations
///
/// Since (i, j) are color bits (0 or 1), there are only 4 combinations.
/// This table precomputes the 2×4 marginal view from R_P for each:
///
/// - Index 0 (i=0, j=0): Extract rows 0,1 columns 0-3 from R_P
/// - Index 1 (i=0, j=1): Extract rows 2,3 columns 0-3 from R_P
/// - Index 2 (i=1, j=0): Extract rows 4,5 columns 0-3 from R_P
/// - Index 3 (i=1, j=1): Extract rows 6,7 columns 0-3 from R_P
const R_P_MARGINALS: [[[u8; 4]; 2]; 4] = [
    // (i=0, j=0): rows 0,1, columns [A₀_L, A₀_R, B₀_L, B₀_R]
    [[0, 0, 1, 0], [0, 1, 0, 0]],
    // (i=0, j=1): rows 2,3
    [[0, 0, 1, 0], [0, 0, 0, 0]],
    // (i=1, j=0): rows 4,5
    [[0, 0, 0, 0], [0, 1, 0, 0]],
    // (i=1, j=1): rows 6,7
    [[0, 0, 0, 0], [0, 0, 0, 0]],
];

/// Extract R_P's marginal view for input position (i,j)
///
/// In ODD mode, the evaluator knows parity is odd and must add R_P's
/// contribution to their marginal view. This function extracts the
/// 2×4 marginal from the constant R_P matrix.
///
/// # Arguments
/// * `i` - First input's color bit (0 or 1)
/// * `j` - Second input's color bit (0 or 1)
///
/// # Returns
/// The 2×4 marginal view from R_P for position (i,j)
///
/// # Implementation Note
/// Since (i, j) can only be (0,0), (0,1), (1,0), or (1,1), this function
/// uses a precomputed lookup table instead of extracting from R_P at runtime.
pub fn extract_r_p_marginal(i: usize, j: usize) -> [[u8; 4]; 2] {
    let index = (i << 1) | j;
    R_P_MARGINALS[index]
}

#[cfg(test)]
pub(in crate::three_halves) mod tests {
    use super::{super::matrices::K, *};

    /// Test: Verify expand_marginal correctly indexes EXPANDED_MARGINALS table
    #[test]
    fn test_expand_marginal_indexing() {
        // Verify expand_marginal correctly indexes EXPANDED_MARGINALS table
        // Index = (c₁ << 1) | c₂
        assert_eq!(expand_marginal(&[0, 0]), EXPANDED_MARGINALS[0]); // index 0b00 = 0
        assert_eq!(expand_marginal(&[0, 1]), EXPANDED_MARGINALS[1]); // index 0b01 = 1
        assert_eq!(expand_marginal(&[1, 0]), EXPANDED_MARGINALS[2]); // index 0b10 = 2
        assert_eq!(expand_marginal(&[1, 1]), EXPANDED_MARGINALS[3]); // index 0b11 = 3
    }

    /// Verification tests for precomputed constants and lookup tables.
    ///
    /// These verify that hardcoded constants/LUTs match their specifications:
    /// - Source matrices (R_P, R_A, R_B, R_DOLLAR_BASIS_*) satisfy K×R
    ///   constraints
    /// - Derived LUTs (SAMPLE_R_BAR_TABLE, EXPANDED_MARGINALS, R_P_MARGINALS)
    ///   are correctly constructed
    ///
    /// These tests only need to run once to verify correctness after changes.
    ///
    /// Run with: `cargo test control::tests::table_verification -- --ignored`
    pub(in crate::three_halves) mod table_verification {
        #![allow(unused_imports)]
        use super::*;

        /// Matrix R_a: Encodes the 'a' bit of truth table position
        ///
        /// From Paper Figure 3, Page 14. See control module docs for details.
        pub(in crate::three_halves) const R_A: [[u8; 6]; 8] = [
            [0, 0, 0, 0, 0, 0], // (0,0) left
            [0, 0, 0, 0, 0, 0], // (0,0) right
            [0, 1, 1, 1, 1, 1], // (0,1) left
            [1, 1, 1, 0, 1, 0], // (0,1) right
            [1, 0, 0, 1, 1, 0], // (1,0) left
            [0, 1, 1, 1, 0, 1], // (1,0) right
            [1, 1, 1, 0, 0, 1], // (1,1) left
            [1, 0, 0, 1, 1, 1], // (1,1) right
        ];

        /// Matrix R_b: Encodes the 'b' bit of truth table position
        ///
        /// From Paper Figure 3, Page 14. See control module docs for details.
        pub(in crate::three_halves) const R_B: [[u8; 6]; 8] = [
            [0, 0, 0, 0, 0, 0], // (0,0) left
            [0, 0, 0, 0, 0, 0], // (0,0) right
            [1, 1, 1, 0, 1, 0], // (0,1) left
            [1, 0, 0, 1, 0, 1], // (0,1) right
            [0, 1, 1, 1, 0, 1], // (1,0) left
            [1, 1, 1, 0, 1, 1], // (1,0) right
            [1, 0, 0, 1, 1, 1], // (1,1) left
            [0, 1, 1, 1, 1, 0], // (1,1) right
        ];

        /// First basis matrix for R$ randomization
        ///
        /// From Paper Figure 3, Page 14. See control module docs for details.
        pub(in crate::three_halves) const R_DOLLAR_BASIS_0: [[u8; 6]; 8] = [
            [1, 1, 1, 0, 0, 0],
            [1, 0, 0, 1, 0, 0],
            [1, 1, 1, 0, 1, 0],
            [1, 0, 0, 1, 0, 1],
            [1, 1, 1, 0, 1, 1],
            [1, 0, 0, 1, 1, 0],
            [1, 1, 1, 0, 0, 1],
            [1, 0, 0, 1, 1, 1],
        ];

        /// Second basis matrix for R$ randomization
        ///
        /// From Paper Figure 3, Page 14. See control module docs for details.
        pub(in crate::three_halves) const R_DOLLAR_BASIS_1: [[u8; 6]; 8] = [
            [1, 0, 0, 1, 0, 0],
            [0, 1, 1, 1, 0, 0],
            [1, 0, 0, 1, 0, 1],
            [0, 1, 1, 1, 1, 1],
            [1, 0, 0, 1, 1, 0],
            [0, 1, 1, 1, 0, 1],
            [1, 0, 0, 1, 1, 1],
            [0, 1, 1, 1, 1, 0],
        ];

        // ========================================================================
        // Helper Functions (used only for verification)
        // ========================================================================

        /// Multiply two matrices over GF(2)
        ///
        /// Computes A × B where all arithmetic is mod 2.
        fn matmul_gf2<const RA: usize, const CA: usize, const CB: usize>(
            a: &[[u8; CA]; RA],
            b: &[[u8; CB]; CA],
        ) -> [[u8; CB]; RA] {
            let mut result = [[0u8; CB]; RA];

            for i in 0..RA {
                for j in 0..CB {
                    let mut sum = 0u8;
                    for k in 0..CA {
                        // In GF(2): multiplication is AND, addition is XOR
                        sum ^= a[i][k] & b[k][j];
                    }
                    result[i][j] = sum;
                }
            }

            result
        }

        /// Check if a matrix is all zeros
        fn is_zero_matrix<const R: usize, const C: usize>(m: &[[u8; C]; R]) -> bool {
            for row in m {
                for &val in row {
                    if val != 0 {
                        return false;
                    }
                }
            }
            true
        }

        /// Verify K × R$ = 0 for basis matrices
        fn verify_k_r_dollar_is_zero_impl() -> bool {
            let kr0 = matmul_gf2(&K, &R_DOLLAR_BASIS_0);
            let kr1 = matmul_gf2(&K, &R_DOLLAR_BASIS_1);
            is_zero_matrix(&kr0) && is_zero_matrix(&kr1)
        }

        /// Verify K × R_a gives expected result (Paper Equation 7)
        fn verify_k_r_a_impl() -> bool {
            let kr_a = matmul_gf2(&K, &R_A);
            let expected: [[u8; 6]; 3] =
                [[0, 0, 0, 0, 0, 0], [0, 0, 0, 0, 0, 0], [0, 0, 0, 0, 1, 0]];
            kr_a == expected
        }

        /// Verify K × R_b gives expected result (Paper Equation 7)
        fn verify_k_r_b_impl() -> bool {
            let kr_b = matmul_gf2(&K, &R_B);
            let expected: [[u8; 6]; 3] =
                [[0, 0, 0, 0, 0, 0], [0, 0, 0, 0, 0, 0], [0, 0, 0, 0, 0, 1]];
            kr_b == expected
        }

        /// Verify K × R_p gives expected result (Paper Equation 7)
        fn verify_k_r_p_impl() -> bool {
            let kr_p = matmul_gf2(&K, &R_P);
            let expected: [[u8; 6]; 3] =
                [[0, 0, 0, 0, 1, 0], [0, 0, 0, 0, 0, 1], [0, 0, 0, 0, 0, 0]];
            kr_p == expected
        }

        /// Extract marginal view R_ij from full control matrix R
        ///
        /// Paper Section 5.1: "When the evaluator holds input labels A_i, B_j,
        /// the submatrix R_ij = [R_ijA R_ijB] is enough to completely determine
        /// which linear combination should be applied."
        ///
        /// # Arguments
        /// * `r` - The full 8×6 control matrix
        /// * `i` - First input's color bit (0 or 1)
        /// * `j` - Second input's color bit (0 or 1)
        ///
        /// # Returns
        /// The 2×4 marginal view [R_ijA R_ijB] where:
        /// - Columns 0-1 are the A-part (coefficients for A_L, A_R)
        /// - Columns 2-3 are the B-part (coefficients for B_L, B_R)
        fn extract_marginal(r: &[[u8; 6]; 8], i: usize, j: usize) -> [[u8; 4]; 2] {
            let row_base = 2 * (2 * i + j); // Row index: 0, 2, 4, or 6

            let mut marginal = [[0u8; 4]; 2];

            // Row 0 of marginal = row (row_base) of R, columns 0-3
            // Row 1 of marginal = row (row_base + 1) of R, columns 0-3
            for col in 0..4 {
                marginal[0][col] = r[row_base][col];
                marginal[1][col] = r[row_base + 1][col];
            }

            marginal
        }

        // ========================================================================
        // Verification Tests
        // ========================================================================

        /// Verify K × R$_BASIS vectors = 0
        ///
        /// Paper Figure 3: The R$ distribution must satisfy KR$ = 0
        #[test]
        #[ignore]
        fn verify_k_r_dollar_is_zero() {
            assert!(
                verify_k_r_dollar_is_zero_impl(),
                "K × R$_BASIS should be zero"
            );
        }

        /// Verify K × R_p matches Equation 7
        #[test]
        #[ignore]
        fn verify_k_r_p_constraint() {
            assert!(verify_k_r_p_impl(), "K × R_p doesn't match Equation 7");
        }

        /// Verify K × R_a matches Equation 7
        #[test]
        #[ignore]
        fn verify_k_r_a_constraint() {
            assert!(verify_k_r_a_impl(), "K × R_a doesn't match Equation 7");
        }

        /// Verify K × R_b matches Equation 7
        #[test]
        #[ignore]
        fn verify_k_r_b_constraint() {
            assert!(verify_k_r_b_impl(), "K × R_b doesn't match Equation 7");
        }

        /// Verify SAMPLE_R_BAR_TABLE construction from compressed basis
        /// matrices
        #[test]
        #[ignore]
        fn verify_sample_r_bar_table() {
            for pi_a in [false, true] {
                for pi_b in [false, true] {
                    for r0 in [false, true] {
                        for r1 in [false, true] {
                            let (a, b) = (!pi_a, !pi_b);

                            // Compute r_bar from formula:
                            // r_bar = r0·R̄$_BASIS_0 ⊕ r1·R̄$_BASIS_1 ⊕ a·R̄_A ⊕ b·R̄_B
                            let mut expected = [[0u8; 2]; 4];
                            for ij in 0..4 {
                                for k in 0..2 {
                                    expected[ij][k] = (r0 as u8 * R_BAR_DOLLAR_BASIS_0[ij][k])
                                        ^ (r1 as u8 * R_BAR_DOLLAR_BASIS_1[ij][k])
                                        ^ (a as u8 * R_BAR_A[ij][k])
                                        ^ (b as u8 * R_BAR_B[ij][k]);
                                }
                            }

                            let index = (pi_a as usize) << 3
                                | (pi_b as usize) << 2
                                | (r0 as usize) << 1
                                | r1 as usize;

                            assert_eq!(
                                super::super::SAMPLE_R_BAR_TABLE[index],
                                expected,
                                "SAMPLE_R_BAR_TABLE[{}] incorrect for pi_a={}, pi_b={}, r0={}, r1={}",
                                index,
                                pi_a,
                                pi_b,
                                r0,
                                r1
                            );
                        }
                    }
                }
            }
        }

        /// Verify EXPANDED_MARGINALS construction from S₁ and S₂
        #[test]
        #[ignore]
        fn verify_expanded_marginals() {
            for c1 in 0u8..=1 {
                for c2 in 0u8..=1 {
                    // Compute marginal = c1·S₁ ⊕ c2·S₂
                    let mut expected = [[0u8; 4]; 2];
                    for row in 0..2 {
                        for col in 0..4 {
                            expected[row][col] = (c1 * S1[row][col]) ^ (c2 * S2[row][col]);
                        }
                    }

                    let index = (c1 << 1) | c2;
                    assert_eq!(
                        super::super::EXPANDED_MARGINALS[index as usize],
                        expected,
                        "EXPANDED_MARGINALS[{}] incorrect for c1={}, c2={}",
                        index,
                        c1,
                        c2
                    );
                }
            }
        }

        /// Verify R_P_MARGINALS extraction from R_P matrix
        #[test]
        #[ignore]
        fn verify_r_p_marginals() {
            for i in 0..2 {
                for j in 0..2 {
                    // Extract marginal from R_P
                    let expected = extract_marginal(&R_P, i, j);

                    let index = (i << 1) | j;
                    assert_eq!(
                        super::super::R_P_MARGINALS[index],
                        expected,
                        "R_P_MARGINALS[{}] incorrect for i={}, j={}",
                        index,
                        i,
                        j
                    );
                }
            }
        }
    }
}
