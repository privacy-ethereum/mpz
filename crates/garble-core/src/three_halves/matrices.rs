//! # Core Matrices for Three-Halves Garbling
//!
//! This module defines the fixed matrices used in the three-halves garbling
//! scheme. All matrices operate over GF(2) (binary field), so all arithmetic is
//! mod 2.
//!
//! ## Matrix Dimensions and Roles
//!
//! | Matrix | Size  | Role |
//! |--------|-------|------|
//! | K      | 3×8   | Cokernel of gate space G; vectors v ∈ G satisfy Kv = 0 |
//! | V      | 8×5   | Maps [output_label; gate_ciphertexts] to 8 evaluation equations |
//! | M      | 8×6   | Maps 6 hash outputs to 8 evaluation equations |
//! | V⁻¹    | 5×8   | Left-inverse of V; used by garbler to solve for outputs |
//!
//! ## The 8 Rows
//!
//! Each matrix has 8 rows corresponding to:
//! - Rows 0-1: Input combination (0,0) - left and right halves
//! - Rows 2-3: Input combination (0,1) - left and right halves
//! - Rows 4-5: Input combination (1,0) - left and right halves
//! - Rows 6-7: Input combination (1,1) - left and right halves

/// Matrix K: Cokernel basis for the gate space G
///
/// From Paper Page 12:
/// ```text
/// K = [ 1 0 | 1 0 | 1 0 | 1 0 ]
///     [ 0 1 | 0 1 | 0 1 | 0 1 ]
///     [ 0 0 | 0 1 | 1 0 | 1 1 ]
/// ```
///
/// **Property**: A vector v is in the gate space G if and only if Kv = 0
///
/// **Interpretation**:
/// - Row 0: Sum of all left halves must be 0 (even parity across left halves)
/// - Row 1: Sum of all right halves must be 0 (even parity across right halves)
/// - Row 2: A specific linear relation involving right halves of (0,1), left of
///   (1,0), both of (1,1)
///
/// The vertical bars separate the 2×2 blocks for each input combination:
/// (0,0) | (0,1) | (1,0) | (1,1)
pub const K: [[u8; 8]; 3] = [
    //   (0,0)L  (0,0)R  (0,1)L  (0,1)R  (1,0)L  (1,0)R  (1,1)L  (1,1)R
    // Row 0: checks parity of left halves
    [1, 0, 1, 0, 1, 0, 1, 0],
    // Row 1: checks parity of right halves
    [0, 1, 0, 1, 0, 1, 0, 1],
    // Row 2: specific constraint from paper
    [0, 0, 0, 1, 1, 0, 1, 1],
];

/// Matrix V: Maps [C_L, C_R, G₀, G₁, G₂] to 8 evaluation equations
///
/// From Paper Page 12:
/// ```text
/// V = [ 1 0 | 0 0 0 ]   <- (0,0) left:  uses C_L
///     [ 0 1 | 0 0 0 ]   <- (0,0) right: uses C_R
///     [ 1 0 | 0 0 1 ]   <- (0,1) left:  uses C_L ⊕ G₂
///     [ 0 1 | 0 1 1 ]   <- (0,1) right: uses C_R ⊕ G₁ ⊕ G₂
///     [ 1 0 | 1 0 1 ]   <- (1,0) left:  uses C_L ⊕ G₀ ⊕ G₂
///     [ 0 1 | 0 0 1 ]   <- (1,0) right: uses C_R ⊕ G₂
///     [ 1 0 | 1 0 0 ]   <- (1,1) left:  uses C_L ⊕ G₀
///     [ 0 1 | 0 1 0 ]   <- (1,1) right: uses C_R ⊕ G₁
/// ```
///
/// **Column interpretation**:
/// - Column 0: C_L (left half of output label)
/// - Column 1: C_R (right half of output label)
/// - Column 2: G₀ (first gate ciphertext, κ/2 bits)
/// - Column 3: G₁ (second gate ciphertext, κ/2 bits)
/// - Column 4: G₂ (third gate ciphertext, κ/2 bits)
///
/// **Key property**: The columns of V span the gate space G (same as columns of
/// M) This means: colspace(V) = colspace(M) = G, and KV = 0
///
/// **Note**: The columns for G₀, G₁, G₂ (rightmost 3 columns) are chosen to
/// match columns of M corresponding to H(A₁), H(B₁), H(A₀⊕B₁). See paper page
/// 12.
pub const V: [[u8; 5]; 8] = [
    //   C_L  C_R  G₀   G₁   G₂
    // Row 0: (0,0) left half
    [1, 0, 0, 0, 0],
    // Row 1: (0,0) right half
    [0, 1, 0, 0, 0],
    // Row 2: (0,1) left half
    [1, 0, 0, 0, 1],
    // Row 3: (0,1) right half
    [0, 1, 0, 1, 1],
    // Row 4: (1,0) left half
    [1, 0, 1, 0, 1],
    // Row 5: (1,0) right half
    [0, 1, 0, 0, 1],
    // Row 6: (1,1) left half
    [1, 0, 1, 0, 0],
    // Row 7: (1,1) right half
    [0, 1, 0, 1, 0],
];

/// Matrix M: Maps hash outputs to 8 evaluation equations
///
/// From Paper Page 10, Equation 3 (the non-? entries):
/// ```text
/// M = [ 1 0 | 0 0 | 1 0 ]   <- (0,0) left:  H(A₀) ⊕ H(A₀⊕B₀)
///     [ 0 0 | 1 0 | 1 0 ]   <- (0,0) right: H(B₀) ⊕ H(A₀⊕B₀)
///     [ 1 0 | 0 0 | 0 1 ]   <- (0,1) left:  H(A₀) ⊕ H(A₀⊕B₁)
///     [ 0 0 | 0 1 | 0 1 ]   <- (0,1) right: H(B₁) ⊕ H(A₀⊕B₁)
///     [ 0 1 | 0 0 | 0 1 ]   <- (1,0) left:  H(A₁) ⊕ H(A₀⊕B₁)
///     [ 0 0 | 1 0 | 0 1 ]   <- (1,0) right: H(B₀) ⊕ H(A₀⊕B₁)
///     [ 0 1 | 0 0 | 1 0 ]   <- (1,1) left:  H(A₁) ⊕ H(A₀⊕B₀)
///     [ 0 0 | 0 1 | 1 0 ]   <- (1,1) right: H(B₁) ⊕ H(A₀⊕B₀)
/// ```
///
/// **Column interpretation** (in order):
/// - Column 0: H(A₀)
/// - Column 1: H(A₁) = H(A₀ ⊕ Δ)
/// - Column 2: H(B₀)
/// - Column 3: H(B₁) = H(B₀ ⊕ Δ)
/// - Column 4: H(A₀ ⊕ B₀)
/// - Column 5: H(A₀ ⊕ B₁) = H(A₁ ⊕ B₀) due to free-XOR
///
/// **Key observation** (Paper Section 4.1):
/// Because of free-XOR, A₀ ⊕ B₀ = A₁ ⊕ B₁ and A₀ ⊕ B₁ = A₁ ⊕ B₀.
/// This creates useful redundancy - each H(A⊕B) term can be used in 2 rows.
///
/// **Which queries are available for each input combination**:
/// - (0,0): Has A₀, B₀, so can query H(A₀), H(B₀), H(A₀⊕B₀)
/// - (0,1): Has A₀, B₁, so can query H(A₀), H(B₁), H(A₀⊕B₁)
/// - (1,0): Has A₁, B₀, so can query H(A₁), H(B₀), H(A₁⊕B₀) = H(A₀⊕B₁)
/// - (1,1): Has A₁, B₁, so can query H(A₁), H(B₁), H(A₁⊕B₁) = H(A₀⊕B₀)
///
/// This is Table (2) from Paper Page 9.
pub const M: [[u8; 6]; 8] = [
    //   H(A₀) H(A₁) H(B₀) H(B₁) H(A₀⊕B₀) H(A₀⊕B₁)
    // Row 0: (0,0) left - uses H(A₀) and H(A₀⊕B₀)
    [1, 0, 0, 0, 1, 0],
    // Row 1: (0,0) right - uses H(B₀) and H(A₀⊕B₀)
    [0, 0, 1, 0, 1, 0],
    // Row 2: (0,1) left - uses H(A₀) and H(A₀⊕B₁)
    [1, 0, 0, 0, 0, 1],
    // Row 3: (0,1) right - uses H(B₁) and H(A₀⊕B₁)
    [0, 0, 0, 1, 0, 1],
    // Row 4: (1,0) left - uses H(A₁) and H(A₀⊕B₁) [note: A₁⊕B₀ = A₀⊕B₁]
    [0, 1, 0, 0, 0, 1],
    // Row 5: (1,0) right - uses H(B₀) and H(A₀⊕B₁)
    [0, 0, 1, 0, 0, 1],
    // Row 6: (1,1) left - uses H(A₁) and H(A₀⊕B₀) [note: A₁⊕B₁ = A₀⊕B₀]
    [0, 1, 0, 0, 1, 0],
    // Row 7: (1,1) right - uses H(B₁) and H(A₀⊕B₀)
    [0, 0, 0, 1, 1, 0],
];

/// Matrix V⁻¹: Left-inverse of V
///
/// From Paper Page 18, Equation 10:
/// ```text
/// V⁻¹ = [ 1 0 | 0 0 | 0 0 | 0 0 ]
///       [ 0 1 | 0 0 | 0 0 | 0 0 ]
///       [ 1 1 | 0 0 | 1 1 | 0 0 ]
///       [ 1 1 | 1 1 | 0 0 | 0 0 ]
///       [ 0 0 | 0 0 | 1 0 | 1 0 ]
/// ```
///
/// **Property**: V⁻¹ · V = I₅ (5×5 identity matrix)
/// This is a LEFT-inverse, not a full inverse (V is 8×5, not square).
///
/// **Usage**: The garbler computes [C; G⃗] = V⁻¹ · (right-hand side of Equation
/// 4)
///
/// **Row interpretation**:
/// - Row 0: Extracts C_L (output label left half)
/// - Row 1: Extracts C_R (output label right half)
/// - Row 2: Extracts G₀ (first gate ciphertext)
/// - Row 3: Extracts G₁ (second gate ciphertext)
/// - Row 4: Extracts G₂ (third gate ciphertext)
///
/// **Note**: The vertical bars separate the 2-column blocks corresponding to
/// each input combination: (0,0) | (0,1) | (1,0) | (1,1)
pub const V_INV: [[u8; 8]; 5] = [
    //   (0,0)L  (0,0)R  (0,1)L  (0,1)R  (1,0)L  (1,0)R  (1,1)L  (1,1)R
    // Row 0: extracts C_L - just takes (0,0) left directly
    [1, 0, 0, 0, 0, 0, 0, 0],
    // Row 1: extracts C_R - just takes (0,0) right directly
    [0, 1, 0, 0, 0, 0, 0, 0],
    // Row 2: extracts G₀
    [1, 1, 0, 0, 1, 1, 0, 0],
    // Row 3: extracts G₁
    [1, 1, 1, 1, 0, 0, 0, 0],
    // Row 4: extracts G₂
    [0, 0, 0, 0, 1, 0, 1, 0],
];

#[cfg(test)]
mod tests {
    use super::*;

    /// Verification tests for core matrices K, V, M, V_INV.
    ///
    /// These verify that the hardcoded matrices were correctly copied from
    /// the paper by checking their mathematical properties.
    ///
    /// These tests only need to run once to verify correctness after changes.
    ///
    /// Run with: `cargo test matrices::tests::table_verification -- --ignored`
    mod table_verification {
        use super::*;

        // ====================================================================
        // Matrix Operations (over GF(2))
        // ====================================================================

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

        /// Check if matrix equals identity
        fn is_identity<const N: usize>(m: &[[u8; N]; N]) -> bool {
            for i in 0..N {
                for j in 0..N {
                    let expected = if i == j { 1 } else { 0 };
                    if m[i][j] != expected {
                        return false;
                    }
                }
            }
            true
        }

        /// Compute rank of a matrix over GF(2) using Gaussian elimination
        fn rank_gf2<const R: usize, const C: usize>(m: &[[u8; C]; R]) -> usize {
            // Make a mutable copy for row reduction
            let mut work = *m;
            let mut rank = 0;
            let mut pivot_col = 0;

            for row in 0..R {
                // Find a column with a pivot (staying on the same row until we find one)
                while pivot_col < C {
                    // Find pivot in current column
                    let mut pivot_row = None;
                    for r in row..R {
                        if work[r][pivot_col] == 1 {
                            pivot_row = Some(r);
                            break;
                        }
                    }

                    if let Some(pr) = pivot_row {
                        // Swap rows
                        work.swap(row, pr);

                        // Eliminate below (and above for reduced form)
                        for r in 0..R {
                            if r != row && work[r][pivot_col] == 1 {
                                for c in 0..C {
                                    work[r][c] ^= work[row][c];
                                }
                            }
                        }

                        rank += 1;
                        pivot_col += 1;
                        break; // Move to next row
                    } else {
                        // No pivot in this column, try next column (stay on same row)
                        pivot_col += 1;
                    }
                }

                if pivot_col >= C {
                    break; // No more columns to search
                }
            }

            rank
        }

        /// Verify K × V = 0
        ///
        /// Paper Page 12: "Then V must satisfy rank(V) = 5 and KV = 0"
        /// This confirms that all columns of V lie in the gate space G.
        #[test]
        #[ignore]
        fn test_k_times_v_is_zero() {
            let kv = matmul_gf2(&K, &V);
            assert!(
                is_zero_matrix(&kv),
                "K × V should be zero matrix. Got: {:?}",
                kv
            );
        }

        /// Verify K × M = 0
        ///
        /// Paper Section 5.1: Since colspace(V) = colspace(M) = G,
        /// and K is the cokernel of G, we must have KM = 0.
        #[test]
        #[ignore]
        fn test_k_times_m_is_zero() {
            let km = matmul_gf2(&K, &M);
            assert!(
                is_zero_matrix(&km),
                "K × M should be zero matrix. Got: {:?}",
                km
            );
        }

        /// Verify V⁻¹ × V = I₅
        ///
        /// Paper Page 18: V⁻¹ is defined as a left-inverse of V.
        #[test]
        #[ignore]
        fn test_v_inv_is_left_inverse() {
            let v_inv_v = matmul_gf2(&V_INV, &V);
            assert!(
                is_identity(&v_inv_v),
                "V⁻¹ × V should be 5×5 identity. Got: {:?}",
                v_inv_v
            );
        }

        /// Verify ranks of V and M are both 5
        ///
        /// Paper Page 12: "The gate space G has dimension 5"
        /// Both V and M should span this 5-dimensional space.
        #[test]
        #[ignore]
        fn test_matrix_ranks() {
            let rank_v = rank_gf2(&V);
            let rank_m = rank_gf2(&M);

            assert_eq!(rank_v, 5, "V should have rank 5, got {}", rank_v);
            assert_eq!(rank_m, 5, "M should have rank 5, got {}", rank_m);
        }

        /// Verify K has rank 3 (3 independent constraints)
        ///
        /// K defines the cokernel of an 8-dimensional space, leaving dimension
        /// 8-3=5 for the gate space G.
        #[test]
        #[ignore]
        fn test_k_rank() {
            let rank_k = rank_gf2(&K);
            assert_eq!(rank_k, 3, "K should have rank 3, got {}", rank_k);
        }

        /// Verify V⁻¹ × M matches expected value from paper
        ///
        /// Paper Equation 12 (Page 21) gives the explicit result.
        #[test]
        #[ignore]
        fn test_v_inv_m_matches_paper() {
            let v_inv_m = matmul_gf2(&V_INV, &M);

            // Expected from Paper Equation 12
            let expected: [[u8; 6]; 5] = [
                [1, 0, 0, 0, 1, 0], // Row 0
                [0, 0, 1, 0, 1, 0], // Row 1
                [1, 1, 0, 0, 0, 0], // Row 2
                [0, 0, 1, 1, 0, 0], // Row 3
                [0, 0, 0, 0, 1, 1], // Row 4
            ];

            assert_eq!(
                v_inv_m, expected,
                "V⁻¹ × M doesn't match paper Equation 12.\nGot: {:?}\nExpected: {:?}",
                v_inv_m, expected
            );
        }
    }
}
