//! Characteristic-2 field arithmetic.

use itybity::{FromBitIterator, ToBits};
use mpz_fields::{Field, gf2::Gf2};

/// `GF(2^n)` field constants.
#[derive(Copy, Clone, Debug)]
pub(crate) struct Gf2nConstants {
    /// Primitive degree-`N` polynomial over `GF(2)`. Full bit
    /// pattern with the leading `x^N` bit included.
    pub(crate) poly: u64,
    /// Generator of `GF(2^N)`'s multiplicative group.
    pub(crate) generator: u64,
    /// Multiplicative-group order: `2^N − 1`.
    pub(crate) group_order: u64,
    /// Multiplicative inverse of `generator` mod `poly`:
    /// `g_inv · g ≡ 1` in `GF(2^N)`.
    pub(crate) g_inv: u64,
}

/// Lookup table: GF(2^N) constants for each supported extension degree `N`.
pub(crate) fn field_constants(n: usize) -> Result<Gf2nConstants, UnsupportedDegree> {
    let (poly, g_inv) = match n {
        8 => (0x11D, 0x8E),           // x^8 + x^4 + x^3 + x^2 + 1
        9 => (0x211, 0x108),          // x^9 + x^4 + 1
        10 => (0x409, 0x204),         // x^10 + x^3 + 1
        11 => (0x805, 0x402),         // x^11 + x^2 + 1
        12 => (0x1053, 0x829),        // x^12 + x^6 + x^4 + x + 1
        13 => (0x201B, 0x100D),       // x^13 + x^4 + x^3 + x + 1
        14 => (0x402B, 0x2015),       // x^14 + x^5 + x^3 + x + 1
        15 => (0x8003, 0x4001),       // x^15 + x + 1
        16 => (0x1002D, 0x8016),      // x^16 + x^5 + x^3 + x^2 + 1
        17 => (0x20009, 0x10004),     // x^17 + x^3 + 1
        18 => (0x40081, 0x20040),     // x^18 + x^7 + 1
        19 => (0x80027, 0x40013),     // x^19 + x^5 + x^2 + x + 1
        20 => (0x100009, 0x80004),    // x^20 + x^3 + 1
        21 => (0x200005, 0x100002),   // x^21 + x^2 + 1
        22 => (0x400003, 0x200001),   // x^22 + x + 1
        23 => (0x800021, 0x400010),   // x^23 + x^5 + 1
        24 => (0x100001B, 0x80000D),  // x^24 + x^4 + x^3 + x + 1
        25 => (0x2000009, 0x1000004), // x^25 + x^3 + 1
        26 => (0x4000047, 0x2000023), // x^26 + x^6 + x^2 + x + 1
        _ => return Err(UnsupportedDegree(n)),
    };
    Ok(Gf2nConstants {
        poly,
        generator: 2,
        group_order: (1u64 << n) - 1,
        g_inv,
    })
}

// ---------------------------------------------------------------------------
// GF(2^N) field arithmetic
// ---------------------------------------------------------------------------

/// One shift-and-reduce step in `GF(2^n)`: returns `c · x mod poly`.
///
/// # Arguments
///
/// * `c` — element of `GF(2^n)` to multiply by `x`. Must fit in its low `n`
///   bits.
/// * `high` — top bit of the mask, i.e., `1 << (n − 1)`.
/// * `mask` — low-`n`-bits mask, i.e., `(1 << n) − 1`.
/// * `reduction` — `poly` with its leading `x^n` bit stripped. This is the
///   polynomial we XOR in to "subtract" an `x^n` term (since `x^n ≡ poly −
///   x^n`).
#[inline]
fn mul_by_x(c: u64, high: u64, mask: u64, reduction: u64) -> u64 {
    // Snapshot the top bit *before* the shift.
    let overflow = c & high;
    // Mask to keep `c` below degree `n`.
    let shifted = (c << 1) & mask;
    // If the shift produced an `x^n` term, fold it back in by adding
    // `reduction` (= `poly − x^n` in `GF(2)`, since `x^n ≡ poly − x^n`).
    if overflow != 0 {
        shifted ^ reduction
    } else {
        shifted
    }
}

/// Multiply `a · b` in `GF(2^n)` modulo `poly` (whose bit `n` is set).
///
/// `a` and `b` must already fit in their low `n` bits (any bit at
/// position `≥ n` will silently produce a wrong result). The output
/// is likewise in the low `n` bits.
pub(crate) fn gf2n_mul_mod(a: u64, b: u64, poly: u64, n: usize) -> u64 {
    let mut a = a;
    let mut b = b;
    let mask = (1u64 << n) - 1;
    let high = 1u64 << (n - 1);
    let reduction = poly & mask;

    let mut result = 0u64;
    while b != 0 {
        if b & 1 == 1 {
            result ^= a;
        }
        a = mul_by_x(a, high, mask, reduction);
        // Advance to the next power.
        b >>= 1;
    }
    result
}

/// Pre-computed "multiply by a fixed element of `GF(2^n)`" matrix.
pub(crate) struct GfMulMatrix {
    /// Row-major bitmask representation. Length `n`; only the low
    /// `n` bits of each row are meaningful.
    rows: Vec<u64>,
}

impl GfMulMatrix {
    /// Build the matrix.
    ///
    /// Conceptually we compute, for each `j ∈ 0..n`, the column
    /// `c_j = multiplier · x^j` reduced mod `poly`, then transpose:
    /// `rows[i]` has bit `j` set iff `c_j` has bit `i` set.
    /// Successive columns are obtained by one multiply-by-`x` step
    /// (shift-and-reduce).
    ///
    /// # Arguments
    ///
    /// * `poly` — irreducible polynomial of degree `n` over `GF(2)`, with the
    ///   leading `x^n` bit included.
    /// * `multiplier` — the fixed element of `GF(2^n)` that the resulting
    ///   matrix multiplies by. Must fit in its low `n` bits.
    /// * `n` — extension degree of `GF(2^n)`.
    pub(crate) fn new(poly: u64, multiplier: u64, n: usize) -> Self {
        let mask = (1u64 << n) - 1;
        let high = 1u64 << (n - 1);
        let reduction = poly & mask;

        // Compute columns: c_0 = multiplier, c_{j+1} = c_j · x mod poly.
        let mut columns = vec![0u64; n];
        let mut c = multiplier & mask;
        for col in columns.iter_mut() {
            *col = c;
            c = mul_by_x(c, high, mask, reduction);
        }

        // Transpose into row-major bitmasks.
        let mut rows = vec![0u64; n];
        for (j, &col) in columns.iter().enumerate() {
            let mut col_bits = col;
            while col_bits != 0 {
                let i = col_bits.trailing_zeros() as usize;
                rows[i] |= 1u64 << j;
                col_bits &= col_bits - 1;
            }
        }
        Self { rows }
    }

    /// Extension degree `n` of the underlying `GF(2^n)`.
    pub(crate) fn len(&self) -> usize {
        self.rows.len()
    }

    /// Apply the matrix to a slice of `Gf2` subfield-coefficients
    /// representing one element of `GF(2^n)` (LSB-first). Returns
    /// the subfield-coefficients of `multiplier · input`.
    ///
    /// # Panics
    ///
    /// Panics if the slice length doesn't match the
    /// extension degree used to build this matrix.
    pub(crate) fn apply(&self, input: &[Gf2]) -> Vec<Gf2> {
        debug_assert_eq!(
            input.len(),
            self.len(),
            "input length must match matrix extension degree",
        );
        let v = u64::from_lsb0_iter(input.iter_lsb0());
        Vec::<Gf2>::from_lsb0_iter(self.apply_bits_u64(v).iter_lsb0().take(self.len()))
    }

    /// Apply the matrix to a `u64` value (treated as a bit vector of
    /// length [`self.len()`](Self::len)).
    pub(crate) fn apply_bits_u64(&self, v: u64) -> u64 {
        let mut out = 0u64;
        for (i, &row) in self.rows.iter().enumerate() {
            if (row & v).count_ones() & 1 == 1 {
                out |= 1u64 << i;
            }
        }
        out
    }

    /// The canonical [`apply`](Self::apply) operation lifted to act
    /// on `F`-element bundles via `GF(2)`-linearity.
    ///
    /// # Panics
    ///
    /// Panics if the input bundle's length doesn't match the matrix's
    /// extension degree.
    pub(crate) fn apply_lifted<F: Field>(&self, input: &[F]) -> Vec<F> {
        debug_assert_eq!(
            input.len(),
            self.len(),
            "input length must match matrix extension degree"
        );
        let mut out = vec![F::zero(); self.len()];
        for i in 0..self.len() {
            let mut acc = F::zero();
            let mut row = self.rows[i];
            while row != 0 {
                let j = row.trailing_zeros() as usize;
                acc = acc + input[j];
                row &= row - 1;
            }
            out[i] = acc;
        }
        out
    }
}

/// Construction error for unsupported extension degrees (`n` not in
/// the primitive-polynomial table's range `8..=26`).
#[derive(Debug, thiserror::Error)]
#[error("unsupported extension degree {0}; supported: 8..=26")]
pub struct UnsupportedDegree(pub usize);

#[cfg(test)]
mod tests {
    use super::*;

    use crate::test_utils::pow_mod;

    fn distinct_prime_factors(mut m: u64) -> Vec<u64> {
        let mut factors = Vec::new();
        let mut p = 2u64;
        while p.saturating_mul(p) <= m {
            if m % p == 0 {
                factors.push(p);
                while m % p == 0 {
                    m /= p;
                }
            }
            p += 1;
        }
        if m > 1 {
            factors.push(m);
        }
        factors
    }

    /// Verify that `generator` has multiplicative order `2^n − 1` in
    /// `GF(2)[x] / poly`.
    fn is_primitive(generator: u64, poly: u64, n: usize) -> bool {
        let order = (1u64 << n) - 1;
        for q in distinct_prime_factors(order) {
            if pow_mod(generator, order / q, poly, n) == 1 {
                return false;
            }
        }
        true
    }

    #[test]
    fn field_constants_are_primitive() {
        for n in 8..=26 {
            let c = field_constants(n).unwrap();
            assert!(
                is_primitive(c.generator, c.poly, n),
                "field_constants({n}) is not primitive: poly=0x{:X} g={}",
                c.poly,
                c.generator,
            );
            assert_eq!(
                c.group_order,
                (1u64 << n) - 1,
                "field_constants({n}) group_order mismatch",
            );
            // The hard-coded `g_inv` actually inverts `generator` in
            // GF(2^n) — guards against a copy-paste error from the
            // example output.
            assert_eq!(
                gf2n_mul_mod(c.generator, c.g_inv, c.poly, n),
                1,
                "field_constants({n}): g · g_inv ≠ 1 in GF(2^{n})",
            );
        }
    }

    #[test]
    fn matrix_application_matches_direct_multiply() {
        for n in 8..=26 {
            let c = field_constants(n).unwrap();
            let (poly, generator) = (c.poly, c.generator);
            let matrix = GfMulMatrix::new(poly, generator, n);
            let mask = (1u64 << n) - 1;
            for v in 0..=mask {
                let expected = gf2n_mul_mod(v, generator, poly, n);
                let got = matrix.apply_bits_u64(v);
                assert_eq!(
                    got, expected,
                    "mismatch at n={n}, v=0x{v:X}: matrix=0x{got:X} direct=0x{expected:X}",
                );
            }
        }
    }

    #[test]
    fn apply_matrix_over_extension_field() {
        use mpz_fields::gf2_64::Gf2_64;

        // Hand-crafted 3-row matrix on a 3-element input. Each row is
        // a bitmask: bit `j` set means "row's output XORs `input[j]`".
        //   rows[0] = 0b011 → out[0] = in[0] + in[1]
        //   rows[1] = 0b101 → out[1] = in[0] + in[2]
        //   rows[2] = 0b110 → out[2] = in[1] + in[2]
        let matrix = GfMulMatrix {
            rows: vec![0b011u64, 0b101, 0b110],
        };
        let input: Vec<Gf2_64> = vec![
            Gf2_64(0x1234_0000_0000_0000),
            Gf2_64(0x0000_5678_0000_0000),
            Gf2_64(0x0000_0000_9abc_0000),
        ];
        let out = matrix.apply_lifted(&input);
        assert_eq!(out.len(), 3);
        assert_eq!(out[0], input[0] + input[1]);
        assert_eq!(out[1], input[0] + input[2]);
        assert_eq!(out[2], input[1] + input[2]);

        // Cross-check the F-element `apply_lifted` path against the
        // bit-packed `apply_bits_u64` path: applying the matrix
        // bit-by-bit must produce the same bit pattern as packing the
        // input as a u64, applying the bit-vector matrix, and unpacking.
        for n in 8..=12 {
            let c = field_constants(n).unwrap();
            let g = GfMulMatrix::new(c.poly, c.generator, n);
            let mask = (1u64 << n) - 1;
            for v in [0u64, 1, mask, mask / 3, mask / 2 + 1] {
                let bits = Vec::<Gf2>::from_lsb0_iter(v.iter_lsb0().take(n));
                let bits_out: Vec<Gf2> = g.apply(&bits);
                let got = u64::from_lsb0_iter(bits_out.iter_lsb0());
                let expected = g.apply_bits_u64(v);
                assert_eq!(
                    got, expected,
                    "apply<Gf2> ≠ apply_bits_u64 at n={n}, v=0x{v:X}",
                );
            }
        }
    }

    #[test]
    fn gf2n_mul_mod_matches_aes_known_vectors() {
        // AES specifies GF(2^8) under the polynomial
        //   p(x) = x^8 + x^4 + x^3 + x + 1   (= 0x11B)
        // and FIPS 197 §4.2 gives canonical worked examples. Used here
        // as an external cross-check against a widely-cited reference.
        // (Independent of our own poly table — our `n = 8` entry uses
        // a different irreducible polynomial.)
        let poly = 0x11B;
        let n = 8;

        // §4.2 main example: {57} · {83} = {c1}.
        assert_eq!(gf2n_mul_mod(0x57, 0x83, poly, n), 0xC1);

        // §4.2.2 alternative computation: {57} · {13} = {fe}.
        assert_eq!(gf2n_mul_mod(0x57, 0x13, poly, n), 0xFE);

        // §4.2.1 xtime() chain — repeated multiplication by `x` (0x02):
        //   xtime({57}) = {ae},  xtime({ae}) = {47},
        //   xtime({47}) = {8e},  xtime({8e}) = {07}.
        assert_eq!(gf2n_mul_mod(0x02, 0x57, poly, n), 0xAE);
        assert_eq!(gf2n_mul_mod(0x02, 0xAE, poly, n), 0x47);
        assert_eq!(gf2n_mul_mod(0x02, 0x47, poly, n), 0x8E);
        assert_eq!(gf2n_mul_mod(0x02, 0x8E, poly, n), 0x07);
    }

    #[test]
    fn field_constants_rejects_unsupported_sizes() {
        // `field_constants` only ships entries for `n ∈ 8..=26`. Any
        // value outside that range must surface `UnsupportedDegree`
        // carrying the requested `n` so callers can report it.
        for &n in &[0usize, 1, 2, 7, 27, 28, 64, 1000] {
            let err = field_constants(n)
                .err()
                .unwrap_or_else(|| panic!("n={n} must be unsupported"));
            assert_eq!(err.0, n, "error should carry the requested n");
        }
        // Sanity: the boundary entries inside the range succeed.
        assert!(field_constants(8).is_ok());
        assert!(field_constants(20).is_ok());
    }
}
