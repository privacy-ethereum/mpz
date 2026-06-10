use super::{LANE_COUNT, TransposeError};
use std::{
    ops::ShlAssign,
    simd::{Simd, SimdElement, cmp::SimdPartialOrd},
};

/// SIMD version for bit-level transposition
///
/// Assumes an LSB0 bit encoding of the matrix.
/// This SIMD implementation additionally requires that the matrix has at least
/// `LANE_COUNT` columns and rows
pub fn transpose_bits(matrix: &mut [u8], rows: usize) -> Result<(), TransposeError> {
    // Check that number of rows is not smaller than LANE_COUNT
    if rows < LANE_COUNT {
        return Err(TransposeError::InvalidNumberOfRows);
    }

    // Check that row length is a multiple of LANE_COUNT
    let columns = matrix.len() / rows;
    if columns & (LANE_COUNT - 1) != 0 || columns < LANE_COUNT {
        return Err(TransposeError::InvalidNumberOfColumns);
    }

    // Perform transposition on bit-level consisting of:
    // 1. normal transposition of elements
    // 2. single-row bit-mask shift
    unsafe {
        transpose_unchecked::<LANE_COUNT, u8>(matrix, rows.trailing_zeros() as usize);
        bitmask_shift_unchecked(matrix, rows);
    }
    Ok(())
}

/// Unsafe matrix transpose
///
/// This function transposes a matrix of generic elements. This function is an
/// implementation of the byte-level transpose in
/// https://docs.rs/oblivious-transfer/latest/oblivious_transfer/extension/fn.transpose128.html
///
/// # Safety
///
/// Caller has to ensure that
///   - number of rows is a power of 2
///   - slice is rectangular (matrix)
///   - columns is a multiple of N
///   - N != 1 c.f. https://github.com/rust-lang/portable-simd/issues/298
///   - rounds == ld(rows)
#[inline]
pub unsafe fn transpose_unchecked<const N: usize, T>(matrix: &mut [T], rounds: usize)
where
    T: SimdElement + Copy,
{
    let half = matrix.len() >> 1;
    let mut matrix_cache = matrix.to_vec();
    let mut write_reference = matrix;
    let mut read_reference = &mut matrix_cache[..];
    let (mut s1, mut s2): (Simd<T, N>, Simd<T, N>);
    if rounds & 1 == 0 {
        std::mem::swap(&mut write_reference, &mut read_reference);
    }
    for _ in 0..rounds {
        for (k, (v1, v2)) in unsafe {
            read_reference
                .as_chunks_unchecked::<N>()
                .iter()
                .zip(read_reference[half..].as_chunks_unchecked())
                .enumerate()
        } {
            (s1, s2) = Simd::from_array(*v1).interleave(Simd::from_array(*v2));
            write_reference[N * 2 * k..N * (2 * k + 1)].copy_from_slice(&s1.to_array());
            write_reference[N * (2 * k + 1)..N * (2 * k + 2)].copy_from_slice(&s2.to_array());
        }
        std::mem::swap(&mut write_reference, &mut read_reference);
    }
}

/// Unsafe single-row bit-mask shift
///
/// Assumes an LSB0 bit encoding of the matrix.
/// This function is an implementation of the bit-level transpose in
/// https://docs.rs/oblivious-transfer/latest/oblivious_transfer/extension/fn.transpose128.html
/// Caller has to make sure that columns is a multiple of `LANE_COUNT`
#[inline]
pub unsafe fn bitmask_shift_unchecked(matrix: &mut [u8], columns: usize) {
    matrix.iter_mut().for_each(|b| *b = b.reverse_bits());
    let simd_one = Simd::<u8, LANE_COUNT>::splat(1);
    let mut s: Simd<u8, LANE_COUNT>;
    for row in matrix.chunks_mut(columns) {
        let mut shifted_row = Vec::with_capacity(columns);
        for _ in 0..8 {
            for chunk in unsafe { row.as_chunks_unchecked_mut::<LANE_COUNT>() } {
                s = Simd::from_array(*chunk);
                // Extract the MSB of every lane into a bitmask, lane 0 in the
                // least significant bit (the portable equivalent of x86
                // movemask / wasm bitmask, lowered to those instructions
                // where available).
                let high_bits = s.reverse().simd_ge(Simd::splat(0x80)).to_bitmask();
                let high_bits: Vec<u8> = high_bits.to_be_bytes()[8 - LANE_COUNT / 8..]
                    .iter()
                    .map(|b| b.reverse_bits())
                    .collect();
                shifted_row.extend_from_slice(&high_bits);
                s.shl_assign(simd_one);
                *chunk = s.to_array();
            }
        }
        row.copy_from_slice(&shifted_row)
    }
}
