//! SHA-256 compression as a boolean circuit.

use mpz_fields::gf2::Gf2;

use crate::Context;

/// A 32-bit register in LSB-first bit order: index 0 is the LSB.
type Word<W> = [W; 32];

/// SHA-256 round constants.
pub const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// SHA-256 initial hash state.
pub const H0: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/// AND-gate count of a single SHA-256 compression block.
pub const AND_PER_BLOCK: usize = 22_696;

fn xor_word<C: Context<Field = Gf2>>(
    ctx: &mut C,
    a: Word<C::Wire>,
    b: Word<C::Wire>,
) -> Word<C::Wire> {
    let mut out = a;
    for i in 0..32 {
        out[i] = ctx.add(a[i], b[i]);
    }
    out
}

/// `ROTR(x, n)` in LSB-first order: `result[i] = x[(i + n) mod 32]`.
/// Matches `u32::rotate_right` at the value level.
fn rotr<W: Copy>(a: Word<W>, n: usize) -> Word<W> {
    let mut out = a;
    for i in 0..32 {
        out[i] = a[(i + n) % 32];
    }
    out
}

/// `SHR(x, n)` in LSB-first order: `result[i] = x[i + n]` for
/// `i + n < 32`, else zero. Matches `x >> n` at the value level.
fn shr<C: Context<Field = Gf2>>(ctx: &mut C, a: Word<C::Wire>, n: usize) -> Word<C::Wire> {
    let zero = ctx.constant(Gf2::ZERO);
    let mut out = [zero; 32];
    let mut i = 0;
    while i + n < 32 {
        out[i] = a[i + n];
        i += 1;
    }
    out
}

/// Ripple-carry 32-bit add modulo 2^32. 31 AND gates (the carry-out at bit 31
/// is unused).
fn add_word<C: Context<Field = Gf2>>(
    ctx: &mut C,
    a: Word<C::Wire>,
    b: Word<C::Wire>,
) -> Word<C::Wire> {
    let zero = ctx.constant(Gf2::ZERO);
    let mut out = [zero; 32];
    let mut carry = zero;
    for i in 0..32 {
        let axb = ctx.add(a[i], b[i]);
        out[i] = ctx.add(axb, carry);

        if i == 31 {
            continue;
        }

        // carry_out = MAJ(a, b, carry) = ((a ^ b) AND (b ^ carry)) ^ b
        let bxc = ctx.add(b[i], carry);
        let m = ctx.mul(axb, bxc);
        carry = ctx.add(m, b[i]);
    }
    out
}

/// `Ch(x, y, z) = (x AND y) XOR ((NOT x) AND z)`, rewritten as
/// `((y XOR z) AND x) XOR z` to save an AND gate per bit.
fn ch<C: Context<Field = Gf2>>(
    ctx: &mut C,
    x: Word<C::Wire>,
    y: Word<C::Wire>,
    z: Word<C::Wire>,
) -> Word<C::Wire> {
    let mut out = x;
    for i in 0..32 {
        let yxz = ctx.add(y[i], z[i]);
        let and = ctx.mul(yxz, x[i]);
        out[i] = ctx.add(and, z[i]);
    }
    out
}

/// `Maj(x, y, z) = (x AND y) XOR (x AND z) XOR (y AND z)`, rewritten as
/// `((x XOR y) AND (y XOR z)) XOR y` to save two AND gates per bit.
fn maj<C: Context<Field = Gf2>>(
    ctx: &mut C,
    x: Word<C::Wire>,
    y: Word<C::Wire>,
    z: Word<C::Wire>,
) -> Word<C::Wire> {
    let mut out = x;
    for i in 0..32 {
        let xxy = ctx.add(x[i], y[i]);
        let yxz = ctx.add(y[i], z[i]);
        let and = ctx.mul(xxy, yxz);
        out[i] = ctx.add(and, y[i]);
    }
    out
}

fn constant_word<C: Context<Field = Gf2>>(ctx: &mut C, v: u32) -> Word<C::Wire> {
    let zero = ctx.constant(Gf2::ZERO);
    let mut out = [zero; 32];
    for (i, wire) in out.iter_mut().enumerate() {
        let bit = (v >> i) & 1 != 0;
        *wire = ctx.constant(Gf2(bit));
    }
    out
}

fn slice_to_word<W: Copy>(s: &[W]) -> Word<W> {
    let mut out = [s[0]; 32];
    out.copy_from_slice(s);
    out
}

/// Boolean-circuit SHA-256 compression.
///
/// Input: `msg` (512 bits, 16 u32 words, LSB-first within each word),
/// `state` (256 bits, 8 u32 words, LSB-first). Output has the same
/// shape as `state`.
pub fn compress<C: Context<Field = Gf2>>(
    ctx: &mut C,
    msg: [C::Wire; 512],
    state: [C::Wire; 256],
) -> [C::Wire; 256] {
    let mut w: Vec<Word<C::Wire>> = Vec::with_capacity(64);
    for i in 0..16 {
        w.push(slice_to_word(&msg[i * 32..(i + 1) * 32]));
    }
    for i in 16..64 {
        // σ0(x) = ROTR(x, 7) XOR ROTR(x, 18) XOR SHR(x, 3)
        let s0 = {
            let a = rotr(w[i - 15], 7);
            let b = rotr(w[i - 15], 18);
            let c = shr(ctx, w[i - 15], 3);
            let ab = xor_word(ctx, a, b);
            xor_word(ctx, ab, c)
        };
        // σ1(x) = ROTR(x, 17) XOR ROTR(x, 19) XOR SHR(x, 10)
        let s1 = {
            let a = rotr(w[i - 2], 17);
            let b = rotr(w[i - 2], 19);
            let c = shr(ctx, w[i - 2], 10);
            let ab = xor_word(ctx, a, b);
            xor_word(ctx, ab, c)
        };
        let t1 = add_word(ctx, w[i - 16], s0);
        let t2 = add_word(ctx, t1, w[i - 7]);
        let t3 = add_word(ctx, t2, s1);
        w.push(t3);
    }

    let old: [Word<C::Wire>; 8] =
        core::array::from_fn(|i| slice_to_word(&state[i * 32..(i + 1) * 32]));
    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = old;

    for i in 0..64 {
        // Σ1(e) = ROTR(e, 6) XOR ROTR(e, 11) XOR ROTR(e, 25)
        let big_s1 = {
            let r6 = rotr(e, 6);
            let r11 = rotr(e, 11);
            let r25 = rotr(e, 25);
            let t = xor_word(ctx, r6, r11);
            xor_word(ctx, t, r25)
        };
        let ch_efg = ch(ctx, e, f, g);
        let ki = constant_word(ctx, K[i]);
        // T1 = h + Σ1(e) + Ch(e,f,g) + K_i + w_i
        let t1 = {
            let s1 = add_word(ctx, h, big_s1);
            let s2 = add_word(ctx, s1, ch_efg);
            let s3 = add_word(ctx, s2, ki);
            add_word(ctx, s3, w[i])
        };
        // Σ0(a) = ROTR(a, 2) XOR ROTR(a, 13) XOR ROTR(a, 22)
        let big_s0 = {
            let r2 = rotr(a, 2);
            let r13 = rotr(a, 13);
            let r22 = rotr(a, 22);
            let t = xor_word(ctx, r2, r13);
            xor_word(ctx, t, r22)
        };
        let maj_abc = maj(ctx, a, b, c);
        // T2 = Σ0(a) + Maj(a,b,c)
        let t2 = add_word(ctx, big_s0, maj_abc);

        h = g;
        g = f;
        f = e;
        e = add_word(ctx, d, t1);
        d = c;
        c = b;
        b = a;
        a = add_word(ctx, t1, t2);
    }

    let new_state = [
        add_word(ctx, old[0], a),
        add_word(ctx, old[1], b),
        add_word(ctx, old[2], c),
        add_word(ctx, old[3], d),
        add_word(ctx, old[4], e),
        add_word(ctx, old[5], f),
        add_word(ctx, old[6], g),
        add_word(ctx, old[7], h),
    ];

    let zero = ctx.constant(Gf2::ZERO);
    let mut out = [zero; 256];
    for (i, word) in new_state.iter().enumerate() {
        out[i * 32..(i + 1) * 32].copy_from_slice(word);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::WitnessCtx;
    use itybity::{FromBitIterator, ToBits};
    use sha2::compress256;

    fn run_compress(block: &[u8; 64], state: &[u32; 8]) -> ([u32; 8], usize) {
        let msg_words: [u32; 16] = core::array::from_fn(|i| {
            u32::from_be_bytes(block[i * 4..i * 4 + 4].try_into().unwrap())
        });
        let msg: [Gf2; 512] = <[Gf2; 512]>::from_lsb0_iter(msg_words.iter_lsb0());
        let state_in: [Gf2; 256] = <[Gf2; 256]>::from_lsb0_iter(state.iter_lsb0());

        let mut witness = Vec::new();
        let mut ctx = WitnessCtx {
            witness: &mut witness,
        };
        let out = compress(&mut ctx, msg, state_in);

        let out_words: [u32; 8] = <[u32; 8]>::from_lsb0_iter(out.iter().map(|g| g.0));
        (out_words, witness.len())
    }

    #[test]
    fn test_compress_zero_block() {
        let block = [0u8; 64];
        let (got, and_count) = run_compress(&block, &H0);

        let mut expected = H0;
        compress256(&mut expected, &[block.into()]);

        assert_eq!(got, expected);
        assert_eq!(and_count, AND_PER_BLOCK);
    }

    #[test]
    fn test_compress_pattern_block() {
        let block: [u8; 64] = core::array::from_fn(|i| i as u8);
        let (got, and_count) = run_compress(&block, &H0);

        let mut expected = H0;
        compress256(&mut expected, &[block.into()]);

        assert_eq!(got, expected);
        assert_eq!(and_count, AND_PER_BLOCK);
    }

    #[test]
    fn test_compress_nonzero_state() {
        let block: [u8; 64] = core::array::from_fn(|i| (i as u8).wrapping_mul(7).wrapping_add(3));
        let state: [u32; 8] = [
            0x01234567, 0x89abcdef, 0xfedcba98, 0x76543210, 0xdeadbeef, 0xcafebabe, 0x0badf00d,
            0x12345678,
        ];
        let (got, _) = run_compress(&block, &state);

        let mut expected = state;
        compress256(&mut expected, &[block.into()]);

        assert_eq!(got, expected);
    }
}
