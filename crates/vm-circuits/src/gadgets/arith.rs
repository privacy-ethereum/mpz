#![allow(dead_code)]

use super::*;

#[inline]
pub(crate) fn full_adder<C: Context<Field = Gf2>>(
    ctx: &mut C,
    a: C::Wire,
    b: C::Wire,
    cin: C::Wire,
) -> (C::Wire, C::Wire) {
    let ab = ctx.add(a, b);
    let sum = ctx.add(ab, cin);
    let x = ctx.add(a, cin);
    let y = ctx.add(b, cin);
    let z = ctx.mul(x, y);
    let cout = ctx.add(z, cin);
    (sum, cout)
}

pub(crate) fn add_with_carry_n<C: Context<Field = Gf2>, const N: usize>(
    ctx: &mut C,
    a: [C::Wire; N],
    b: [C::Wire; N],
    cin: C::Wire,
) -> ([C::Wire; N], C::Wire) {
    let mut sum = a;
    let mut carry = cin;
    for i in 0..N {
        let (s, c) = full_adder(ctx, a[i], b[i], carry);
        sum[i] = s;
        carry = c;
    }
    (sum, carry)
}

pub(crate) fn add_n<C: Context<Field = Gf2>, const N: usize>(
    ctx: &mut C,
    a: [C::Wire; N],
    b: [C::Wire; N],
) -> [C::Wire; N] {
    let cin = zero(ctx);
    add_with_carry_n(ctx, a, b, cin).0
}

pub(crate) fn neg_n<C: Context<Field = Gf2>, const N: usize>(
    ctx: &mut C,
    a: [C::Wire; N],
) -> [C::Wire; N] {
    let one_w = one(ctx);
    let mut inv = a;
    for i in 0..N {
        inv[i] = ctx.add(a[i], one_w);
    }
    let cin = one(ctx);
    let zeros: [C::Wire; N] = zeros(ctx);
    add_with_carry_n(ctx, inv, zeros, cin).0
}

pub(crate) fn sub_with_borrow_n<C: Context<Field = Gf2>, const N: usize>(
    ctx: &mut C,
    a: [C::Wire; N],
    b: [C::Wire; N],
) -> ([C::Wire; N], C::Wire) {
    let one_w = one(ctx);
    let mut inv_b = b;
    for i in 0..N {
        inv_b[i] = ctx.add(b[i], one_w);
    }
    let cin = one(ctx);
    let (diff, cout) = add_with_carry_n(ctx, a, inv_b, cin);
    let borrow = not(ctx, cout);
    (diff, borrow)
}

pub(crate) fn sub_n<C: Context<Field = Gf2>, const N: usize>(
    ctx: &mut C,
    a: [C::Wire; N],
    b: [C::Wire; N],
) -> [C::Wire; N] {
    sub_with_borrow_n(ctx, a, b).0
}

pub(crate) fn schoolbook_full_dyn<C: Context<Field = Gf2>>(
    ctx: &mut C,
    a: &[C::Wire],
    b: &[C::Wire],
) -> Vec<C::Wire> {
    let na = a.len();
    let nb = b.len();
    let total = na + nb;
    let z = zero(ctx);
    let mut acc = vec![z; total];
    for (j, &bj) in b.iter().enumerate() {
        let mut partial = Vec::with_capacity(na);
        for &ai in a {
            partial.push(ctx.mul(ai, bj));
        }
        add_at_offset(ctx, &mut acc, &partial, j);
    }
    acc
}

pub(crate) fn add_at_offset<C: Context<Field = Gf2>>(
    ctx: &mut C,
    dst: &mut [C::Wire],
    val: &[C::Wire],
    offset: usize,
) {
    let z = zero(ctx);
    let mut carry = z;
    let mut i = 0;
    while i < val.len() && offset + i < dst.len() {
        let (sum, cout) = full_adder(ctx, dst[offset + i], val[i], carry);
        dst[offset + i] = sum;
        carry = cout;
        i += 1;
    }
    let mut pos = offset + val.len();
    while pos < dst.len() {
        let (sum, cout) = full_adder(ctx, dst[pos], z, carry);
        dst[pos] = sum;
        carry = cout;
        pos += 1;
    }
}

pub(crate) fn add_dyn<C: Context<Field = Gf2>>(
    ctx: &mut C,
    a: &[C::Wire],
    b: &[C::Wire],
) -> Vec<C::Wire> {
    let len = std::cmp::max(a.len(), b.len()) + 1;
    let z = zero(ctx);
    let mut out = Vec::with_capacity(len);
    let mut carry = z;
    for i in 0..len {
        let ai = if i < a.len() { a[i] } else { z };
        let bi = if i < b.len() { b[i] } else { z };
        let (sum, cout) = full_adder(ctx, ai, bi, carry);
        out.push(sum);
        carry = cout;
    }
    out
}

pub(crate) fn sub_dyn<C: Context<Field = Gf2>>(
    ctx: &mut C,
    a: &[C::Wire],
    b: &[C::Wire],
) -> Vec<C::Wire> {
    let len = std::cmp::max(a.len(), b.len());
    let z = zero(ctx);
    let one_w = one(ctx);
    let mut out = Vec::with_capacity(len);
    let mut carry = one_w;
    for i in 0..len {
        let ai = if i < a.len() { a[i] } else { z };
        let bi = if i < b.len() { b[i] } else { z };
        let bi_inv = ctx.add(bi, one_w);
        let (sum, cout) = full_adder(ctx, ai, bi_inv, carry);
        out.push(sum);
        carry = cout;
    }
    out
}

pub(crate) const KARATSUBA_BASE: usize = 8;

pub(crate) fn karatsuba_full<C: Context<Field = Gf2>>(
    ctx: &mut C,
    a: &[C::Wire],
    b: &[C::Wire],
) -> Vec<C::Wire> {
    let n = a.len();
    debug_assert_eq!(b.len(), n);
    if n <= KARATSUBA_BASE {
        return schoolbook_full_dyn(ctx, a, b);
    }
    let half = n / 2;
    let (a_lo, a_hi) = a.split_at(half);
    let (b_lo, b_hi) = b.split_at(half);
    let z0 = karatsuba_full(ctx, a_lo, b_lo);
    let z2 = karatsuba_full(ctx, a_hi, b_hi);
    let a_sum = add_dyn(ctx, a_lo, a_hi);
    let b_sum = add_dyn(ctx, b_lo, b_hi);
    let m_full = karatsuba_full(ctx, &a_sum, &b_sum);
    let m_minus_z0 = sub_dyn(ctx, &m_full, &z0);
    let z1 = sub_dyn(ctx, &m_minus_z0, &z2);
    let total = 2 * n;
    let zw = zero(ctx);
    let mut result = vec![zw; total];
    let z0_len = std::cmp::min(z0.len(), total);
    result[..z0_len].copy_from_slice(&z0[..z0_len]);
    add_at_offset(ctx, &mut result, &z1, half);
    add_at_offset(ctx, &mut result, &z2, 2 * half);
    result
}

pub(crate) fn mul_n<C: Context<Field = Gf2>, const N: usize>(
    ctx: &mut C,
    a: [C::Wire; N],
    b: [C::Wire; N],
) -> [C::Wire; N] {
    let full = karatsuba_full(ctx, &a, &b);
    let mut out = a;
    out.copy_from_slice(&full[..N]);
    out
}
