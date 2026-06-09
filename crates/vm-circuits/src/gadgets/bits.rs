#![allow(dead_code)]

use super::*;

#[inline]
pub(crate) fn one<C: Context<Field = Gf2>>(ctx: &mut C) -> C::Wire {
    ctx.constant(Gf2::one())
}

#[inline]
pub(crate) fn zero<C: Context<Field = Gf2>>(ctx: &mut C) -> C::Wire {
    ctx.constant(Gf2::zero())
}

#[inline]
pub(crate) fn not<C: Context<Field = Gf2>>(ctx: &mut C, x: C::Wire) -> C::Wire {
    let one = one(ctx);
    ctx.add(x, one)
}

#[inline]
pub(crate) fn mux_bit<C: Context<Field = Gf2>>(
    ctx: &mut C,
    cond: C::Wire,
    t: C::Wire,
    f: C::Wire,
) -> C::Wire {
    let diff = ctx.add(t, f);
    let masked = ctx.mul(cond, diff);
    ctx.add(masked, f)
}

#[inline]
pub(crate) fn or_bit<C: Context<Field = Gf2>>(ctx: &mut C, a: C::Wire, b: C::Wire) -> C::Wire {
    let xor = ctx.add(a, b);
    let and = ctx.mul(a, b);
    ctx.add(xor, and)
}

#[inline]
pub(crate) fn zeros<C: Context<Field = Gf2>, const N: usize>(ctx: &mut C) -> [C::Wire; N] {
    let z = zero(ctx);
    [z; N]
}

pub(crate) fn xor_arr<C: Context<Field = Gf2>, const N: usize>(
    ctx: &mut C,
    a: [C::Wire; N],
    b: [C::Wire; N],
) -> [C::Wire; N] {
    let mut out = a;
    for i in 0..N {
        out[i] = ctx.add(a[i], b[i]);
    }
    out
}

pub(crate) fn and_arr<C: Context<Field = Gf2>, const N: usize>(
    ctx: &mut C,
    a: [C::Wire; N],
    b: [C::Wire; N],
) -> [C::Wire; N] {
    let mut out = a;
    for i in 0..N {
        out[i] = ctx.mul(a[i], b[i]);
    }
    out
}

pub(crate) fn or_arr<C: Context<Field = Gf2>, const N: usize>(
    ctx: &mut C,
    a: [C::Wire; N],
    b: [C::Wire; N],
) -> [C::Wire; N] {
    let mut out = a;
    for i in 0..N {
        out[i] = or_bit(ctx, a[i], b[i]);
    }
    out
}

pub(crate) fn mux_arr<C: Context<Field = Gf2>, const N: usize>(
    ctx: &mut C,
    cond: C::Wire,
    t: [C::Wire; N],
    f: [C::Wire; N],
) -> [C::Wire; N] {
    let mut out = t;
    for i in 0..N {
        out[i] = mux_bit(ctx, cond, t[i], f[i]);
    }
    out
}
