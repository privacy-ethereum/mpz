#![allow(dead_code)]

use super::*;

pub(crate) fn eqz_n<C: Context<Field = Gf2>, const N: usize>(
    ctx: &mut C,
    a: [C::Wire; N],
) -> C::Wire {
    let one_w = one(ctx);
    let mut acc = ctx.add(a[0], one_w);
    for &w in &a[1..] {
        let inv = ctx.add(w, one_w);
        acc = ctx.mul(acc, inv);
    }
    acc
}

pub(crate) fn eq_n<C: Context<Field = Gf2>, const N: usize>(
    ctx: &mut C,
    a: [C::Wire; N],
    b: [C::Wire; N],
) -> C::Wire {
    let xor = xor_arr(ctx, a, b);
    eqz_n(ctx, xor)
}

pub(crate) fn ne_n<C: Context<Field = Gf2>, const N: usize>(
    ctx: &mut C,
    a: [C::Wire; N],
    b: [C::Wire; N],
) -> C::Wire {
    let e = eq_n(ctx, a, b);
    not(ctx, e)
}

pub(crate) fn lt_u_n<C: Context<Field = Gf2>, const N: usize>(
    ctx: &mut C,
    a: [C::Wire; N],
    b: [C::Wire; N],
) -> C::Wire {
    sub_with_borrow_n(ctx, a, b).1
}

pub(crate) fn lt_s_n<C: Context<Field = Gf2>, const N: usize>(
    ctx: &mut C,
    a: [C::Wire; N],
    b: [C::Wire; N],
) -> C::Wire {
    let one_w = one(ctx);
    let mut a_flip = a;
    a_flip[N - 1] = ctx.add(a[N - 1], one_w);
    let mut b_flip = b;
    b_flip[N - 1] = ctx.add(b[N - 1], one_w);
    lt_u_n(ctx, a_flip, b_flip)
}
