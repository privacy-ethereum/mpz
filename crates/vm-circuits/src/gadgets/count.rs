#![allow(dead_code)]

use super::*;

pub(crate) fn popcnt_n<C: Context<Field = Gf2>, const N: usize>(
    ctx: &mut C,
    a: [C::Wire; N],
) -> [C::Wire; N] {
    let z = zero(ctx);
    let mut count: [C::Wire; N] = [z; N];
    for i in 0..N {
        let mut inc = [z; N];
        inc[0] = a[i];
        count = add_n(ctx, count, inc);
    }
    count
}

pub(crate) fn clz_n<C: Context<Field = Gf2>, const N: usize>(
    ctx: &mut C,
    a: [C::Wire; N],
) -> [C::Wire; N] {
    let z = zero(ctx);
    let mut count: [C::Wire; N] = [z; N];
    let mut done = z;
    for i in (0..N).rev() {
        let bit = a[i];
        let not_done = not(ctx, done);
        let inc_bit = {
            let not_bit = not(ctx, bit);
            ctx.mul(not_done, not_bit)
        };
        let mut inc = [z; N];
        inc[0] = inc_bit;
        count = add_n(ctx, count, inc);
        let nd_b = ctx.mul(not_done, bit);
        done = ctx.add(done, nd_b);
    }
    count
}

pub(crate) fn ctz_n<C: Context<Field = Gf2>, const N: usize>(
    ctx: &mut C,
    a: [C::Wire; N],
) -> [C::Wire; N] {
    let z = zero(ctx);
    let mut count: [C::Wire; N] = [z; N];
    let mut done = z;
    for i in 0..N {
        let bit = a[i];
        let not_done = not(ctx, done);
        let inc_bit = {
            let not_bit = not(ctx, bit);
            ctx.mul(not_done, not_bit)
        };
        let mut inc = [z; N];
        inc[0] = inc_bit;
        count = add_n(ctx, count, inc);
        let nd_b = ctx.mul(not_done, bit);
        done = ctx.add(done, nd_b);
    }
    count
}

pub(crate) fn sign_extend_low_in_place<C: Context<Field = Gf2>, const N: usize>(
    a: [C::Wire; N],
    m: usize,
) -> [C::Wire; N] {
    let sign = a[m - 1];
    let mut out = [sign; N];
    for i in 0..m {
        out[i] = a[i];
    }
    out
}

pub(crate) fn popcnt_tree_n<C: Context<Field = Gf2>, const N: usize>(
    ctx: &mut C,
    a: [C::Wire; N],
) -> [C::Wire; N] {
    let z = zero(ctx);
    let mut level: Vec<Vec<C::Wire>> = a.iter().map(|&w| vec![w]).collect();
    while level.len() > 1 {
        let mut next: Vec<Vec<C::Wire>> = Vec::with_capacity(level.len().div_ceil(2));
        let mut iter = level.into_iter();
        loop {
            match (iter.next(), iter.next()) {
                (Some(x), Some(y)) => next.push(add_dyn(ctx, &x, &y)),
                (Some(x), None) => next.push(x),
                _ => break,
            }
        }
        level = next;
    }
    let result = level.into_iter().next().expect("non-empty input");
    let mut out = [z; N];
    for (i, w) in result.iter().enumerate().take(N) {
        out[i] = *w;
    }
    out
}
