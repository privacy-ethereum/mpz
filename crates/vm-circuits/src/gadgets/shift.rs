#![allow(dead_code)]

use super::*;

pub(crate) fn shift_left_const<W: Copy, const N: usize>(a: [W; N], k: usize, fill: W) -> [W; N] {
    let mut out = [fill; N];
    if k < N {
        for i in 0..(N - k) {
            out[i + k] = a[i];
        }
    }
    out
}

pub(crate) fn shift_right_const<W: Copy, const N: usize>(a: [W; N], k: usize, fill: W) -> [W; N] {
    let mut out = [fill; N];
    if k < N {
        for i in k..N {
            out[i - k] = a[i];
        }
    }
    out
}

pub(crate) fn rotate_left_const<W: Copy, const N: usize>(a: [W; N], k: usize) -> [W; N] {
    let k = k % N;
    let mut out = a;
    for i in 0..N {
        out[(i + k) % N] = a[i];
    }
    out
}

pub(crate) fn rotate_right_const<W: Copy, const N: usize>(a: [W; N], k: usize) -> [W; N] {
    let k = k % N;
    let mut out = a;
    for i in 0..N {
        out[i] = a[(i + k) % N];
    }
    out
}

pub(crate) fn barrel_shift<C, const N: usize, F>(
    ctx: &mut C,
    a: [C::Wire; N],
    b: [C::Wire; N],
    shift_const: F,
) -> [C::Wire; N]
where
    C: Context<Field = Gf2>,
    F: Fn([C::Wire; N], usize) -> [C::Wire; N],
{
    let log2_n = N.trailing_zeros() as usize;
    let mut result = a;
    for k in 0..log2_n {
        let shifted = shift_const(result, 1 << k);
        result = mux_arr(ctx, b[k], shifted, result);
    }
    result
}

pub(crate) fn shl_n<C: Context<Field = Gf2>, const N: usize>(
    ctx: &mut C,
    a: [C::Wire; N],
    b: [C::Wire; N],
) -> [C::Wire; N] {
    let z = zero(ctx);
    barrel_shift(ctx, a, b, |arr, k| shift_left_const(arr, k, z))
}

pub(crate) fn shr_u_n<C: Context<Field = Gf2>, const N: usize>(
    ctx: &mut C,
    a: [C::Wire; N],
    b: [C::Wire; N],
) -> [C::Wire; N] {
    let z = zero(ctx);
    barrel_shift(ctx, a, b, |arr, k| shift_right_const(arr, k, z))
}

pub(crate) fn shr_s_n<C: Context<Field = Gf2>, const N: usize>(
    ctx: &mut C,
    a: [C::Wire; N],
    b: [C::Wire; N],
) -> [C::Wire; N] {
    let sign = a[N - 1];
    barrel_shift(ctx, a, b, |arr, k| shift_right_const(arr, k, sign))
}

pub(crate) fn rotl_n<C: Context<Field = Gf2>, const N: usize>(
    ctx: &mut C,
    a: [C::Wire; N],
    b: [C::Wire; N],
) -> [C::Wire; N] {
    barrel_shift(ctx, a, b, |arr, k| rotate_left_const(arr, k))
}

pub(crate) fn rotr_n<C: Context<Field = Gf2>, const N: usize>(
    ctx: &mut C,
    a: [C::Wire; N],
    b: [C::Wire; N],
) -> [C::Wire; N] {
    barrel_shift(ctx, a, b, |arr, k| rotate_right_const(arr, k))
}
