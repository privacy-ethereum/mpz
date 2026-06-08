#![allow(dead_code)]

use super::*;

pub(crate) fn divrem_u_n<C: Context<Field = Gf2>, const N: usize>(
    ctx: &mut C,
    a: [C::Wire; N],
    b: [C::Wire; N],
) -> ([C::Wire; N], [C::Wire; N]) {
    let z = zero(ctx);
    let mut q = [z; N];
    let mut r: [C::Wire; N] = [z; N];
    for i in (0..N).rev() {
        let mut new_r = [z; N];
        for j in 1..N {
            new_r[j] = r[j - 1];
        }
        new_r[0] = a[i];
        let (diff, borrow) = sub_with_borrow_n(ctx, new_r, b);
        let success = not(ctx, borrow);
        r = mux_arr(ctx, success, diff, new_r);
        q[i] = success;
    }
    (q, r)
}

pub(crate) fn divrem_s_n<C: Context<Field = Gf2>, const N: usize>(
    ctx: &mut C,
    a: [C::Wire; N],
    b: [C::Wire; N],
) -> ([C::Wire; N], [C::Wire; N]) {
    let sign_a = a[N - 1];
    let sign_b = b[N - 1];
    let neg_a = neg_n(ctx, a);
    let neg_b = neg_n(ctx, b);
    let abs_a = mux_arr(ctx, sign_a, neg_a, a);
    let abs_b = mux_arr(ctx, sign_b, neg_b, b);
    let (uq, ur) = divrem_u_n(ctx, abs_a, abs_b);
    let q_sign = ctx.add(sign_a, sign_b);
    let neg_uq = neg_n(ctx, uq);
    let neg_ur = neg_n(ctx, ur);
    let q = mux_arr(ctx, q_sign, neg_uq, uq);
    let r = mux_arr(ctx, sign_a, neg_ur, ur);
    (q, r)
}
