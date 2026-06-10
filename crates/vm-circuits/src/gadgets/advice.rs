#![allow(dead_code)]

use super::*;

/// Quotient and remainder wires returned by the division advice gadgets.
type DivRemResult<C, const N: usize> =
    Result<([<C as Context>::Wire; N], [<C as Context>::Wire; N]), <C as Context>::Error>;

pub(crate) fn divrem_u_advice_n<C: Context<Field = Gf2>, const N: usize>(
    ctx: &mut C,
    a: [C::Wire; N],
    b: [C::Wire; N],
    q: [C::Wire; N],
    r: [C::Wire; N],
) -> DivRemResult<C, N> {
    let qb = mul_n(ctx, q, b);
    let sum = add_n(ctx, qb, r);
    let diff = xor_arr(ctx, sum, a);
    for w in diff {
        ctx.assert_const(w, Gf2::zero())?;
    }
    let lt = lt_u_n(ctx, r, b);
    ctx.assert_const(lt, Gf2::one())?;
    Ok((q, r))
}

pub(crate) fn divrem_s_advice_n<C: Context<Field = Gf2>, const N: usize>(
    ctx: &mut C,
    a: [C::Wire; N],
    b: [C::Wire; N],
    q: [C::Wire; N],
    r: [C::Wire; N],
) -> DivRemResult<C, N> {
    let qb = mul_n(ctx, q, b);
    let sum = add_n(ctx, qb, r);
    let diff = xor_arr(ctx, sum, a);
    for w in diff {
        ctx.assert_const(w, Gf2::zero())?;
    }
    let abs_r = {
        let nr = neg_n(ctx, r);
        mux_arr(ctx, r[N - 1], nr, r)
    };
    let abs_b = {
        let nb = neg_n(ctx, b);
        mux_arr(ctx, b[N - 1], nb, b)
    };
    let lt = lt_u_n(ctx, abs_r, abs_b);
    ctx.assert_const(lt, Gf2::one())?;
    let r_eqz = eqz_n(ctx, r);
    let r_nz = not(ctx, r_eqz);
    let sign_diff = ctx.add(r[N - 1], a[N - 1]);
    let sign_violation = ctx.mul(r_nz, sign_diff);
    ctx.assert_const(sign_violation, Gf2::zero())?;
    Ok((q, r))
}

pub(crate) fn popcnt_advice_n<C: Context<Field = Gf2>, const N: usize>(
    ctx: &mut C,
    a: [C::Wire; N],
    advice: [C::Wire; N],
) -> Result<[C::Wire; N], C::Error> {
    let computed = popcnt_tree_n(ctx, a);
    let diff = xor_arr(ctx, computed, advice);
    for w in diff {
        ctx.assert_const(w, Gf2::zero())?;
    }
    Ok(advice)
}

pub(crate) fn clz_advice_n<C: Context<Field = Gf2>, const N: usize>(
    ctx: &mut C,
    a: [C::Wire; N],
    advice: [C::Wire; N],
) -> Result<[C::Wire; N], C::Error> {
    let one_w = one(ctx);
    let mut lz = a;
    lz[N - 1] = ctx.add(a[N - 1], one_w);
    for i in (0..N - 1).rev() {
        let n_a = ctx.add(a[i], one_w);
        lz[i] = ctx.mul(lz[i + 1], n_a);
    }
    let computed = popcnt_tree_n(ctx, lz);
    let diff = xor_arr(ctx, computed, advice);
    for w in diff {
        ctx.assert_const(w, Gf2::zero())?;
    }
    Ok(advice)
}

pub(crate) fn ctz_advice_n<C: Context<Field = Gf2>, const N: usize>(
    ctx: &mut C,
    a: [C::Wire; N],
    advice: [C::Wire; N],
) -> Result<[C::Wire; N], C::Error> {
    let one_w = one(ctx);
    let mut tz = a;
    tz[0] = ctx.add(a[0], one_w);
    for i in 1..N {
        let n_a = ctx.add(a[i], one_w);
        tz[i] = ctx.mul(tz[i - 1], n_a);
    }
    let computed = popcnt_tree_n(ctx, tz);
    let diff = xor_arr(ctx, computed, advice);
    for w in diff {
        ctx.assert_const(w, Gf2::zero())?;
    }
    Ok(advice)
}

/// Quotient and remainder of unsigned `a / b` over `n` bits (returning `(0, a)`
/// for `b == 0`, matching the circuit's divide-by-zero convention).
pub(crate) fn divrem_u_advice_values(a: u64, b: u64, n: usize) -> (u64, u64) {
    let mask = if n == 64 { u64::MAX } else { (1u64 << n) - 1 };
    let a = a & mask;
    let b = b & mask;
    match a.checked_div(b) {
        Some(q) => (q, a % b),
        None => (0, a),
    }
}

/// Quotient and remainder of signed `a / b` over `n` bits, returned as
/// `n`-bit two's-complement patterns (zero-extended into `u64`).
pub(crate) fn divrem_s_advice_values(a: u64, b: u64, n: usize) -> (u64, u64) {
    if n == 32 {
        let (sa, sb) = (a as u32 as i32, b as u32 as i32);
        if sb == 0 {
            (0, sa as u32 as u64)
        } else {
            (
                sa.wrapping_div(sb) as u32 as u64,
                sa.wrapping_rem(sb) as u32 as u64,
            )
        }
    } else {
        let (sa, sb) = (a as i64, b as i64);
        if sb == 0 {
            (0, sa as u64)
        } else {
            (sa.wrapping_div(sb) as u64, sa.wrapping_rem(sb) as u64)
        }
    }
}

/// Population count of the low `n` bits of `a`.
pub(crate) fn popcnt_advice_values(a: u64, n: usize) -> u64 {
    let mask = if n == 64 { u64::MAX } else { (1u64 << n) - 1 };
    (a & mask).count_ones() as u64
}

/// Number of leading zeros of `a` within its low `n` bits.
pub(crate) fn clz_advice_values(a: u64, n: usize) -> u64 {
    let mask = if n == 64 { u64::MAX } else { (1u64 << n) - 1 };
    let v = a & mask;
    v.leading_zeros() as u64 - (64 - n as u64)
}

/// Number of trailing zeros of `a` within its low `n` bits (`n` if zero).
pub(crate) fn ctz_advice_values(a: u64, n: usize) -> u64 {
    let mask = if n == 64 { u64::MAX } else { (1u64 << n) - 1 };
    let v = a & mask;
    if v == 0 {
        n as u64
    } else if n == 32 {
        (v as u32).trailing_zeros() as u64
    } else {
        v.trailing_zeros() as u64
    }
}
