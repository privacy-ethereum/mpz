use crate::harness::{from_bits, pairs_u64, run_bin, to_bits};
use crate::{divrem_s_advice_n, divrem_s_advice_values, divrem_u_advice_n, divrem_u_advice_values};
use crate::{divrem_s_n, divrem_u_n};
use mpz_circuits_new::{Context, WitnessCtx};
use mpz_fields::gf2::Gf2;
use proptest::prelude::*;

fn div_u_w<C: Context<Field = Gf2>, const N: usize>(
    ctx: &mut C,
    a: [C::Wire; N],
    b: [C::Wire; N],
) -> [C::Wire; N] {
    divrem_u_n(ctx, a, b).0
}

fn rem_u_w<C: Context<Field = Gf2>, const N: usize>(
    ctx: &mut C,
    a: [C::Wire; N],
    b: [C::Wire; N],
) -> [C::Wire; N] {
    divrem_u_n(ctx, a, b).1
}

fn div_s_w<C: Context<Field = Gf2>, const N: usize>(
    ctx: &mut C,
    a: [C::Wire; N],
    b: [C::Wire; N],
) -> [C::Wire; N] {
    divrem_s_n(ctx, a, b).0
}

fn rem_s_w<C: Context<Field = Gf2>, const N: usize>(
    ctx: &mut C,
    a: [C::Wire; N],
    b: [C::Wire; N],
) -> [C::Wire; N] {
    divrem_s_n(ctx, a, b).1
}

prop_compose! {
    fn biased_u32()(
        sel in 0u32..8,
        k in 0u32..32,
        small in 0u32..16,
        rand in any::<u32>(),
    ) -> u32 {
        match sel {
            0 => 0,
            1 => 1,
            2 => u32::MAX,
            3 => i32::MIN as u32,
            4 => i32::MAX as u32,
            5 => 1u32 << k,
            6 => small,
            _ => rand,
        }
    }
}

prop_compose! {
    fn biased_u64()(
        sel in 0u64..8,
        k in 0u32..64,
        small in 0u64..16,
        rand in any::<u64>(),
    ) -> u64 {
        match sel {
            0 => 0,
            1 => 1,
            2 => u64::MAX,
            3 => i64::MIN as u64,
            4 => i64::MAX as u64,
            5 => 1u64 << k,
            6 => small,
            _ => rand,
        }
    }
}

prop_compose! {
    fn biased_u32_nz()(
        sel in 0u32..7,
        k in 0u32..32,
        small in 1u32..16,
        rand in any::<u32>(),
    ) -> u32 {
        match sel {
            0 => 1,
            1 => u32::MAX,
            2 => i32::MIN as u32,
            3 => i32::MAX as u32,
            4 => 1u32 << k,
            5 => small,
            _ => rand | 1,
        }
    }
}

prop_compose! {
    fn biased_u64_nz()(
        sel in 0u64..7,
        k in 0u32..64,
        small in 1u64..16,
        rand in any::<u64>(),
    ) -> u64 {
        match sel {
            0 => 1,
            1 => u64::MAX,
            2 => i64::MIN as u64,
            3 => i64::MAX as u64,
            4 => 1u64 << k,
            5 => small,
            _ => rand | 1,
        }
    }
}

fn cfg() -> ProptestConfig {
    ProptestConfig {
        cases: 8192,
        ..ProptestConfig::default()
    }
}

proptest! {
    #![proptest_config(cfg())]

    #[test]
    fn i32_div_rem_u_prop(a in biased_u32(), b in biased_u32_nz()) {
        let got_div = run_bin::<_, 32>(|c, a, b| divrem_u_n(c, a, b).0, a as u64, b as u64) as u32;
        let got_rem = run_bin::<_, 32>(|c, a, b| divrem_u_n(c, a, b).1, a as u64, b as u64) as u32;
        prop_assert_eq!(got_div, a / b, "div_u a={:#x} b={:#x}", a, b);
        prop_assert_eq!(got_rem, a % b, "rem_u a={:#x} b={:#x}", a, b);
    }

    #[test]
    fn i32_div_rem_s_prop(a in biased_u32(), b in biased_u32_nz()) {
        let (sa, sb) = (a as i32, b as i32);
        let got_div = run_bin::<_, 32>(|c, a, b| divrem_s_n(c, a, b).0, a as u64, b as u64) as i32;
        let got_rem = run_bin::<_, 32>(|c, a, b| divrem_s_n(c, a, b).1, a as u64, b as u64) as i32;
        prop_assert_eq!(got_div, sa.wrapping_div(sb), "div_s a={} b={}", sa, sb);
        prop_assert_eq!(got_rem, sa.wrapping_rem(sb), "rem_s a={} b={}", sa, sb);
    }

    #[test]
    fn i64_div_rem_u_prop(a in biased_u64(), b in biased_u64_nz()) {
        let got_div = run_bin::<_, 64>(|c, a, b| divrem_u_n(c, a, b).0, a, b);
        let got_rem = run_bin::<_, 64>(|c, a, b| divrem_u_n(c, a, b).1, a, b);
        prop_assert_eq!(got_div, a / b, "div_u a={:#x} b={:#x}", a, b);
        prop_assert_eq!(got_rem, a % b, "rem_u a={:#x} b={:#x}", a, b);
    }

    #[test]
    fn i64_div_rem_s_prop(a in biased_u64(), b in biased_u64_nz()) {
        let (sa, sb) = (a as i64, b as i64);
        let got_div = run_bin::<_, 64>(|c, a, b| divrem_s_n(c, a, b).0, a, b) as i64;
        let got_rem = run_bin::<_, 64>(|c, a, b| divrem_s_n(c, a, b).1, a, b) as i64;
        prop_assert_eq!(got_div, sa.wrapping_div(sb), "div_s a={} b={}", sa, sb);
        prop_assert_eq!(got_rem, sa.wrapping_rem(sb), "rem_s a={} b={}", sa, sb);
    }
}

#[test]
fn i32_div_rem_u_boundaries() {
    let edges: [u32; 8] = [
        0,
        1,
        u32::MAX,
        i32::MIN as u32,
        i32::MAX as u32,
        2,
        0x1000_0000,
        0xDEAD_BEEF,
    ];
    for &a in &edges {
        for &b in &edges {
            if b == 0 {
                continue;
            }
            let got_div =
                run_bin::<_, 32>(|c, a, b| divrem_u_n(c, a, b).0, a as u64, b as u64) as u32;
            let got_rem =
                run_bin::<_, 32>(|c, a, b| divrem_u_n(c, a, b).1, a as u64, b as u64) as u32;
            assert_eq!(got_div, a / b, "div_u a={a:#x} b={b:#x}");
            assert_eq!(got_rem, a % b, "rem_u a={a:#x} b={b:#x}");
        }
    }
}

#[test]
fn i32_div_rem_s_boundaries() {
    let edges: [i32; 9] = [
        0,
        1,
        -1,
        i32::MIN,
        i32::MAX,
        2,
        -2,
        0x1234_5678,
        -0x1234_5678,
    ];
    for &sa in &edges {
        for &sb in &edges {
            if sb == 0 {
                continue;
            }
            let a = sa as u32;
            let b = sb as u32;
            let got_div =
                run_bin::<_, 32>(|c, a, b| divrem_s_n(c, a, b).0, a as u64, b as u64) as i32;
            let got_rem =
                run_bin::<_, 32>(|c, a, b| divrem_s_n(c, a, b).1, a as u64, b as u64) as i32;
            assert_eq!(got_div, sa.wrapping_div(sb), "div_s a={sa} b={sb}");
            assert_eq!(got_rem, sa.wrapping_rem(sb), "rem_s a={sa} b={sb}");
        }
    }
}

#[test]
fn i32_div_s_int_min_over_neg_one() {
    let a = i32::MIN as u32;
    let b = (-1i32) as u32;
    let got_div = run_bin::<_, 32>(|c, a, b| divrem_s_n(c, a, b).0, a as u64, b as u64) as i32;
    let got_rem = run_bin::<_, 32>(|c, a, b| divrem_s_n(c, a, b).1, a as u64, b as u64) as i32;
    assert_eq!(got_div, i32::MIN, "INT_MIN / -1 wraps to INT_MIN");
    assert_eq!(got_div, i32::MIN.wrapping_div(-1));
    assert_eq!(got_rem, 0, "INT_MIN % -1 == 0");
    assert_eq!(got_rem, i32::MIN.wrapping_rem(-1));
}

#[test]
fn i64_div_s_int_min_over_neg_one() {
    let a = i64::MIN as u64;
    let b = (-1i64) as u64;
    let got_div = run_bin::<_, 64>(|c, a, b| divrem_s_n(c, a, b).0, a, b) as i64;
    let got_rem = run_bin::<_, 64>(|c, a, b| divrem_s_n(c, a, b).1, a, b) as i64;
    assert_eq!(got_div, i64::MIN, "INT_MIN / -1 wraps to INT_MIN");
    assert_eq!(got_div, i64::MIN.wrapping_div(-1));
    assert_eq!(got_rem, 0, "INT_MIN % -1 == 0");
    assert_eq!(got_rem, i64::MIN.wrapping_rem(-1));
}

#[test]
fn i32_div_rem_u_divisor_one_and_max() {
    for &a in &[0u32, 1, 2, i32::MIN as u32, i32::MAX as u32, u32::MAX] {
        assert_eq!(
            run_bin::<_, 32>(|c, a, b| divrem_u_n(c, a, b).0, a as u64, 1) as u32,
            a
        );
        assert_eq!(
            run_bin::<_, 32>(|c, a, b| divrem_u_n(c, a, b).1, a as u64, 1) as u32,
            0
        );
        let m = u32::MAX;
        assert_eq!(
            run_bin::<_, 32>(|c, a, b| divrem_u_n(c, a, b).0, a as u64, m as u64) as u32,
            a / m
        );
        assert_eq!(
            run_bin::<_, 32>(|c, a, b| divrem_u_n(c, a, b).1, a as u64, m as u64) as u32,
            a % m
        );
    }
}

#[test]
fn i64_div_rem_s_boundaries() {
    let edges: [i64; 7] = [0, 1, -1, i64::MIN, i64::MAX, 2, -2];
    for &sa in &edges {
        for &sb in &edges {
            if sb == 0 {
                continue;
            }
            let a = sa as u64;
            let b = sb as u64;
            let got_div = run_bin::<_, 64>(|c, a, b| divrem_s_n(c, a, b).0, a, b) as i64;
            let got_rem = run_bin::<_, 64>(|c, a, b| divrem_s_n(c, a, b).1, a, b) as i64;
            assert_eq!(got_div, sa.wrapping_div(sb), "div_s a={sa} b={sb}");
            assert_eq!(got_rem, sa.wrapping_rem(sb), "rem_s a={sa} b={sb}");
        }
    }
}

#[test]
fn divrem_u_exhaustive_n8() {
    for a in 0u8..=u8::MAX {
        for b in 1u8..=u8::MAX {
            let got_div = run_bin::<_, 8>(|c, a, b| div_u_w(c, a, b), a as u64, b as u64) as u8;
            let got_rem = run_bin::<_, 8>(|c, a, b| rem_u_w(c, a, b), a as u64, b as u64) as u8;
            assert_eq!(got_div, a / b, "div_u a={a} b={b}");
            assert_eq!(got_rem, a % b, "rem_u a={a} b={b}");
        }
    }
}

#[test]
fn divrem_s_exhaustive_n8() {
    for a in 0u8..=u8::MAX {
        for b in 1u8..=u8::MAX {
            let sa = a as i8;
            let sb = b as i8;
            let got_div =
                run_bin::<_, 8>(|c, a, b| div_s_w(c, a, b), a as u64, b as u64) as u8 as i8;
            let got_rem =
                run_bin::<_, 8>(|c, a, b| rem_s_w(c, a, b), a as u64, b as u64) as u8 as i8;
            assert_eq!(got_div, sa.wrapping_div(sb), "div_s a={sa} b={sb}");
            assert_eq!(got_rem, sa.wrapping_rem(sb), "rem_s a={sa} b={sb}");
        }
    }
}

fn run_u_advice_honest_32(a: u32, b: u32) -> (u32, u32) {
    let mut w = Vec::new();
    let mut ctx = WitnessCtx { witness: &mut w };
    let (hq, hr) = divrem_u_advice_values(a as u64, b as u64, 32);
    let q_bits = to_bits::<32>(hq);
    let r_bits = to_bits::<32>(hr);
    let (q, r) = divrem_u_advice_n::<_, 32>(
        &mut ctx,
        to_bits(a as u64),
        to_bits(b as u64),
        q_bits,
        r_bits,
    )
    .expect("honest advice satisfies constraints");
    (from_bits(q) as u32, from_bits(r) as u32)
}

fn run_s_advice_honest_32(a: u32, b: u32) -> (i32, i32) {
    let mut w = Vec::new();
    let mut ctx = WitnessCtx { witness: &mut w };
    let (hq, hr) = divrem_s_advice_values(a as u64, b as u64, 32);
    let q_bits = to_bits::<32>(hq);
    let r_bits = to_bits::<32>(hr);
    let (q, r) = divrem_s_advice_n::<_, 32>(
        &mut ctx,
        to_bits(a as u64),
        to_bits(b as u64),
        q_bits,
        r_bits,
    )
    .expect("honest advice satisfies constraints");
    (from_bits(q) as i32, from_bits(r) as i32)
}

proptest! {
    #![proptest_config(cfg())]

    #[test]
    fn divrem_u_advice_complete_32(a in biased_u32(), b in biased_u32_nz()) {
        let (q, r) = run_u_advice_honest_32(a, b);
        prop_assert_eq!(q, a / b);
        prop_assert_eq!(r, a % b);
    }

    #[test]
    fn divrem_s_advice_complete_32(a in biased_u32(), b in biased_u32_nz()) {
        let (sa, sb) = (a as i32, b as i32);
        let (q, r) = run_s_advice_honest_32(a, b);
        prop_assert_eq!(q, sa.wrapping_div(sb));
        prop_assert_eq!(r, sa.wrapping_rem(sb));
    }
}

#[test]
fn divrem_u_advice_complete_64() {
    for (a, b) in pairs_u64(16) {
        if b == 0 {
            continue;
        }
        let mut w = Vec::new();
        let mut ctx = WitnessCtx { witness: &mut w };
        let (hq, hr) = divrem_u_advice_values(a, b, 64);
        let q_bits = to_bits::<64>(hq);
        let r_bits = to_bits::<64>(hr);
        let (q, r) = divrem_u_advice_n::<_, 64>(&mut ctx, to_bits(a), to_bits(b), q_bits, r_bits)
            .expect("honest advice satisfies constraints");
        assert_eq!(from_bits(q), a / b);
        assert_eq!(from_bits(r), a % b);
    }
}

#[test]
fn divrem_s_advice_complete_64() {
    for (a, b) in pairs_u64(16) {
        let (sa, sb) = (a as i64, b as i64);
        if sb == 0 {
            continue;
        }
        let mut w = Vec::new();
        let mut ctx = WitnessCtx { witness: &mut w };
        let (hq, hr) = divrem_s_advice_values(a, b, 64);
        let q_bits = to_bits::<64>(hq);
        let r_bits = to_bits::<64>(hr);
        let (q, r) = divrem_s_advice_n::<_, 64>(&mut ctx, to_bits(a), to_bits(b), q_bits, r_bits)
            .expect("honest advice satisfies constraints");
        assert_eq!(from_bits(q) as i64, sa.wrapping_div(sb), "q for {sa}/{sb}");
        assert_eq!(from_bits(r) as i64, sa.wrapping_rem(sb), "r for {sa}%{sb}");
    }
}

const BOUNDARY_U32: &[u32] = &[
    0,
    1,
    2,
    3,
    (-1i32) as u32,
    (-2i32) as u32,
    (-3i32) as u32,
    i32::MIN as u32,
    i32::MAX as u32,
    (i32::MIN + 1) as u32,
    (i32::MAX - 1) as u32,
    u32::MAX,
    1 << 31,
    1 << 16,
    0x5555_5555,
    0xAAAA_AAAA,
];

const BOUNDARY_U64: &[u64] = &[
    0,
    1,
    2,
    3,
    (-1i64) as u64,
    (-2i64) as u64,
    (-3i64) as u64,
    i64::MIN as u64,
    i64::MAX as u64,
    (i64::MIN + 1) as u64,
    (i64::MAX - 1) as u64,
    u64::MAX,
    1 << 63,
    1 << 32,
    0x5555_5555_5555_5555,
    0xAAAA_AAAA_AAAA_AAAA,
];

fn run_u_advice_honest_64(a: u64, b: u64) -> (u64, u64) {
    let mut w = Vec::new();
    let mut ctx = WitnessCtx { witness: &mut w };
    let (hq, hr) = divrem_u_advice_values(a, b, 64);
    let q_bits = to_bits::<64>(hq);
    let r_bits = to_bits::<64>(hr);
    let (q, r) = divrem_u_advice_n::<_, 64>(&mut ctx, to_bits(a), to_bits(b), q_bits, r_bits)
        .expect("honest advice satisfies constraints");
    (from_bits(q), from_bits(r))
}

fn run_s_advice_honest_64(a: u64, b: u64) -> (i64, i64) {
    let mut w = Vec::new();
    let mut ctx = WitnessCtx { witness: &mut w };
    let (hq, hr) = divrem_s_advice_values(a, b, 64);
    let q_bits = to_bits::<64>(hq);
    let r_bits = to_bits::<64>(hr);
    let (q, r) = divrem_s_advice_n::<_, 64>(&mut ctx, to_bits(a), to_bits(b), q_bits, r_bits)
        .expect("honest advice satisfies constraints");
    (from_bits(q) as i64, from_bits(r) as i64)
}

#[test]
fn divrem_advice_boundary_full_path_32() {
    for &a in BOUNDARY_U32 {
        for &b in BOUNDARY_U32 {
            if b == 0 {
                continue;
            }
            let (qu, ru) = run_u_advice_honest_32(a, b);
            assert_eq!(qu, a / b, "div_u {a:#x}/{b:#x}");
            assert_eq!(ru, a % b, "rem_u {a:#x}%{b:#x}");
            let (sa, sb) = (a as i32, b as i32);
            let (qs, rs) = run_s_advice_honest_32(a, b);
            assert_eq!(qs, sa.wrapping_div(sb), "div_s {sa}/{sb}");
            assert_eq!(rs, sa.wrapping_rem(sb), "rem_s {sa}%{sb}");
        }
    }
}

#[test]
fn divrem_advice_boundary_full_path_64() {
    for &a in BOUNDARY_U64 {
        for &b in BOUNDARY_U64 {
            if b == 0 {
                continue;
            }
            let (qu, ru) = run_u_advice_honest_64(a, b);
            assert_eq!(qu, a / b, "div_u {a:#x}/{b:#x}");
            assert_eq!(ru, a % b, "rem_u {a:#x}%{b:#x}");
            let (sa, sb) = (a as i64, b as i64);
            let (qs, rs) = run_s_advice_honest_64(a, b);
            assert_eq!(qs, sa.wrapping_div(sb), "div_s {sa}/{sb}");
            assert_eq!(rs, sa.wrapping_rem(sb), "rem_s {sa}%{sb}");
        }
    }
}

#[test]
fn divrem_advice_values_match_native() {
    for &a in BOUNDARY_U32 {
        for &b in BOUNDARY_U32 {
            if b == 0 {
                continue;
            }
            let (hq, hr) = divrem_u_advice_values(a as u64, b as u64, 32);
            assert_eq!(hq as u32, a / b, "u q {a:#x}/{b:#x}");
            assert_eq!(hr as u32, a % b, "u r {a:#x}%{b:#x}");
            let (sa, sb) = (a as i32, b as i32);
            let (sq, sr) = divrem_s_advice_values(a as u64, b as u64, 32);
            assert_eq!(sq as u32 as i32, sa.wrapping_div(sb), "s q {sa}/{sb}");
            assert_eq!(sr as u32 as i32, sa.wrapping_rem(sb), "s r {sa}%{sb}");
        }
    }
    for &a in BOUNDARY_U64 {
        for &b in BOUNDARY_U64 {
            if b == 0 {
                continue;
            }
            let (hq, hr) = divrem_u_advice_values(a, b, 64);
            assert_eq!(hq, a / b, "u64 q {a:#x}/{b:#x}");
            assert_eq!(hr, a % b, "u64 r {a:#x}%{b:#x}");
            let (sa, sb) = (a as i64, b as i64);
            let (sq, sr) = divrem_s_advice_values(a, b, 64);
            assert_eq!(sq as i64, sa.wrapping_div(sb), "s64 q {sa}/{sb}");
            assert_eq!(sr as i64, sa.wrapping_rem(sb), "s64 r {sa}%{sb}");
        }
    }
}

fn u_advice_violates_32(a: u32, b: u32, q: u32, r: u32) -> bool {
    let mut w = Vec::new();
    let mut ctx = WitnessCtx { witness: &mut w };
    divrem_u_advice_n::<_, 32>(
        &mut ctx,
        to_bits(a as u64),
        to_bits(b as u64),
        to_bits(q as u64),
        to_bits(r as u64),
    )
    .is_err()
}

fn s_advice_violates_32(a: u32, b: u32, q: u32, r: u32) -> bool {
    let mut w = Vec::new();
    let mut ctx = WitnessCtx { witness: &mut w };
    divrem_s_advice_n::<_, 32>(
        &mut ctx,
        to_bits(a as u64),
        to_bits(b as u64),
        to_bits(q as u64),
        to_bits(r as u64),
    )
    .is_err()
}

#[test]
fn divrem_u_advice_rejects_noncanonical_remainder() {
    assert!(u_advice_violates_32(100, 7, 0, 100));
    assert!(u_advice_violates_32(20, 6, 2, 8));
}

#[test]
fn divrem_u_advice_rejects_wrong_quotient() {
    assert!(u_advice_violates_32(100, 7, 13, 2));
    assert!(u_advice_violates_32(100, 7, 15, 2));
}

#[test]
fn divrem_s_advice_rejects_wrong_quotient() {
    let a = (-100i32) as u32;
    let b = 7u32;
    let bad_q = (-13i32) as u32;
    let r = (-2i32) as u32;
    assert!(s_advice_violates_32(a, b, bad_q, r));
}

#[test]
fn divrem_s_advice_rejects_wrong_remainder_sign() {
    let a = (-7i32) as u32;
    let b = 3u32;
    let bad_q = (-3i32) as u32;
    let bad_r = 2u32;
    assert!(s_advice_violates_32(a, b, bad_q, bad_r));
}

proptest! {
    #![proptest_config(cfg())]

    #[test]
    fn divrem_u_advice_soundness_perturbed(
        a in biased_u32(),
        b in biased_u32_nz(),
        delta in 1u32..=u32::MAX,
    ) {
        let q = a / b;
        let r = a % b;
        let bad_q = q.wrapping_add(delta);
        let reconstructs = bad_q.wrapping_mul(b).wrapping_add(r) == a;
        prop_assume!(!reconstructs);
        prop_assert!(u_advice_violates_32(a, b, bad_q, r),
            "perturbed q must be rejected: a={:#x} b={:#x} bad_q={:#x}", a, b, bad_q);
    }
}
