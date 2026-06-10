use crate::{
    clz_advice_n, clz_advice_values, clz_n, ctz_advice_n, ctz_advice_values, ctz_n,
    harness::{from_bits, run_conv, run_un, to_bits},
    popcnt_advice_n, popcnt_advice_values, popcnt_n,
};
use mpz_circuits::{Context, WitnessCtx};
use mpz_fields::gf2::Gf2;
use proptest::prelude::*;

fn clz_w<C: Context<Field = Gf2>, const N: usize>(ctx: &mut C, a: [C::Wire; N]) -> [C::Wire; N] {
    clz_n(ctx, a)
}

fn ctz_w<C: Context<Field = Gf2>, const N: usize>(ctx: &mut C, a: [C::Wire; N]) -> [C::Wire; N] {
    ctz_n(ctx, a)
}

fn popcnt_w<C: Context<Field = Gf2>, const N: usize>(ctx: &mut C, a: [C::Wire; N]) -> [C::Wire; N] {
    popcnt_n(ctx, a)
}

fn sign_extend<W: Copy, const N: usize>(a: [W; N], m: usize) -> [W; N] {
    let sign = a[m - 1];
    let mut out = [sign; N];
    out[..m].copy_from_slice(&a[..m]);
    out
}

fn ref_clz32(v: u32) -> u32 {
    v.leading_zeros()
}

fn ref_ctz32(v: u32) -> u32 {
    v.trailing_zeros()
}

fn ref_popcnt32(v: u32) -> u32 {
    v.count_ones()
}

fn ref_clz64(v: u64) -> u64 {
    v.leading_zeros() as u64
}

fn ref_ctz64(v: u64) -> u64 {
    v.trailing_zeros() as u64
}

fn ref_popcnt64(v: u64) -> u64 {
    v.count_ones() as u64
}

fn ref_clz_n(v: u64, n: usize) -> u64 {
    let mask = if n == 64 { u64::MAX } else { (1u64 << n) - 1 };
    let v = v & mask;
    if v == 0 {
        n as u64
    } else {
        (v.leading_zeros() as u64) - (64 - n as u64)
    }
}

fn ref_ctz_n(v: u64, n: usize) -> u64 {
    let mask = if n == 64 { u64::MAX } else { (1u64 << n) - 1 };
    let v = v & mask;
    if v == 0 {
        n as u64
    } else {
        v.trailing_zeros() as u64
    }
}

fn ref_popcnt_n(v: u64, n: usize) -> u64 {
    let mask = if n == 64 { u64::MAX } else { (1u64 << n) - 1 };
    (v & mask).count_ones() as u64
}

fn biased_u32() -> impl Strategy<Value = u32> {
    prop_oneof![
        Just(0u32),
        Just(1u32),
        Just(u32::MAX),
        Just(i32::MIN as u32),
        Just(i32::MAX as u32),
        Just(0x8000_0000u32),
        (0u32..32).prop_map(|k| 1u32 << k),
        (0u32..32).prop_map(|k| u32::MAX >> k),
        (0u32..32).prop_map(|k| u32::MAX << k),
        0u32..256,
        any::<u32>(),
    ]
}

fn biased_u64() -> impl Strategy<Value = u64> {
    prop_oneof![
        Just(0u64),
        Just(1u64),
        Just(u64::MAX),
        Just(i64::MIN as u64),
        Just(i64::MAX as u64),
        Just(0x8000_0000_0000_0000u64),
        (0u64..64).prop_map(|k| 1u64 << k),
        (0u64..64).prop_map(|k| u64::MAX >> k),
        (0u64..64).prop_map(|k| u64::MAX << k),
        0u64..256,
        any::<u64>(),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 8192, ..ProptestConfig::default() })]

    #[test]
    fn prop_i32clz(v in biased_u32()) {
        let got = run_un::<_, 32>(|c, a| crate::clz_n(c, a), v as u64) as u32;
        prop_assert_eq!(got, ref_clz32(v), "clz v={:#x}", v);
    }

    #[test]
    fn prop_i32ctz(v in biased_u32()) {
        let got = run_un::<_, 32>(|c, a| crate::ctz_n(c, a), v as u64) as u32;
        prop_assert_eq!(got, ref_ctz32(v), "ctz v={:#x}", v);
    }

    #[test]
    fn prop_i32popcnt(v in biased_u32()) {
        let got = run_un::<_, 32>(|c, a| crate::popcnt_n(c, a), v as u64) as u32;
        prop_assert_eq!(got, ref_popcnt32(v), "popcnt v={:#x}", v);
    }

    #[test]
    fn prop_i64clz(v in biased_u64()) {
        let got = run_un::<_, 64>(|c, a| crate::clz_n(c, a), v);
        prop_assert_eq!(got, ref_clz64(v), "clz v={:#x}", v);
    }

    #[test]
    fn prop_i64ctz(v in biased_u64()) {
        let got = run_un::<_, 64>(|c, a| crate::ctz_n(c, a), v);
        prop_assert_eq!(got, ref_ctz64(v), "ctz v={:#x}", v);
    }

    #[test]
    fn prop_i64popcnt(v in biased_u64()) {
        let got = run_un::<_, 64>(|c, a| crate::popcnt_n(c, a), v);
        prop_assert_eq!(got, ref_popcnt64(v), "popcnt v={:#x}", v);
    }
}

fn run_clz_advice_n<const N: usize>(v: u64) -> (u64, bool) {
    let mut w = Vec::new();
    let mut ctx = WitnessCtx { witness: &mut w };
    let advice = to_bits::<N>(clz_advice_values(v, N));
    match clz_advice_n::<_, N>(&mut ctx, to_bits(v), advice) {
        Ok(out) => (from_bits(out), true),
        Err(_) => (0, false),
    }
}

fn run_ctz_advice_n<const N: usize>(v: u64) -> (u64, bool) {
    let mut w = Vec::new();
    let mut ctx = WitnessCtx { witness: &mut w };
    let advice = to_bits::<N>(ctz_advice_values(v, N));
    match ctz_advice_n::<_, N>(&mut ctx, to_bits(v), advice) {
        Ok(out) => (from_bits(out), true),
        Err(_) => (0, false),
    }
}

fn run_popcnt_advice_n<const N: usize>(v: u64) -> (u64, bool) {
    let mut w = Vec::new();
    let mut ctx = WitnessCtx { witness: &mut w };
    let advice = to_bits::<N>(popcnt_advice_values(v, N));
    match popcnt_advice_n::<_, N>(&mut ctx, to_bits(v), advice) {
        Ok(out) => (from_bits(out), true),
        Err(_) => (0, false),
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 8192, ..ProptestConfig::default() })]

    #[test]
    fn prop_clz_advice_complete_32(v in biased_u32()) {
        let (out, ok) = run_clz_advice_n::<32>(v as u64);
        prop_assert!(ok, "honest clz advice must leave all asserts zero, v={:#x}", v);
        prop_assert_eq!(out as u32, ref_clz32(v), "clz advice v={:#x}", v);
    }

    #[test]
    fn prop_ctz_advice_complete_32(v in biased_u32()) {
        let (out, ok) = run_ctz_advice_n::<32>(v as u64);
        prop_assert!(ok, "honest ctz advice must leave all asserts zero, v={:#x}", v);
        prop_assert_eq!(out as u32, ref_ctz32(v), "ctz advice v={:#x}", v);
    }

    #[test]
    fn prop_popcnt_advice_complete_32(v in biased_u32()) {
        let (out, ok) = run_popcnt_advice_n::<32>(v as u64);
        prop_assert!(ok, "honest popcnt advice must leave all asserts zero, v={:#x}", v);
        prop_assert_eq!(out as u32, ref_popcnt32(v), "popcnt advice v={:#x}", v);
    }

    #[test]
    fn prop_clz_advice_complete_64(v in biased_u64()) {
        let (out, ok) = run_clz_advice_n::<64>(v);
        prop_assert!(ok, "honest clz advice must leave all asserts zero, v={:#x}", v);
        prop_assert_eq!(out, ref_clz64(v), "clz advice v={:#x}", v);
    }

    #[test]
    fn prop_ctz_advice_complete_64(v in biased_u64()) {
        let (out, ok) = run_ctz_advice_n::<64>(v);
        prop_assert!(ok, "honest ctz advice must leave all asserts zero, v={:#x}", v);
        prop_assert_eq!(out, ref_ctz64(v), "ctz advice v={:#x}", v);
    }

    #[test]
    fn prop_popcnt_advice_complete_64(v in biased_u64()) {
        let (out, ok) = run_popcnt_advice_n::<64>(v);
        prop_assert!(ok, "honest popcnt advice must leave all asserts zero, v={:#x}", v);
        prop_assert_eq!(out, ref_popcnt64(v), "popcnt advice v={:#x}", v);
    }
}

fn clz_advice_rejects(v: u64, n: usize, bad: u64) -> bool {
    let mut w = Vec::new();
    let mut ctx = WitnessCtx { witness: &mut w };
    macro_rules! run {
        ($N:literal) => {{
            let mut advice = [Gf2(false); $N];
            for i in 0..$N {
                advice[i] = Gf2((bad >> i) & 1 != 0);
            }
            clz_advice_n::<_, $N>(&mut ctx, to_bits::<$N>(v), advice).is_err()
        }};
    }
    match n {
        32 => run!(32),
        64 => run!(64),
        _ => unreachable!(),
    }
}

fn ctz_advice_rejects(v: u64, n: usize, bad: u64) -> bool {
    let mut w = Vec::new();
    let mut ctx = WitnessCtx { witness: &mut w };
    macro_rules! run {
        ($N:literal) => {{
            let mut advice = [Gf2(false); $N];
            for i in 0..$N {
                advice[i] = Gf2((bad >> i) & 1 != 0);
            }
            ctz_advice_n::<_, $N>(&mut ctx, to_bits::<$N>(v), advice).is_err()
        }};
    }
    match n {
        32 => run!(32),
        64 => run!(64),
        _ => unreachable!(),
    }
}

fn popcnt_advice_rejects(v: u64, n: usize, bad: u64) -> bool {
    let mut w = Vec::new();
    let mut ctx = WitnessCtx { witness: &mut w };
    macro_rules! run {
        ($N:literal) => {{
            let mut advice = [Gf2(false); $N];
            for i in 0..$N {
                advice[i] = Gf2((bad >> i) & 1 != 0);
            }
            popcnt_advice_n::<_, $N>(&mut ctx, to_bits::<$N>(v), advice).is_err()
        }};
    }
    match n {
        32 => run!(32),
        64 => run!(64),
        _ => unreachable!(),
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 4096, ..ProptestConfig::default() })]

    #[test]
    fn prop_clz_advice_rejects_dishonest_32(v in biased_u32(), bit in 0u32..32) {
        let honest = ref_clz32(v) as u64;
        let bad = honest ^ (1u64 << bit);
        prop_assert!(clz_advice_rejects(v as u64, 32, bad),
            "dishonest clz advice must violate some assert, v={:#x} bad={}", v, bad);
    }

    #[test]
    fn prop_ctz_advice_rejects_dishonest_32(v in biased_u32(), bit in 0u32..32) {
        let honest = ref_ctz32(v) as u64;
        let bad = honest ^ (1u64 << bit);
        prop_assert!(ctz_advice_rejects(v as u64, 32, bad),
            "dishonest ctz advice must violate some assert, v={:#x} bad={}", v, bad);
    }

    #[test]
    fn prop_popcnt_advice_rejects_dishonest_32(v in biased_u32(), bit in 0u32..32) {
        let honest = ref_popcnt32(v) as u64;
        let bad = honest ^ (1u64 << bit);
        prop_assert!(popcnt_advice_rejects(v as u64, 32, bad),
            "dishonest popcnt advice must violate some assert, v={:#x} bad={}", v, bad);
    }

    #[test]
    fn prop_clz_advice_rejects_dishonest_64(v in biased_u64(), bit in 0u32..64) {
        let honest = ref_clz64(v);
        let bad = honest ^ (1u64 << bit);
        prop_assert!(clz_advice_rejects(v, 64, bad),
            "dishonest clz advice must violate some assert, v={:#x} bad={}", v, bad);
    }

    #[test]
    fn prop_ctz_advice_rejects_dishonest_64(v in biased_u64(), bit in 0u32..64) {
        let honest = ref_ctz64(v);
        let bad = honest ^ (1u64 << bit);
        prop_assert!(ctz_advice_rejects(v, 64, bad),
            "dishonest ctz advice must violate some assert, v={:#x} bad={}", v, bad);
    }

    #[test]
    fn prop_popcnt_advice_rejects_dishonest_64(v in biased_u64(), bit in 0u32..64) {
        let honest = ref_popcnt64(v);
        let bad = honest ^ (1u64 << bit);
        prop_assert!(popcnt_advice_rejects(v, 64, bad),
            "dishonest popcnt advice must violate some assert, v={:#x} bad={}", v, bad);
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 8192, ..ProptestConfig::default() })]

    #[test]
    fn prop_i32wrap_i64(v in biased_u64()) {
        let got = run_conv::<_, 64, 32>(|_c, a| {
            let mut out = [a[0]; 32];
            out.copy_from_slice(&a[..32]);
            out
        }, v) as u32;
        prop_assert_eq!(got, v as u32, "wrap v={:#x}", v);
    }

    #[test]
    fn prop_i64extend_i32_s(v in biased_u32()) {
        let got = run_conv::<_, 32, 64>(|_c, a| {
            let sign = a[31];
            let mut out = [sign; 64];
            out[..32].copy_from_slice(&a);
            out
        }, v as u64);
        prop_assert_eq!(got, v as i32 as i64 as u64, "extend_s v={:#x}", v);
    }

    #[test]
    fn prop_i64extend_i32_u(v in biased_u32()) {
        let got = run_conv::<_, 32, 64>(|c, a| {
            let z = crate::zero(c);
            let mut out = [z; 64];
            out[..32].copy_from_slice(&a);
            out
        }, v as u64);
        prop_assert_eq!(got, v as u64, "extend_u v={:#x}", v);
    }

    #[test]
    fn prop_i32extend8_s(v in biased_u32()) {
        let got = run_un::<_, 32>(|_c, a| sign_extend(a, 8), v as u64) as u32;
        prop_assert_eq!(got, ((v as i32) << 24 >> 24) as u32, "extend8 v={:#x}", v);
    }

    #[test]
    fn prop_i32extend16_s(v in biased_u32()) {
        let got = run_un::<_, 32>(|_c, a| sign_extend(a, 16), v as u64) as u32;
        prop_assert_eq!(got, ((v as i32) << 16 >> 16) as u32, "extend16 v={:#x}", v);
    }

    #[test]
    fn prop_i64extend8_s(v in biased_u64()) {
        let got = run_un::<_, 64>(|_c, a| sign_extend(a, 8), v);
        prop_assert_eq!(got, ((v as i64) << 56 >> 56) as u64, "extend8 v={:#x}", v);
    }

    #[test]
    fn prop_i64extend16_s(v in biased_u64()) {
        let got = run_un::<_, 64>(|_c, a| sign_extend(a, 16), v);
        prop_assert_eq!(got, ((v as i64) << 48 >> 48) as u64, "extend16 v={:#x}", v);
    }

    #[test]
    fn prop_i64extend32_s(v in biased_u64()) {
        let got = run_un::<_, 64>(|_c, a| sign_extend(a, 32), v);
        prop_assert_eq!(got, ((v as i64) << 32 >> 32) as u64, "extend32 v={:#x}", v);
    }
}

#[test]
fn clz_ctz_popcnt_boundaries_32() {
    let cases = [
        0u32,
        1,
        u32::MAX,
        0x8000_0000,
        i32::MAX as u32,
        i32::MIN as u32,
        0x0F0F_0F0F,
        0x0000_0001,
        0x4000_0000,
    ];
    for v in cases {
        assert_eq!(
            run_un::<_, 32>(|c, a| crate::clz_n(c, a), v as u64) as u32,
            v.leading_zeros(),
            "clz v={v:#x}"
        );
        assert_eq!(
            run_un::<_, 32>(|c, a| crate::ctz_n(c, a), v as u64) as u32,
            v.trailing_zeros(),
            "ctz v={v:#x}"
        );
        assert_eq!(
            run_un::<_, 32>(|c, a| crate::popcnt_n(c, a), v as u64) as u32,
            v.count_ones(),
            "popcnt v={v:#x}"
        );
    }
    for k in 0..32u32 {
        let v = 1u32 << k;
        assert_eq!(
            run_un::<_, 32>(|c, a| crate::clz_n(c, a), v as u64) as u32,
            31 - k,
            "clz single bit k={k}"
        );
        assert_eq!(
            run_un::<_, 32>(|c, a| crate::ctz_n(c, a), v as u64) as u32,
            k,
            "ctz single bit k={k}"
        );
        assert_eq!(
            run_un::<_, 32>(|c, a| crate::popcnt_n(c, a), v as u64) as u32,
            1,
            "popcnt single bit k={k}"
        );
    }
}

#[test]
fn clz_ctz_popcnt_boundaries_64() {
    let cases = [
        0u64,
        1,
        u64::MAX,
        0x8000_0000_0000_0000,
        i64::MAX as u64,
        i64::MIN as u64,
        0x0F0F_0F0F_0F0F_0F0F,
        0x1,
        0x4000_0000_0000_0000,
        0x1_0000_0000,
    ];
    for v in cases {
        assert_eq!(
            run_un::<_, 64>(|c, a| crate::clz_n(c, a), v),
            v.leading_zeros() as u64,
            "clz v={v:#x}"
        );
        assert_eq!(
            run_un::<_, 64>(|c, a| crate::ctz_n(c, a), v),
            v.trailing_zeros() as u64,
            "ctz v={v:#x}"
        );
        assert_eq!(
            run_un::<_, 64>(|c, a| crate::popcnt_n(c, a), v),
            v.count_ones() as u64,
            "popcnt v={v:#x}"
        );
    }
    for k in 0..64u32 {
        let v = 1u64 << k;
        assert_eq!(
            run_un::<_, 64>(|c, a| crate::clz_n(c, a), v),
            (63 - k) as u64,
            "clz single bit k={k}"
        );
        assert_eq!(
            run_un::<_, 64>(|c, a| crate::ctz_n(c, a), v),
            k as u64,
            "ctz single bit k={k}"
        );
        assert_eq!(
            run_un::<_, 64>(|c, a| crate::popcnt_n(c, a), v),
            1,
            "popcnt single bit k={k}"
        );
    }
}

#[test]
fn wrap_extend_boundaries() {
    for v in [
        0u64,
        u64::MAX,
        0x1234_5678_9ABC_DEF0,
        0xFFFF_FFFF_0000_0000,
        0x0000_0000_FFFF_FFFF,
        0x8000_0000_8000_0000,
        i64::MIN as u64,
        i64::MAX as u64,
    ] {
        assert_eq!(
            run_conv::<_, 64, 32>(
                |_c, a| {
                    let mut out = [a[0]; 32];
                    out.copy_from_slice(&a[..32]);
                    out
                },
                v
            ) as u32,
            v as u32,
            "wrap v={v:#x}"
        );
    }
    for v in [
        0u32,
        1,
        0x7F,
        0x80,
        0xFF,
        0x7FFF_FFFF,
        0x8000_0000,
        u32::MAX,
    ] {
        assert_eq!(
            run_conv::<_, 32, 64>(
                |_c, a| {
                    let sign = a[31];
                    let mut out = [sign; 64];
                    out[..32].copy_from_slice(&a);
                    out
                },
                v as u64
            ),
            v as i32 as i64 as u64,
            "extend_s v={v:#x}"
        );
        assert_eq!(
            run_conv::<_, 32, 64>(
                |c, a| {
                    let z = crate::zero(c);
                    let mut out = [z; 64];
                    out[..32].copy_from_slice(&a);
                    out
                },
                v as u64
            ),
            v as u64,
            "extend_u v={v:#x}"
        );
    }
}

#[test]
fn sign_extend_boundaries() {
    for v in [
        0u32,
        0x7F,
        0x80,
        0xFF,
        0x1234_5678,
        0x8000_0000,
        u32::MAX,
        0x0000_7FFF,
        0x0000_8000,
        0x0000_FFFF,
    ] {
        assert_eq!(
            run_un::<_, 32>(|_c, a| sign_extend(a, 8), v as u64) as u32,
            ((v as i32) << 24 >> 24) as u32,
            "extend8_s v={v:#x}"
        );
        assert_eq!(
            run_un::<_, 32>(|_c, a| sign_extend(a, 16), v as u64) as u32,
            ((v as i32) << 16 >> 16) as u32,
            "extend16_s v={v:#x}"
        );
    }
    for v in [
        0u64,
        0x7F,
        0x80,
        0xFF,
        0x7FFF,
        0x8000,
        0xFFFF,
        0x7FFF_FFFF,
        0x8000_0000,
        0xFFFF_FFFF,
        u64::MAX,
        0x1_0000_0000,
    ] {
        assert_eq!(
            run_un::<_, 64>(|_c, a| sign_extend(a, 8), v),
            ((v as i64) << 56 >> 56) as u64,
            "extend8_s v={v:#x}"
        );
        assert_eq!(
            run_un::<_, 64>(|_c, a| sign_extend(a, 16), v),
            ((v as i64) << 48 >> 48) as u64,
            "extend16_s v={v:#x}"
        );
        assert_eq!(
            run_un::<_, 64>(|_c, a| sign_extend(a, 32), v),
            ((v as i64) << 32 >> 32) as u64,
            "extend32_s v={v:#x}"
        );
    }
}

#[test]
fn advice_completeness_boundaries_32() {
    for v in [0u32, 1, u32::MAX, 0x8000_0000, 0x0F0F_0F0F, 42, 0xDEAD_BEEF] {
        let (out, ok) = run_clz_advice_n::<32>(v as u64);
        assert!(ok, "clz advice asserts, v={v:#x}");
        assert_eq!(out as u32, v.leading_zeros(), "clz advice v={v:#x}");

        let (out, ok) = run_ctz_advice_n::<32>(v as u64);
        assert!(ok, "ctz advice asserts, v={v:#x}");
        assert_eq!(out as u32, v.trailing_zeros(), "ctz advice v={v:#x}");

        let (out, ok) = run_popcnt_advice_n::<32>(v as u64);
        assert!(ok, "popcnt advice asserts, v={v:#x}");
        assert_eq!(out as u32, v.count_ones(), "popcnt advice v={v:#x}");
    }
}

#[test]
fn advice_soundness_boundaries_32() {
    let cases = [0u32, 1, u32::MAX, 0x8000_0000, 0x0F0F_0F0F, 0x10, 7];
    for v in cases {
        let clz = v.leading_zeros() as u64;
        let ctz = v.trailing_zeros() as u64;
        let pc = v.count_ones() as u64;
        let bad_clz = clz ^ 1;
        let bad_ctz = ctz ^ 1;
        let bad_pc = pc ^ 1;
        assert!(
            clz_advice_rejects(v as u64, 32, bad_clz),
            "clz soundness v={v:#x}"
        );
        assert!(
            ctz_advice_rejects(v as u64, 32, bad_ctz),
            "ctz soundness v={v:#x}"
        );
        assert!(
            popcnt_advice_rejects(v as u64, 32, bad_pc),
            "popcnt soundness v={v:#x}"
        );
    }
}

#[test]
fn advice_explicit_assert_inspection_32() {
    let v = 0x0F0F_0F0Fu32;
    let mut w = Vec::new();
    let mut ctx = WitnessCtx { witness: &mut w };
    let advice = to_bits::<32>(clz_advice_values(v as u64, 32));
    let out = clz_advice_n::<_, 32>(&mut ctx, to_bits(v as u64), advice)
        .expect("honest advice satisfies constraints");
    assert_eq!(from_bits(out) as u32, v.leading_zeros());

    let mut w = Vec::new();
    let mut ctx = WitnessCtx { witness: &mut w };
    let mut bad_advice = advice;
    bad_advice[0] = Gf2(!bad_advice[0].0);
    let res = clz_advice_n::<_, 32>(&mut ctx, to_bits(v as u64), bad_advice);
    assert!(
        res.is_err(),
        "dishonest clz advice must violate at least one assert"
    );
}

#[test]
fn clz_ctz_popcnt_exhaustive_n8() {
    const N: usize = 8;
    for v in 0u64..(1u64 << N) {
        assert_eq!(
            run_un::<_, N>(|c, a| clz_w::<_, N>(c, a), v),
            ref_clz_n(v, N),
            "clz N=8 v={v:#x}"
        );
        assert_eq!(
            run_un::<_, N>(|c, a| ctz_w::<_, N>(c, a), v),
            ref_ctz_n(v, N),
            "ctz N=8 v={v:#x}"
        );
        assert_eq!(
            run_un::<_, N>(|c, a| popcnt_w::<_, N>(c, a), v),
            ref_popcnt_n(v, N),
            "popcnt N=8 v={v:#x}"
        );
    }
}

#[test]
fn clz_ctz_popcnt_exhaustive_n10() {
    const N: usize = 10;
    for v in 0u64..(1u64 << N) {
        assert_eq!(
            run_un::<_, N>(|c, a| clz_w::<_, N>(c, a), v),
            ref_clz_n(v, N),
            "clz N=10 v={v:#x}"
        );
        assert_eq!(
            run_un::<_, N>(|c, a| ctz_w::<_, N>(c, a), v),
            ref_ctz_n(v, N),
            "ctz N=10 v={v:#x}"
        );
        assert_eq!(
            run_un::<_, N>(|c, a| popcnt_w::<_, N>(c, a), v),
            ref_popcnt_n(v, N),
            "popcnt N=10 v={v:#x}"
        );
    }
}

#[test]
fn advice_exhaustive_n8() {
    const N: usize = 8;
    for v in 0u64..(1u64 << N) {
        let (out, ok) = run_clz_advice_n::<N>(v);
        assert!(ok, "clz advice asserts N=8 v={v:#x}");
        assert_eq!(out, ref_clz_n(v, N), "clz advice N=8 v={v:#x}");

        let (out, ok) = run_ctz_advice_n::<N>(v);
        assert!(ok, "ctz advice asserts N=8 v={v:#x}");
        assert_eq!(out, ref_ctz_n(v, N), "ctz advice N=8 v={v:#x}");

        let (out, ok) = run_popcnt_advice_n::<N>(v);
        assert!(ok, "popcnt advice asserts N=8 v={v:#x}");
        assert_eq!(out, ref_popcnt_n(v, N), "popcnt advice N=8 v={v:#x}");
    }
}

#[test]
fn advice_soundness_exhaustive_n8() {
    const N: usize = 8;
    for v in 0u64..(1u64 << N) {
        let clz = ref_clz_n(v, N);
        let ctz = ref_ctz_n(v, N);
        let pc = ref_popcnt_n(v, N);
        for bit in 0..N {
            let m = 1u64 << bit;
            assert!(
                clz_advice_n_rejects_8(v, clz ^ m),
                "clz reject N=8 v={v:#x} bit={bit}"
            );
            assert!(
                ctz_advice_n_rejects_8(v, ctz ^ m),
                "ctz reject N=8 v={v:#x} bit={bit}"
            );
            assert!(
                popcnt_advice_n_rejects_8(v, pc ^ m),
                "popcnt reject N=8 v={v:#x} bit={bit}"
            );
        }
    }
}

fn clz_advice_n_rejects_8(v: u64, bad: u64) -> bool {
    let mut w = Vec::new();
    let mut ctx = WitnessCtx { witness: &mut w };
    let mut advice = [Gf2(false); 8];
    for (i, h) in advice.iter_mut().enumerate() {
        *h = Gf2((bad >> i) & 1 != 0);
    }
    clz_advice_n::<_, 8>(&mut ctx, to_bits::<8>(v), advice).is_err()
}

fn ctz_advice_n_rejects_8(v: u64, bad: u64) -> bool {
    let mut w = Vec::new();
    let mut ctx = WitnessCtx { witness: &mut w };
    let mut advice = [Gf2(false); 8];
    for (i, h) in advice.iter_mut().enumerate() {
        *h = Gf2((bad >> i) & 1 != 0);
    }
    ctz_advice_n::<_, 8>(&mut ctx, to_bits::<8>(v), advice).is_err()
}

fn popcnt_advice_n_rejects_8(v: u64, bad: u64) -> bool {
    let mut w = Vec::new();
    let mut ctx = WitnessCtx { witness: &mut w };
    let mut advice = [Gf2(false); 8];
    for (i, h) in advice.iter_mut().enumerate() {
        *h = Gf2((bad >> i) & 1 != 0);
    }
    popcnt_advice_n::<_, 8>(&mut ctx, to_bits::<8>(v), advice).is_err()
}

#[test]
fn wrap_extend_exhaustive_small() {
    for v in 0u64..(1u64 << 8) {
        let got = run_conv::<_, 8, 4>(
            |_c, a| {
                let mut out = [a[0]; 4];
                out.copy_from_slice(&a[..4]);
                out
            },
            v,
        );
        assert_eq!(got, v & 0xF, "wrap8->4 v={v:#x}");
    }
    for v in 0u64..(1u64 << 4) {
        let s = ((v as i8) << 4 >> 4) as u8 as u64;
        let got_s = run_conv::<_, 4, 8>(
            |_c, a| {
                let sign = a[3];
                let mut out = [sign; 8];
                out[..4].copy_from_slice(&a[..4]);
                out
            },
            v,
        );
        assert_eq!(got_s, s, "extend_s 4->8 v={v:#x}");
        let got_u = run_conv::<_, 4, 8>(
            |c, a| {
                let z = c.constant(Gf2::default());
                let mut out = [z; 8];
                out[..4].copy_from_slice(&a[..4]);
                out
            },
            v,
        );
        assert_eq!(got_u, v, "extend_u 4->8 v={v:#x}");
    }
}
