use crate::harness::{run_bin_bit, run_un_bit};
use crate::{eq_n, eqz_n, lt_s_n, lt_u_n, ne_n, not};
use mpz_circuits::Context;
use mpz_fields::gf2::Gf2;
use proptest::prelude::*;

fn eq8<C: Context<Field = Gf2>>(ctx: &mut C, a: [C::Wire; 8], b: [C::Wire; 8]) -> C::Wire {
    eq_n(ctx, a, b)
}

fn ne8<C: Context<Field = Gf2>>(ctx: &mut C, a: [C::Wire; 8], b: [C::Wire; 8]) -> C::Wire {
    ne_n(ctx, a, b)
}

fn lt_u8<C: Context<Field = Gf2>>(ctx: &mut C, a: [C::Wire; 8], b: [C::Wire; 8]) -> C::Wire {
    lt_u_n(ctx, a, b)
}

fn lt_s8<C: Context<Field = Gf2>>(ctx: &mut C, a: [C::Wire; 8], b: [C::Wire; 8]) -> C::Wire {
    lt_s_n(ctx, a, b)
}

fn gt_u8<C: Context<Field = Gf2>>(ctx: &mut C, a: [C::Wire; 8], b: [C::Wire; 8]) -> C::Wire {
    lt_u_n(ctx, b, a)
}

fn gt_s8<C: Context<Field = Gf2>>(ctx: &mut C, a: [C::Wire; 8], b: [C::Wire; 8]) -> C::Wire {
    lt_s_n(ctx, b, a)
}

fn le_u8<C: Context<Field = Gf2>>(ctx: &mut C, a: [C::Wire; 8], b: [C::Wire; 8]) -> C::Wire {
    let gt = lt_u_n(ctx, b, a);
    let one = ctx.constant(Gf2(true));
    ctx.add(gt, one)
}

fn le_s8<C: Context<Field = Gf2>>(ctx: &mut C, a: [C::Wire; 8], b: [C::Wire; 8]) -> C::Wire {
    let gt = lt_s_n(ctx, b, a);
    let one = ctx.constant(Gf2(true));
    ctx.add(gt, one)
}

fn ge_u8<C: Context<Field = Gf2>>(ctx: &mut C, a: [C::Wire; 8], b: [C::Wire; 8]) -> C::Wire {
    let lt = lt_u_n(ctx, a, b);
    let one = ctx.constant(Gf2(true));
    ctx.add(lt, one)
}

fn ge_s8<C: Context<Field = Gf2>>(ctx: &mut C, a: [C::Wire; 8], b: [C::Wire; 8]) -> C::Wire {
    let lt = lt_s_n(ctx, a, b);
    let one = ctx.constant(Gf2(true));
    ctx.add(lt, one)
}

fn eqz8<C: Context<Field = Gf2>>(ctx: &mut C, a: [C::Wire; 8]) -> C::Wire {
    eqz_n(ctx, a)
}

fn biased_u32() -> impl Strategy<Value = u32> {
    prop_oneof![
        Just(0u32),
        Just(1u32),
        Just(u32::MAX),
        Just(i32::MIN as u32),
        Just(i32::MAX as u32),
        Just((-1i32) as u32),
        0u32..=255,
        (0u32..32).prop_map(|k| 1u32 << k),
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
        Just((-1i64) as u64),
        0u64..=255,
        (0u64..64).prop_map(|k| 1u64 << k),
        any::<u64>(),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 8192, ..ProptestConfig::default() })]

    #[test]
    fn prop_i32_eq(a in biased_u32(), b in biased_u32()) {
        prop_assert_eq!(
            run_bin_bit::<_, 32>(|c, a, b| eq_n(c, a, b), a as u64, b as u64),
            a == b
        );
    }

    #[test]
    fn prop_i32_ne(a in biased_u32(), b in biased_u32()) {
        prop_assert_eq!(
            run_bin_bit::<_, 32>(|c, a, b| ne_n(c, a, b), a as u64, b as u64),
            a != b
        );
    }

    #[test]
    fn prop_i32_lt_u(a in biased_u32(), b in biased_u32()) {
        prop_assert_eq!(
            run_bin_bit::<_, 32>(|c, a, b| lt_u_n(c, a, b), a as u64, b as u64),
            a < b
        );
    }

    #[test]
    fn prop_i32_gt_u(a in biased_u32(), b in biased_u32()) {
        prop_assert_eq!(
            run_bin_bit::<_, 32>(|c, a, b| lt_u_n(c, b, a), a as u64, b as u64),
            a > b
        );
    }

    #[test]
    fn prop_i32_le_u(a in biased_u32(), b in biased_u32()) {
        prop_assert_eq!(
            run_bin_bit::<_, 32>(|c, a, b| {
            let gt = lt_u_n(c, b, a);
            not(c, gt)
        }, a as u64, b as u64),
            a <= b
        );
    }

    #[test]
    fn prop_i32_ge_u(a in biased_u32(), b in biased_u32()) {
        prop_assert_eq!(
            run_bin_bit::<_, 32>(|c, a, b| {
            let lt = lt_u_n(c, a, b);
            not(c, lt)
        }, a as u64, b as u64),
            a >= b
        );
    }

    #[test]
    fn prop_i32_lt_s(a in biased_u32(), b in biased_u32()) {
        prop_assert_eq!(
            run_bin_bit::<_, 32>(|c, a, b| lt_s_n(c, a, b), a as u64, b as u64),
            (a as i32) < (b as i32)
        );
    }

    #[test]
    fn prop_i32_gt_s(a in biased_u32(), b in biased_u32()) {
        prop_assert_eq!(
            run_bin_bit::<_, 32>(|c, a, b| lt_s_n(c, b, a), a as u64, b as u64),
            (a as i32) > (b as i32)
        );
    }

    #[test]
    fn prop_i32_le_s(a in biased_u32(), b in biased_u32()) {
        prop_assert_eq!(
            run_bin_bit::<_, 32>(|c, a, b| {
            let gt = lt_s_n(c, b, a);
            not(c, gt)
        }, a as u64, b as u64),
            (a as i32) <= (b as i32)
        );
    }

    #[test]
    fn prop_i32_ge_s(a in biased_u32(), b in biased_u32()) {
        prop_assert_eq!(
            run_bin_bit::<_, 32>(|c, a, b| {
            let lt = lt_s_n(c, a, b);
            not(c, lt)
        }, a as u64, b as u64),
            (a as i32) >= (b as i32)
        );
    }

    #[test]
    fn prop_i32_eqz(a in biased_u32()) {
        prop_assert_eq!(
            run_un_bit::<_, 32>(|c, a| eqz_n(c, a), a as u64),
            a == 0
        );
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 8192, ..ProptestConfig::default() })]

    #[test]
    fn prop_i64_eq(a in biased_u64(), b in biased_u64()) {
        prop_assert_eq!(
            run_bin_bit::<_, 64>(|c, a, b| eq_n(c, a, b), a, b),
            a == b
        );
    }

    #[test]
    fn prop_i64_ne(a in biased_u64(), b in biased_u64()) {
        prop_assert_eq!(
            run_bin_bit::<_, 64>(|c, a, b| ne_n(c, a, b), a, b),
            a != b
        );
    }

    #[test]
    fn prop_i64_lt_u(a in biased_u64(), b in biased_u64()) {
        prop_assert_eq!(
            run_bin_bit::<_, 64>(|c, a, b| lt_u_n(c, a, b), a, b),
            a < b
        );
    }

    #[test]
    fn prop_i64_gt_u(a in biased_u64(), b in biased_u64()) {
        prop_assert_eq!(
            run_bin_bit::<_, 64>(|c, a, b| lt_u_n(c, b, a), a, b),
            a > b
        );
    }

    #[test]
    fn prop_i64_le_u(a in biased_u64(), b in biased_u64()) {
        prop_assert_eq!(
            run_bin_bit::<_, 64>(|c, a, b| {
            let gt = lt_u_n(c, b, a);
            not(c, gt)
        }, a, b),
            a <= b
        );
    }

    #[test]
    fn prop_i64_ge_u(a in biased_u64(), b in biased_u64()) {
        prop_assert_eq!(
            run_bin_bit::<_, 64>(|c, a, b| {
            let lt = lt_u_n(c, a, b);
            not(c, lt)
        }, a, b),
            a >= b
        );
    }

    #[test]
    fn prop_i64_lt_s(a in biased_u64(), b in biased_u64()) {
        prop_assert_eq!(
            run_bin_bit::<_, 64>(|c, a, b| lt_s_n(c, a, b), a, b),
            (a as i64) < (b as i64)
        );
    }

    #[test]
    fn prop_i64_gt_s(a in biased_u64(), b in biased_u64()) {
        prop_assert_eq!(
            run_bin_bit::<_, 64>(|c, a, b| lt_s_n(c, b, a), a, b),
            (a as i64) > (b as i64)
        );
    }

    #[test]
    fn prop_i64_le_s(a in biased_u64(), b in biased_u64()) {
        prop_assert_eq!(
            run_bin_bit::<_, 64>(|c, a, b| {
            let gt = lt_s_n(c, b, a);
            not(c, gt)
        }, a, b),
            (a as i64) <= (b as i64)
        );
    }

    #[test]
    fn prop_i64_ge_s(a in biased_u64(), b in biased_u64()) {
        prop_assert_eq!(
            run_bin_bit::<_, 64>(|c, a, b| {
            let lt = lt_s_n(c, a, b);
            not(c, lt)
        }, a, b),
            (a as i64) >= (b as i64)
        );
    }

    #[test]
    fn prop_i64_eqz(a in biased_u64()) {
        prop_assert_eq!(
            run_un_bit::<_, 64>(|c, a| eqz_n(c, a), a),
            a == 0
        );
    }
}

fn check_all_i32(a: u32, b: u32) {
    assert_eq!(
        run_bin_bit::<_, 32>(|c, a, b| eq_n(c, a, b), a as u64, b as u64),
        a == b,
        "eq a={a:#x} b={b:#x}"
    );
    assert_eq!(
        run_bin_bit::<_, 32>(|c, a, b| ne_n(c, a, b), a as u64, b as u64),
        a != b,
        "ne a={a:#x} b={b:#x}"
    );
    assert_eq!(
        run_bin_bit::<_, 32>(|c, a, b| lt_u_n(c, a, b), a as u64, b as u64),
        a < b,
        "lt_u a={a:#x} b={b:#x}"
    );
    assert_eq!(
        run_bin_bit::<_, 32>(|c, a, b| lt_u_n(c, b, a), a as u64, b as u64),
        a > b,
        "gt_u a={a:#x} b={b:#x}"
    );
    assert_eq!(
        run_bin_bit::<_, 32>(
            |c, a, b| {
                let gt = lt_u_n(c, b, a);
                not(c, gt)
            },
            a as u64,
            b as u64
        ),
        a <= b,
        "le_u a={a:#x} b={b:#x}"
    );
    assert_eq!(
        run_bin_bit::<_, 32>(
            |c, a, b| {
                let lt = lt_u_n(c, a, b);
                not(c, lt)
            },
            a as u64,
            b as u64
        ),
        a >= b,
        "ge_u a={a:#x} b={b:#x}"
    );
    assert_eq!(
        run_bin_bit::<_, 32>(|c, a, b| lt_s_n(c, a, b), a as u64, b as u64),
        (a as i32) < (b as i32),
        "lt_s a={a:#x} b={b:#x}"
    );
    assert_eq!(
        run_bin_bit::<_, 32>(|c, a, b| lt_s_n(c, b, a), a as u64, b as u64),
        (a as i32) > (b as i32),
        "gt_s a={a:#x} b={b:#x}"
    );
    assert_eq!(
        run_bin_bit::<_, 32>(
            |c, a, b| {
                let gt = lt_s_n(c, b, a);
                not(c, gt)
            },
            a as u64,
            b as u64
        ),
        (a as i32) <= (b as i32),
        "le_s a={a:#x} b={b:#x}"
    );
    assert_eq!(
        run_bin_bit::<_, 32>(
            |c, a, b| {
                let lt = lt_s_n(c, a, b);
                not(c, lt)
            },
            a as u64,
            b as u64
        ),
        (a as i32) >= (b as i32),
        "ge_s a={a:#x} b={b:#x}"
    );
}

fn check_all_i64(a: u64, b: u64) {
    assert_eq!(
        run_bin_bit::<_, 64>(|c, a, b| eq_n(c, a, b), a, b),
        a == b,
        "eq a={a:#x} b={b:#x}"
    );
    assert_eq!(
        run_bin_bit::<_, 64>(|c, a, b| ne_n(c, a, b), a, b),
        a != b,
        "ne a={a:#x} b={b:#x}"
    );
    assert_eq!(
        run_bin_bit::<_, 64>(|c, a, b| lt_u_n(c, a, b), a, b),
        a < b,
        "lt_u a={a:#x} b={b:#x}"
    );
    assert_eq!(
        run_bin_bit::<_, 64>(|c, a, b| lt_u_n(c, b, a), a, b),
        a > b,
        "gt_u a={a:#x} b={b:#x}"
    );
    assert_eq!(
        run_bin_bit::<_, 64>(
            |c, a, b| {
                let gt = lt_u_n(c, b, a);
                not(c, gt)
            },
            a,
            b
        ),
        a <= b,
        "le_u a={a:#x} b={b:#x}"
    );
    assert_eq!(
        run_bin_bit::<_, 64>(
            |c, a, b| {
                let lt = lt_u_n(c, a, b);
                not(c, lt)
            },
            a,
            b
        ),
        a >= b,
        "ge_u a={a:#x} b={b:#x}"
    );
    assert_eq!(
        run_bin_bit::<_, 64>(|c, a, b| lt_s_n(c, a, b), a, b),
        (a as i64) < (b as i64),
        "lt_s a={a:#x} b={b:#x}"
    );
    assert_eq!(
        run_bin_bit::<_, 64>(|c, a, b| lt_s_n(c, b, a), a, b),
        (a as i64) > (b as i64),
        "gt_s a={a:#x} b={b:#x}"
    );
    assert_eq!(
        run_bin_bit::<_, 64>(
            |c, a, b| {
                let gt = lt_s_n(c, b, a);
                not(c, gt)
            },
            a,
            b
        ),
        (a as i64) <= (b as i64),
        "le_s a={a:#x} b={b:#x}"
    );
    assert_eq!(
        run_bin_bit::<_, 64>(
            |c, a, b| {
                let lt = lt_s_n(c, a, b);
                not(c, lt)
            },
            a,
            b
        ),
        (a as i64) >= (b as i64),
        "ge_s a={a:#x} b={b:#x}"
    );
}

#[test]
fn boundary_i32_all_ops() {
    let vals: [u32; 9] = [
        0,
        1,
        u32::MAX,
        i32::MIN as u32,
        i32::MAX as u32,
        (-1i32) as u32,
        0x8000_0000,
        0x0000_0001,
        0x0000_8000,
    ];
    for &a in &vals {
        for &b in &vals {
            check_all_i32(a, b);
        }
    }
    check_all_i32(i32::MIN as u32, i32::MAX as u32);
    check_all_i32(i32::MAX as u32, i32::MIN as u32);
    check_all_i32(1, (-1i32) as u32);
    check_all_i32((-1i32) as u32, 1);
    check_all_i32(0, i32::MIN as u32);
    check_all_i32(i32::MIN as u32, 0);
}

#[test]
fn boundary_i64_all_ops() {
    let vals: [u64; 9] = [
        0,
        1,
        u64::MAX,
        i64::MIN as u64,
        i64::MAX as u64,
        (-1i64) as u64,
        0x8000_0000_0000_0000,
        0x0000_0000_0000_0001,
        0x0000_0001_0000_0000,
    ];
    for &a in &vals {
        for &b in &vals {
            check_all_i64(a, b);
        }
    }
    check_all_i64(i64::MIN as u64, i64::MAX as u64);
    check_all_i64(i64::MAX as u64, i64::MIN as u64);
    check_all_i64(1, (-1i64) as u64);
    check_all_i64((-1i64) as u64, 1);
    check_all_i64(0, i64::MIN as u64);
    check_all_i64(i64::MIN as u64, 0);
}

#[test]
fn boundary_eqz() {
    assert!(run_un_bit::<_, 32>(|c, a| eqz_n(c, a), 0));
    for v in [
        1u32,
        u32::MAX,
        i32::MIN as u32,
        i32::MAX as u32,
        0x8000_0000,
        0x0000_0001,
    ] {
        assert!(
            !run_un_bit::<_, 32>(|c, a| eqz_n(c, a), v as u64),
            "i32eqz({v:#x}) should be false"
        );
    }
    assert!(run_un_bit::<_, 64>(|c, a| eqz_n(c, a), 0));
    for v in [
        1u64,
        u64::MAX,
        i64::MIN as u64,
        i64::MAX as u64,
        0x8000_0000_0000_0000,
        0x0000_0000_0000_0001,
    ] {
        assert!(
            !run_un_bit::<_, 64>(|c, a| eqz_n(c, a), v),
            "i64eqz({v:#x}) should be false"
        );
    }
}

#[test]
fn exhaustive_n8_binary_all_ops() {
    for a in 0u16..256 {
        for b in 0u16..256 {
            let (au, bu) = (a as u8, b as u8);
            let (ai, bi) = (au as i8, bu as i8);
            let a64 = au as u64;
            let b64 = bu as u64;

            assert_eq!(
                run_bin_bit::<_, 8>(|c, a, b| eq8(c, a, b), a64, b64),
                au == bu,
                "eq a={au} b={bu}"
            );
            assert_eq!(
                run_bin_bit::<_, 8>(|c, a, b| ne8(c, a, b), a64, b64),
                au != bu,
                "ne a={au} b={bu}"
            );
            assert_eq!(
                run_bin_bit::<_, 8>(|c, a, b| lt_u8(c, a, b), a64, b64),
                au < bu,
                "lt_u a={au} b={bu}"
            );
            assert_eq!(
                run_bin_bit::<_, 8>(|c, a, b| gt_u8(c, a, b), a64, b64),
                au > bu,
                "gt_u a={au} b={bu}"
            );
            assert_eq!(
                run_bin_bit::<_, 8>(|c, a, b| le_u8(c, a, b), a64, b64),
                au <= bu,
                "le_u a={au} b={bu}"
            );
            assert_eq!(
                run_bin_bit::<_, 8>(|c, a, b| ge_u8(c, a, b), a64, b64),
                au >= bu,
                "ge_u a={au} b={bu}"
            );
            assert_eq!(
                run_bin_bit::<_, 8>(|c, a, b| lt_s8(c, a, b), a64, b64),
                ai < bi,
                "lt_s a={ai} b={bi}"
            );
            assert_eq!(
                run_bin_bit::<_, 8>(|c, a, b| gt_s8(c, a, b), a64, b64),
                ai > bi,
                "gt_s a={ai} b={bi}"
            );
            assert_eq!(
                run_bin_bit::<_, 8>(|c, a, b| le_s8(c, a, b), a64, b64),
                ai <= bi,
                "le_s a={ai} b={bi}"
            );
            assert_eq!(
                run_bin_bit::<_, 8>(|c, a, b| ge_s8(c, a, b), a64, b64),
                ai >= bi,
                "ge_s a={ai} b={bi}"
            );
        }
    }
}

#[test]
fn exhaustive_n8_eqz() {
    for a in 0u16..256 {
        let au = a as u8;
        assert_eq!(
            run_un_bit::<_, 8>(|c, a| eqz8(c, a), au as u64),
            au == 0,
            "eqz a={au}"
        );
    }
}
