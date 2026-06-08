use crate::harness::{from_bits, run_bin, to_bits};
use mpz_circuits::WitnessCtx;
use mpz_fields::gf2::Gf2;
use proptest::prelude::*;

fn and8<C: mpz_circuits::Context<Field = Gf2>>(
    ctx: &mut C,
    a: [C::Wire; 8],
    b: [C::Wire; 8],
) -> [C::Wire; 8] {
    crate::and_arr(ctx, a, b)
}

fn or8<C: mpz_circuits::Context<Field = Gf2>>(
    ctx: &mut C,
    a: [C::Wire; 8],
    b: [C::Wire; 8],
) -> [C::Wire; 8] {
    crate::or_arr(ctx, a, b)
}

fn xor8<C: mpz_circuits::Context<Field = Gf2>>(
    ctx: &mut C,
    a: [C::Wire; 8],
    b: [C::Wire; 8],
) -> [C::Wire; 8] {
    crate::xor_arr(ctx, a, b)
}

fn shl8<C: mpz_circuits::Context<Field = Gf2>>(
    ctx: &mut C,
    a: [C::Wire; 8],
    b: [C::Wire; 8],
) -> [C::Wire; 8] {
    crate::shl_n(ctx, a, b)
}

fn shr_u8<C: mpz_circuits::Context<Field = Gf2>>(
    ctx: &mut C,
    a: [C::Wire; 8],
    b: [C::Wire; 8],
) -> [C::Wire; 8] {
    crate::shr_u_n(ctx, a, b)
}

fn shr_s8<C: mpz_circuits::Context<Field = Gf2>>(
    ctx: &mut C,
    a: [C::Wire; 8],
    b: [C::Wire; 8],
) -> [C::Wire; 8] {
    crate::shr_s_n(ctx, a, b)
}

fn rotl8<C: mpz_circuits::Context<Field = Gf2>>(
    ctx: &mut C,
    a: [C::Wire; 8],
    b: [C::Wire; 8],
) -> [C::Wire; 8] {
    crate::rotl_n(ctx, a, b)
}

fn rotr8<C: mpz_circuits::Context<Field = Gf2>>(
    ctx: &mut C,
    a: [C::Wire; 8],
    b: [C::Wire; 8],
) -> [C::Wire; 8] {
    crate::rotr_n(ctx, a, b)
}

fn ref_shl8(a: u8, b: u8) -> u8 {
    a.wrapping_shl((b & 7) as u32)
}
fn ref_shr_u8(a: u8, b: u8) -> u8 {
    a.wrapping_shr((b & 7) as u32)
}
fn ref_shr_s8(a: u8, b: u8) -> u8 {
    (a as i8).wrapping_shr((b & 7) as u32) as u8
}
fn ref_rotl8(a: u8, b: u8) -> u8 {
    a.rotate_left((b & 7) as u32)
}
fn ref_rotr8(a: u8, b: u8) -> u8 {
    a.rotate_right((b & 7) as u32)
}

fn word32() -> impl Strategy<Value = u32> {
    prop_oneof![
        Just(0u32),
        Just(1u32),
        Just(u32::MAX),
        Just(0x8000_0000u32),
        Just(i32::MAX as u32),
        (0u32..32).prop_map(|k| 1u32 << k),
        (0u32..64),
        any::<u32>(),
    ]
}

fn word64() -> impl Strategy<Value = u64> {
    prop_oneof![
        Just(0u64),
        Just(1u64),
        Just(u64::MAX),
        Just(0x8000_0000_0000_0000u64),
        Just(i64::MAX as u64),
        (0u64..64).prop_map(|k| 1u64 << k),
        (0u64..64),
        any::<u64>(),
    ]
}

fn amount32() -> impl Strategy<Value = u32> {
    prop_oneof![
        Just(0u32),
        Just(1u32),
        Just(31u32),
        Just(32u32),
        Just(33u32),
        Just(63u32),
        Just(64u32),
        Just(u32::MAX),
        any::<u32>(),
    ]
}

fn amount64() -> impl Strategy<Value = u64> {
    prop_oneof![
        Just(0u64),
        Just(1u64),
        Just(63u64),
        Just(64u64),
        Just(65u64),
        Just(127u64),
        Just(128u64),
        Just(u64::MAX),
        any::<u64>(),
    ]
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
    fn pt_i32and(a in word32(), b in word32()) {
        let got = run_bin::<_, 32>(|c, a, b| crate::and_arr(c, a, b), a as u64, b as u64) as u32;
        prop_assert_eq!(got, a & b);
    }

    #[test]
    fn pt_i32or(a in word32(), b in word32()) {
        let got = run_bin::<_, 32>(|c, a, b| crate::or_arr(c, a, b), a as u64, b as u64) as u32;
        prop_assert_eq!(got, a | b);
    }

    #[test]
    fn pt_i32xor(a in word32(), b in word32()) {
        let got = run_bin::<_, 32>(|c, a, b| crate::xor_arr(c, a, b), a as u64, b as u64) as u32;
        prop_assert_eq!(got, a ^ b);
    }

    #[test]
    fn pt_i32shl(a in word32(), amt in amount32()) {
        let got = run_bin::<_, 32>(|c, a, b| crate::shl_n(c, a, b), a as u64, amt as u64) as u32;
        prop_assert_eq!(got, a.wrapping_shl(amt & 31));
    }

    #[test]
    fn pt_i32shr_u(a in word32(), amt in amount32()) {
        let got = run_bin::<_, 32>(|c, a, b| crate::shr_u_n(c, a, b), a as u64, amt as u64) as u32;
        prop_assert_eq!(got, a.wrapping_shr(amt & 31));
    }

    #[test]
    fn pt_i32shr_s(a in word32(), amt in amount32()) {
        let got = run_bin::<_, 32>(|c, a, b| crate::shr_s_n(c, a, b), a as u64, amt as u64) as u32;
        prop_assert_eq!(got, (a as i32).wrapping_shr(amt & 31) as u32);
    }

    #[test]
    fn pt_i32rotl(a in word32(), amt in amount32()) {
        let got = run_bin::<_, 32>(|c, a, b| crate::rotl_n(c, a, b), a as u64, amt as u64) as u32;
        prop_assert_eq!(got, a.rotate_left(amt & 31));
    }

    #[test]
    fn pt_i32rotr(a in word32(), amt in amount32()) {
        let got = run_bin::<_, 32>(|c, a, b| crate::rotr_n(c, a, b), a as u64, amt as u64) as u32;
        prop_assert_eq!(got, a.rotate_right(amt & 31));
    }
}

proptest! {
    #![proptest_config(cfg())]

    #[test]
    fn pt_i64and(a in word64(), b in word64()) {
        let got = run_bin::<_, 64>(|c, a, b| crate::and_arr(c, a, b), a, b);
        prop_assert_eq!(got, a & b);
    }

    #[test]
    fn pt_i64or(a in word64(), b in word64()) {
        let got = run_bin::<_, 64>(|c, a, b| crate::or_arr(c, a, b), a, b);
        prop_assert_eq!(got, a | b);
    }

    #[test]
    fn pt_i64xor(a in word64(), b in word64()) {
        let got = run_bin::<_, 64>(|c, a, b| crate::xor_arr(c, a, b), a, b);
        prop_assert_eq!(got, a ^ b);
    }

    #[test]
    fn pt_i64shl(a in word64(), amt in amount64()) {
        let got = run_bin::<_, 64>(|c, a, b| crate::shl_n(c, a, b), a, amt);
        prop_assert_eq!(got, a.wrapping_shl((amt & 63) as u32));
    }

    #[test]
    fn pt_i64shr_u(a in word64(), amt in amount64()) {
        let got = run_bin::<_, 64>(|c, a, b| crate::shr_u_n(c, a, b), a, amt);
        prop_assert_eq!(got, a.wrapping_shr((amt & 63) as u32));
    }

    #[test]
    fn pt_i64shr_s(a in word64(), amt in amount64()) {
        let got = run_bin::<_, 64>(|c, a, b| crate::shr_s_n(c, a, b), a, amt);
        prop_assert_eq!(got, (a as i64).wrapping_shr((amt & 63) as u32) as u64);
    }

    #[test]
    fn pt_i64rotl(a in word64(), amt in amount64()) {
        let got = run_bin::<_, 64>(|c, a, b| crate::rotl_n(c, a, b), a, amt);
        prop_assert_eq!(got, a.rotate_left((amt & 63) as u32));
    }

    #[test]
    fn pt_i64rotr(a in word64(), amt in amount64()) {
        let got = run_bin::<_, 64>(|c, a, b| crate::rotr_n(c, a, b), a, amt);
        prop_assert_eq!(got, a.rotate_right((amt & 63) as u32));
    }
}

const W32: [u32; 7] = [
    0,
    1,
    u32::MAX,
    0x8000_0000,
    0x7FFF_FFFF,
    0x0F0F_0F0F,
    0x1234_5678,
];

const W64: [u64; 7] = [
    0,
    1,
    u64::MAX,
    0x8000_0000_0000_0000,
    0x7FFF_FFFF_FFFF_FFFF,
    0x0F0F_0F0F_0F0F_0F0F,
    0x1234_5678_9ABC_DEF0,
];

const AMT32: [u32; 9] = [0, 1, 15, 31, 32, 33, 63, 64, u32::MAX];

const AMT64: [u64; 9] = [0, 1, 31, 63, 64, 65, 127, 128, u64::MAX];

#[test]
fn boundary_i32_bitwise() {
    for &a in &W32 {
        for &b in &W32 {
            assert_eq!(
                run_bin::<_, 32>(|c, a, b| crate::and_arr(c, a, b), a as u64, b as u64) as u32,
                a & b,
                "and a={a:#x} b={b:#x}"
            );
            assert_eq!(
                run_bin::<_, 32>(|c, a, b| crate::or_arr(c, a, b), a as u64, b as u64) as u32,
                a | b,
                "or a={a:#x} b={b:#x}"
            );
            assert_eq!(
                run_bin::<_, 32>(|c, a, b| crate::xor_arr(c, a, b), a as u64, b as u64) as u32,
                a ^ b,
                "xor a={a:#x} b={b:#x}"
            );
        }
    }
    for k in 0..32u32 {
        let a = 1u32 << k;
        assert_eq!(
            run_bin::<_, 32>(|c, a, b| crate::and_arr(c, a, b), a as u64, a as u64) as u32,
            a
        );
        assert_eq!(
            run_bin::<_, 32>(|c, a, b| crate::xor_arr(c, a, b), a as u64, a as u64) as u32,
            0
        );
    }
}

#[test]
fn boundary_i32_shifts_rotates() {
    for &a in &W32 {
        for &amt in &AMT32 {
            let s = amt & 31;
            assert_eq!(
                run_bin::<_, 32>(|c, a, b| crate::shl_n(c, a, b), a as u64, amt as u64) as u32,
                a.wrapping_shl(s),
                "shl a={a:#x} amt={amt}"
            );
            assert_eq!(
                run_bin::<_, 32>(|c, a, b| crate::shr_u_n(c, a, b), a as u64, amt as u64) as u32,
                a.wrapping_shr(s),
                "shr_u a={a:#x} amt={amt}"
            );
            assert_eq!(
                run_bin::<_, 32>(|c, a, b| crate::shr_s_n(c, a, b), a as u64, amt as u64) as u32,
                (a as i32).wrapping_shr(s) as u32,
                "shr_s a={a:#x} amt={amt}"
            );
            assert_eq!(
                run_bin::<_, 32>(|c, a, b| crate::rotl_n(c, a, b), a as u64, amt as u64) as u32,
                a.rotate_left(s),
                "rotl a={a:#x} amt={amt}"
            );
            assert_eq!(
                run_bin::<_, 32>(|c, a, b| crate::rotr_n(c, a, b), a as u64, amt as u64) as u32,
                a.rotate_right(s),
                "rotr a={a:#x} amt={amt}"
            );
        }
    }
    for s in 0..32u32 {
        let a = 0x1234_5678u32;
        assert_eq!(
            run_bin::<_, 32>(|c, a, b| crate::shl_n(c, a, b), a as u64, s as u64) as u32,
            a.wrapping_shl(s),
            "shl sweep s={s}"
        );
        assert_eq!(
            run_bin::<_, 32>(|c, a, b| crate::shr_s_n(c, a, b), 0x8000_0000, s as u64) as u32,
            (0x8000_0000u32 as i32).wrapping_shr(s) as u32,
            "shr_s sign-fill sweep s={s}"
        );
        assert_eq!(
            run_bin::<_, 32>(|c, a, b| crate::rotr_n(c, a, b), a as u64, s as u64) as u32,
            a.rotate_right(s),
            "rotr sweep s={s}"
        );
    }
}

#[test]
fn boundary_i64_bitwise() {
    for &a in &W64 {
        for &b in &W64 {
            assert_eq!(
                run_bin::<_, 64>(|c, a, b| crate::and_arr(c, a, b), a, b),
                a & b,
                "and a={a:#x} b={b:#x}"
            );
            assert_eq!(
                run_bin::<_, 64>(|c, a, b| crate::or_arr(c, a, b), a, b),
                a | b,
                "or a={a:#x} b={b:#x}"
            );
            assert_eq!(
                run_bin::<_, 64>(|c, a, b| crate::xor_arr(c, a, b), a, b),
                a ^ b,
                "xor a={a:#x} b={b:#x}"
            );
        }
    }
}

#[test]
fn boundary_i64_shifts_rotates() {
    for &a in &W64 {
        for &amt in &AMT64 {
            let s = (amt & 63) as u32;
            assert_eq!(
                run_bin::<_, 64>(|c, a, b| crate::shl_n(c, a, b), a, amt),
                a.wrapping_shl(s),
                "shl a={a:#x} amt={amt}"
            );
            assert_eq!(
                run_bin::<_, 64>(|c, a, b| crate::shr_u_n(c, a, b), a, amt),
                a.wrapping_shr(s),
                "shr_u a={a:#x} amt={amt}"
            );
            assert_eq!(
                run_bin::<_, 64>(|c, a, b| crate::shr_s_n(c, a, b), a, amt),
                (a as i64).wrapping_shr(s) as u64,
                "shr_s a={a:#x} amt={amt}"
            );
            assert_eq!(
                run_bin::<_, 64>(|c, a, b| crate::rotl_n(c, a, b), a, amt),
                a.rotate_left(s),
                "rotl a={a:#x} amt={amt}"
            );
            assert_eq!(
                run_bin::<_, 64>(|c, a, b| crate::rotr_n(c, a, b), a, amt),
                a.rotate_right(s),
                "rotr a={a:#x} amt={amt}"
            );
        }
    }
    for s in 0..64u32 {
        let a = 0x1234_5678_9ABC_DEF0u64;
        assert_eq!(
            run_bin::<_, 64>(|c, a, b| crate::shl_n(c, a, b), a, s as u64),
            a.wrapping_shl(s),
            "shl sweep s={s}"
        );
        assert_eq!(
            run_bin::<_, 64>(
                |c, a, b| crate::shr_s_n(c, a, b),
                0x8000_0000_0000_0000,
                s as u64
            ),
            (0x8000_0000_0000_0000u64 as i64).wrapping_shr(s) as u64,
            "shr_s sign-fill sweep s={s}"
        );
        assert_eq!(
            run_bin::<_, 64>(|c, a, b| crate::rotr_n(c, a, b), a, s as u64),
            a.rotate_right(s),
            "rotr sweep s={s}"
        );
    }
}

fn run8<F>(g: F, a: u8, b: u8) -> u8
where
    F: for<'a, 'b> FnOnce(&'a mut WitnessCtx<'b, Gf2>, [Gf2; 8], [Gf2; 8]) -> [Gf2; 8],
{
    let mut w = Vec::new();
    let mut ctx = WitnessCtx { witness: &mut w };
    from_bits(g(&mut ctx, to_bits::<8>(a as u64), to_bits::<8>(b as u64))) as u8
}

#[test]
fn exhaustive_n8_bitwise() {
    for a in 0u8..=255 {
        for b in 0u8..=255 {
            assert_eq!(
                run8(|c, a, b| and8(c, a, b), a, b),
                a & b,
                "and a={a} b={b}"
            );
            assert_eq!(run8(|c, a, b| or8(c, a, b), a, b), a | b, "or a={a} b={b}");
            assert_eq!(
                run8(|c, a, b| xor8(c, a, b), a, b),
                a ^ b,
                "xor a={a} b={b}"
            );
        }
    }
}

#[test]
fn exhaustive_n8_shifts_rotates() {
    for a in 0u8..=255 {
        for b in 0u8..=255 {
            assert_eq!(
                run8(|c, a, b| shl8(c, a, b), a, b),
                ref_shl8(a, b),
                "shl a={a} b={b}"
            );
            assert_eq!(
                run8(|c, a, b| shr_u8(c, a, b), a, b),
                ref_shr_u8(a, b),
                "shr_u a={a} b={b}"
            );
            assert_eq!(
                run8(|c, a, b| shr_s8(c, a, b), a, b),
                ref_shr_s8(a, b),
                "shr_s a={a} b={b}"
            );
            assert_eq!(
                run8(|c, a, b| rotl8(c, a, b), a, b),
                ref_rotl8(a, b),
                "rotl a={a} b={b}"
            );
            assert_eq!(
                run8(|c, a, b| rotr8(c, a, b), a, b),
                ref_rotr8(a, b),
                "rotr a={a} b={b}"
            );
        }
    }
}
