use crate::{
    add_n,
    harness::{from_bits, run_bin, to_bits},
    mul_n, sub_n,
};
use mpz_circuits::{Context, WitnessCtx};
use mpz_fields::gf2::Gf2;
use proptest::prelude::*;

fn add8<C: Context<Field = Gf2>>(ctx: &mut C, a: [C::Wire; 8], b: [C::Wire; 8]) -> [C::Wire; 8] {
    add_n(ctx, a, b)
}

fn sub8<C: Context<Field = Gf2>>(ctx: &mut C, a: [C::Wire; 8], b: [C::Wire; 8]) -> [C::Wire; 8] {
    sub_n(ctx, a, b)
}

fn mul8<C: Context<Field = Gf2>>(ctx: &mut C, a: [C::Wire; 8], b: [C::Wire; 8]) -> [C::Wire; 8] {
    mul_n(ctx, a, b)
}

prop_compose! {
    fn biased_u32()(
        choice in 0u8..8,
        bit in 0u32..32,
        small in 0u32..256,
        any in any::<u32>(),
    ) -> u32 {
        match choice {
            0 => 0,
            1 => 1,
            2 => u32::MAX,
            3 => i32::MIN as u32,
            4 => i32::MAX as u32,
            5 => 1u32 << bit,
            6 => small,
            _ => any,
        }
    }
}

prop_compose! {
    fn biased_u64()(
        choice in 0u8..8,
        bit in 0u32..64,
        small in 0u64..256,
        any in any::<u64>(),
    ) -> u64 {
        match choice {
            0 => 0,
            1 => 1,
            2 => u64::MAX,
            3 => i64::MIN as u64,
            4 => i64::MAX as u64,
            5 => 1u64 << bit,
            6 => small,
            _ => any,
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 8192, ..ProptestConfig::default() })]

    #[test]
    fn prop_i32add(a in biased_u32(), b in biased_u32()) {
        let got = run_bin::<_, 32>(|c, a, b| add_n(c, a, b), a as u64, b as u64) as u32;
        prop_assert_eq!(got, a.wrapping_add(b), "a={:#x} b={:#x}", a, b);
    }

    #[test]
    fn prop_i32sub(a in biased_u32(), b in biased_u32()) {
        let got = run_bin::<_, 32>(|c, a, b| sub_n(c, a, b), a as u64, b as u64) as u32;
        prop_assert_eq!(got, a.wrapping_sub(b), "a={:#x} b={:#x}", a, b);
    }

    #[test]
    fn prop_i32mul(a in biased_u32(), b in biased_u32()) {
        let got = run_bin::<_, 32>(|c, a, b| mul_n(c, a, b), a as u64, b as u64) as u32;
        prop_assert_eq!(got, a.wrapping_mul(b), "a={:#x} b={:#x}", a, b);
    }

    #[test]
    fn prop_i64add(a in biased_u64(), b in biased_u64()) {
        let got = run_bin::<_, 64>(|c, a, b| add_n(c, a, b), a, b);
        prop_assert_eq!(got, a.wrapping_add(b), "a={:#x} b={:#x}", a, b);
    }

    #[test]
    fn prop_i64sub(a in biased_u64(), b in biased_u64()) {
        let got = run_bin::<_, 64>(|c, a, b| sub_n(c, a, b), a, b);
        prop_assert_eq!(got, a.wrapping_sub(b), "a={:#x} b={:#x}", a, b);
    }

    #[test]
    fn prop_i64mul(a in biased_u64(), b in biased_u64()) {
        let got = run_bin::<_, 64>(|c, a, b| mul_n(c, a, b), a, b);
        prop_assert_eq!(got, a.wrapping_mul(b), "a={:#x} b={:#x}", a, b);
    }
}

fn boundary_u32() -> [u32; 8] {
    [
        0,
        1,
        u32::MAX,
        i32::MIN as u32,
        i32::MAX as u32,
        0x8000_0000,
        0x0000_0001,
        0xFFFF_FFFF,
    ]
}

fn boundary_u64() -> [u64; 8] {
    [
        0,
        1,
        u64::MAX,
        i64::MIN as u64,
        i64::MAX as u64,
        0x8000_0000_0000_0000,
        0x0000_0000_0000_0001,
        0xFFFF_FFFF_FFFF_FFFF,
    ]
}

#[test]
fn i32add_boundaries() {
    for a in boundary_u32() {
        for b in boundary_u32() {
            let got = run_bin::<_, 32>(|c, a, b| add_n(c, a, b), a as u64, b as u64) as u32;
            assert_eq!(got, a.wrapping_add(b), "a={a:#x} b={b:#x}");
        }
    }
}

#[test]
fn i32sub_boundaries() {
    for a in boundary_u32() {
        for b in boundary_u32() {
            let got = run_bin::<_, 32>(|c, a, b| sub_n(c, a, b), a as u64, b as u64) as u32;
            assert_eq!(got, a.wrapping_sub(b), "a={a:#x} b={b:#x}");
        }
    }
}

#[test]
fn i32mul_boundaries() {
    for a in boundary_u32() {
        for b in boundary_u32() {
            let got = run_bin::<_, 32>(|c, a, b| mul_n(c, a, b), a as u64, b as u64) as u32;
            assert_eq!(got, a.wrapping_mul(b), "a={a:#x} b={b:#x}");
        }
    }
}

#[test]
fn i64add_boundaries() {
    for a in boundary_u64() {
        for b in boundary_u64() {
            let got = run_bin::<_, 64>(|c, a, b| add_n(c, a, b), a, b);
            assert_eq!(got, a.wrapping_add(b), "a={a:#x} b={b:#x}");
        }
    }
}

#[test]
fn i64sub_boundaries() {
    for a in boundary_u64() {
        for b in boundary_u64() {
            let got = run_bin::<_, 64>(|c, a, b| sub_n(c, a, b), a, b);
            assert_eq!(got, a.wrapping_sub(b), "a={a:#x} b={b:#x}");
        }
    }
}

#[test]
fn i64mul_boundaries() {
    for a in boundary_u64() {
        for b in boundary_u64() {
            let got = run_bin::<_, 64>(|c, a, b| mul_n(c, a, b), a, b);
            assert_eq!(got, a.wrapping_mul(b), "a={a:#x} b={b:#x}");
        }
    }
}

#[test]
fn add8_exhaustive() {
    for a in 0u16..256 {
        for b in 0u16..256 {
            let (a, b) = (a as u8, b as u8);
            let got = run_bin::<_, 8>(|c, a, b| add8(c, a, b), a as u64, b as u64) as u8;
            assert_eq!(got, a.wrapping_add(b), "a={a:#x} b={b:#x}");
        }
    }
}

#[test]
fn sub8_exhaustive() {
    for a in 0u16..256 {
        for b in 0u16..256 {
            let (a, b) = (a as u8, b as u8);
            let got = run_bin::<_, 8>(|c, a, b| sub8(c, a, b), a as u64, b as u64) as u8;
            assert_eq!(got, a.wrapping_sub(b), "a={a:#x} b={b:#x}");
        }
    }
}

#[test]
fn mul8_exhaustive() {
    for a in 0u16..256 {
        for b in 0u16..256 {
            let (a, b) = (a as u8, b as u8);
            let got = run_bin::<_, 8>(|c, a, b| mul8(c, a, b), a as u64, b as u64) as u8;
            assert_eq!(got, a.wrapping_mul(b), "a={a:#x} b={b:#x}");
        }
    }
}

#[test]
fn add8_direct_smoke() {
    let mut w = Vec::new();
    let mut ctx = WitnessCtx { witness: &mut w };
    let out = add8(&mut ctx, to_bits::<8>(0xFF), to_bits::<8>(0x01));
    assert_eq!(from_bits(out) as u8, 0u8);
}
