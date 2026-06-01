use super::*;
use mpz_circuits_new::Context;
use mpz_fields::gf2::Gf2;
use mpz_fields::gf2_128::Gf2_128;
use mpz_memory_core_new::{I32, I64};

struct EvalCtx;

impl Context for EvalCtx {
    type Error = ();
    type Wire = Gf2_128;
    type Field = Gf2;

    fn add(&mut self, a: Gf2_128, b: Gf2_128) -> Gf2_128 {
        a + b
    }

    fn sub(&mut self, a: Gf2_128, b: Gf2_128) -> Gf2_128 {
        a + b
    }

    fn mul(&mut self, a: Gf2_128, b: Gf2_128) -> Gf2_128 {
        a * b
    }

    fn constant(&mut self, v: Gf2) -> Gf2_128 {
        if v.0 { Gf2_128::ONE } else { Gf2_128::ZERO }
    }

    fn assert_const(&mut self, v: Gf2_128, expected: Gf2) -> Result<(), ()> {
        let exp = if expected.0 { Gf2_128::ONE } else { Gf2_128::ZERO };
        if v == exp { Ok(()) } else { Err(()) }
    }
}

fn wires<const N: usize>(v: u64) -> [Gf2_128; N] {
    let mut w = [Gf2_128::ZERO; N];
    for (i, wi) in w.iter_mut().enumerate() {
        if (v >> i) & 1 == 1 {
            *wi = Gf2_128::ONE;
        }
    }
    w
}

fn read<const N: usize>(w: [Gf2_128; N]) -> u64 {
    let mut v = 0u64;
    for (i, wi) in w.iter().enumerate() {
        if *wi == Gf2_128::ONE {
            v |= 1u64 << i;
        }
    }
    v
}

fn i32_in(v: u32) -> I32 {
    I32::from(wires::<32>(v as u64))
}

fn i64_in(v: u64) -> I64 {
    I64::from(wires::<64>(v))
}

fn i32_out(x: I32) -> u32 {
    read(x.to_wires()) as u32
}

fn i64_out(x: I64) -> u64 {
    read(x.to_wires())
}

const E32: [u32; 8] = [
    0,
    1,
    2,
    0x7FFF_FFFF,
    0x8000_0000,
    0xFFFF_FFFF,
    0x1234_5678,
    0xDEAD_BEEF,
];

const E64: [u64; 6] = [
    0,
    1,
    u64::MAX,
    0x8000_0000_0000_0000,
    0x1234_5678_9ABC_DEF0,
    0x0000_0000_FFFF_FFFF,
];

#[test]
fn eval_roundtrip_arith() {
    for &a in &E32 {
        for &b in &E32 {
            assert_eq!(
                i32_out(I32Add::eval(&mut EvalCtx, i32_in(a), i32_in(b))),
                a.wrapping_add(b)
            );
            assert_eq!(
                i32_out(I32Sub::eval(&mut EvalCtx, i32_in(a), i32_in(b))),
                a.wrapping_sub(b)
            );
            assert_eq!(
                i32_out(I32Mul::eval(&mut EvalCtx, i32_in(a), i32_in(b))),
                a.wrapping_mul(b)
            );
        }
    }
    for &a in &E64 {
        for &b in &E64 {
            assert_eq!(
                i64_out(I64Add::eval(&mut EvalCtx, i64_in(a), i64_in(b))),
                a.wrapping_add(b)
            );
            assert_eq!(
                i64_out(I64Mul::eval(&mut EvalCtx, i64_in(a), i64_in(b))),
                a.wrapping_mul(b)
            );
        }
    }
}

#[test]
fn eval_const_lowering() {
    for &a in &E32 {
        for &k in &E32 {
            assert_eq!(
                i32_out(I32Mul::eval_const(&mut EvalCtx, i32_in(a), k as i32)),
                a.wrapping_mul(k)
            );
            assert_eq!(
                i32_out(I32And::eval_const(&mut EvalCtx, i32_in(a), k as i32)),
                a & k
            );
            assert_eq!(
                i32_out(I32Or::eval_const(&mut EvalCtx, i32_in(a), k as i32)),
                a | k
            );
            if k != 0 {
                assert_eq!(
                    i32_out(I32DivU::eval_const_divisor(&mut EvalCtx, i32_in(a), k as i32)),
                    a / k
                );
            }
        }
    }
}

#[test]
fn const_shift_amount() {
    for &v in &E32 {
        for &n in &[0u32, 1, 7, 31, 32, 35] {
            let m = n & 31;
            assert_eq!(
                i32_out(I32Shl::eval_const_amount(&mut EvalCtx, i32_in(v), n as i32)),
                v.wrapping_shl(m),
                "shl v={v:#x} n={n}"
            );
            assert_eq!(
                i32_out(I32ShrU::eval_const_amount(&mut EvalCtx, i32_in(v), n as i32)),
                v.wrapping_shr(m),
                "shr_u v={v:#x} n={n}"
            );
            assert_eq!(
                i32_out(I32ShrS::eval_const_amount(i32_in(v), n as i32)),
                (v as i32).wrapping_shr(m) as u32,
                "shr_s v={v:#x} n={n}"
            );
            assert_eq!(
                i32_out(I32Rotl::eval_const_amount(i32_in(v), n as i32)),
                v.rotate_left(m),
                "rotl v={v:#x} n={n}"
            );
            assert_eq!(
                i32_out(I32Rotr::eval_const_amount(i32_in(v), n as i32)),
                v.rotate_right(m),
                "rotr v={v:#x} n={n}"
            );
        }
    }
    for &v in &E64 {
        for &n in &[0u32, 1, 63, 64, 70] {
            let m = n & 63;
            assert_eq!(
                i64_out(I64Shl::eval_const_amount(&mut EvalCtx, i64_in(v), n as i64)),
                v.wrapping_shl(m),
                "i64 shl v={v:#x} n={n}"
            );
            assert_eq!(
                i64_out(I64ShrU::eval_const_amount(&mut EvalCtx, i64_in(v), n as i64)),
                v.wrapping_shr(m),
                "i64 shr_u v={v:#x} n={n}"
            );
            assert_eq!(
                i64_out(I64ShrS::eval_const_amount(i64_in(v), n as i64)),
                (v as i64).wrapping_shr(m) as u64,
                "i64 shr_s v={v:#x} n={n}"
            );
            assert_eq!(
                i64_out(I64Rotl::eval_const_amount(i64_in(v), n as i64)),
                v.rotate_left(m),
                "i64 rotl v={v:#x} n={n}"
            );
            assert_eq!(
                i64_out(I64Rotr::eval_const_amount(i64_in(v), n as i64)),
                v.rotate_right(m),
                "i64 rotr v={v:#x} n={n}"
            );
        }
    }
}

#[test]
fn conversions() {
    for &v in &E32 {
        assert_eq!(
            i32_out(I32Extend8S::eval(&mut EvalCtx, i32_in(v))),
            ((v as i32) << 24 >> 24) as u32
        );
        assert_eq!(
            i32_out(I32Extend16S::eval(&mut EvalCtx, i32_in(v))),
            ((v as i32) << 16 >> 16) as u32
        );
        assert_eq!(
            i64_out(I64ExtendI32S::eval(&mut EvalCtx, i32_in(v))),
            v as i32 as i64 as u64
        );
        assert_eq!(
            i64_out(I64ExtendI32U::eval(&mut EvalCtx, i32_in(v))),
            v as u64
        );
    }
    for &v in &E64 {
        assert_eq!(
            i64_out(I64Extend8S::eval(&mut EvalCtx, i64_in(v))),
            ((v as i64) << 56 >> 56) as u64
        );
        assert_eq!(
            i64_out(I64Extend16S::eval(&mut EvalCtx, i64_in(v))),
            ((v as i64) << 48 >> 48) as u64
        );
        assert_eq!(
            i64_out(I64Extend32S::eval(&mut EvalCtx, i64_in(v))),
            ((v as i64) << 32 >> 32) as u64
        );
        assert_eq!(
            i32_out(I32WrapI64::eval(&mut EvalCtx, i64_in(v))),
            v as u32
        );
    }
}

#[test]
fn compare_packs_into_bit0() {
    for &a in &E32 {
        for &b in &E32 {
            assert_eq!(
                i32_out(I32Eq::eval(&mut EvalCtx, i32_in(a), i32_in(b))),
                (a == b) as u32
            );
            assert_eq!(
                i32_out(I32Ne::eval(&mut EvalCtx, i32_in(a), i32_in(b))),
                (a != b) as u32
            );
            assert_eq!(
                i32_out(I32LtU::eval(&mut EvalCtx, i32_in(a), i32_in(b))),
                (a < b) as u32
            );
            assert_eq!(
                i32_out(I32LtS::eval(&mut EvalCtx, i32_in(a), i32_in(b))),
                ((a as i32) < (b as i32)) as u32
            );
            assert_eq!(
                i32_out(I32GeU::eval(&mut EvalCtx, i32_in(a), i32_in(b))),
                (a >= b) as u32
            );
            assert_eq!(
                i32_out(I32LeS::eval(&mut EvalCtx, i32_in(a), i32_in(b))),
                ((a as i32) <= (b as i32)) as u32
            );
        }
    }
    assert_eq!(i32_out(I32Eqz::eval(&mut EvalCtx, i32_in(0))), 1);
    assert_eq!(i32_out(I32Eqz::eval(&mut EvalCtx, i32_in(7))), 0);
    assert_eq!(i32_out(I64Eqz::eval(&mut EvalCtx, i64_in(0))), 1);
}

#[test]
fn divrem_advice_roundtrip() {
    for &a in &E32 {
        for &b in &E32 {
            if b == 0 {
                continue;
            }
            let (q, r) = I32DivU::advice_values(a, b);
            assert_eq!(
                i32_out(
                    I32DivU::eval_with_advice(&mut EvalCtx, i32_in(a), i32_in(b), i32_in(q as u32), i32_in(r as u32))
                        .expect("honest")
                ),
                a / b
            );
            let (q, r) = I32RemU::advice_values(a, b);
            assert_eq!(
                i32_out(
                    I32RemU::eval_with_advice(&mut EvalCtx, i32_in(a), i32_in(b), i32_in(q as u32), i32_in(r as u32))
                        .expect("honest")
                ),
                a % b
            );
            let (sa, sb) = (a as i32, b as i32);
            let (q, r) = I32DivS::advice_values(sa, sb);
            assert_eq!(
                i32_out(
                    I32DivS::eval_with_advice(&mut EvalCtx, i32_in(a), i32_in(b), i32_in(q as u32), i32_in(r as u32))
                        .expect("honest")
                ) as i32,
                sa.wrapping_div(sb)
            );
            let (q, r) = I32RemS::advice_values(sa, sb);
            assert_eq!(
                i32_out(
                    I32RemS::eval_with_advice(&mut EvalCtx, i32_in(a), i32_in(b), i32_in(q as u32), i32_in(r as u32))
                        .expect("honest")
                ) as i32,
                sa.wrapping_rem(sb)
            );
        }
    }
    for &a in &E64 {
        for &b in &E64 {
            if b == 0 {
                continue;
            }
            let (q, r) = I64DivU::advice_values(a, b);
            assert_eq!(
                i64_out(
                    I64DivU::eval_with_advice(&mut EvalCtx, i64_in(a), i64_in(b), i64_in(q as u64), i64_in(r as u64))
                        .expect("honest")
                ),
                a / b
            );
        }
    }
}

#[test]
fn count_advice_roundtrip() {
    for &v in &E32 {
        let h = I32Clz::advice_values(v);
        assert_eq!(
            i32_out(I32Clz::eval_with_advice(&mut EvalCtx, i32_in(v), i32_in(h)).expect("honest")),
            v.leading_zeros()
        );
        let h = I32Ctz::advice_values(v);
        assert_eq!(
            i32_out(I32Ctz::eval_with_advice(&mut EvalCtx, i32_in(v), i32_in(h)).expect("honest")),
            v.trailing_zeros()
        );
    }
    for &v in &E64 {
        let h = I64Clz::advice_values(v);
        assert_eq!(
            i64_out(I64Clz::eval_with_advice(&mut EvalCtx, i64_in(v), i64_in(h)).expect("honest")),
            v.leading_zeros() as u64
        );
    }
}

#[test]
fn advice_soundness_rejects_dishonest() {
    let bad = I32DivU::eval_with_advice(&mut EvalCtx, i32_in(100), i32_in(7), i32_in(0), i32_in(100));
    assert!(bad.is_err(), "r >= b must be rejected");

    let bad = I32DivU::eval_with_advice(&mut EvalCtx, i32_in(100), i32_in(7), i32_in(13), i32_in(2));
    assert!(bad.is_err(), "q*b + r != a must be rejected");

    let h = I32Clz::advice_values(0xF0) ^ 1;
    assert!(
        I32Clz::eval_with_advice(&mut EvalCtx, i32_in(0xF0), i32_in(h)).is_err(),
        "wrong clz advice must be rejected"
    );
}
