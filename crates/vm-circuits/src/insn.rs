use mpz_circuits_new::Context;
#[cfg(test)]
use mpz_circuits_new::MaybeConst;
#[cfg(test)]
use mpz_fields::Field;
use mpz_fields::gf2::Gf2;
use mpz_fields::gf2_128::Gf2_128;
use mpz_vm_memory::{I32, I64};

pub trait CircuitContext: Context<Wire = Gf2_128, Field = Gf2> {}

impl<C: Context<Wire = Gf2_128, Field = Gf2>> CircuitContext for C {}

#[cfg(test)]
macro_rules! assert_cost {
    ($cost:expr, |$ctx:ident| $eval:expr) => {
        assert_eq!(
            $cost,
            $crate::insn::GateCount::count(|$ctx| {
                let _ = $eval;
            })
        );
    };
}

mod arith;
mod bitwise;
mod compare;
mod convert;
mod count;
mod divrem;
mod shift;

#[cfg(test)]
mod value_tests;

pub use arith::*;
pub use bitwise::*;
pub use compare::*;
pub use convert::*;
pub use count::*;
pub use divrem::*;
pub use shift::*;

pub(crate) fn zero_extend_bit<C: CircuitContext>(ctx: &mut C, bit: Gf2_128) -> I32 {
    let zero = ctx.constant(Gf2(false));
    let mut wires = [zero; 32];
    wires[0] = bit;
    I32::from(wires)
}

pub(crate) fn const_i32<C: CircuitContext>(ctx: &mut C, v: i32) -> I32 {
    let mut wires = [Gf2_128::ZERO; 32];
    for (i, w) in wires.iter_mut().enumerate() {
        *w = ctx.constant(Gf2((v >> i) & 1 != 0));
    }
    I32::from(wires)
}

pub(crate) fn const_i64<C: CircuitContext>(ctx: &mut C, v: i64) -> I64 {
    let mut wires = [Gf2_128::ZERO; 64];
    for (i, w) in wires.iter_mut().enumerate() {
        *w = ctx.constant(Gf2((v >> i) & 1 != 0));
    }
    I64::from(wires)
}

#[cfg(test)]
pub(crate) fn dummy_i32() -> I32 {
    I32::from([Gf2_128::ZERO; 32])
}

#[cfg(test)]
pub(crate) fn dummy_i64() -> I64 {
    I64::from([Gf2_128::ZERO; 64])
}

#[cfg(test)]
#[derive(Default)]
pub(crate) struct GateCount {
    pub(crate) ands: usize,
}

#[cfg(test)]
impl GateCount {
    pub(crate) fn count(f: impl FnOnce(&mut GateCount)) -> usize {
        let mut ctx = GateCount::default();
        f(&mut ctx);
        ctx.ands
    }
}

#[cfg(test)]
impl Context for GateCount {
    type Error = ();
    type Wire = Gf2_128;
    type Field = Gf2;

    fn add(&mut self, _a: Gf2_128, _b: Gf2_128) -> Gf2_128 {
        Gf2_128::ZERO
    }

    fn sub(&mut self, _a: Gf2_128, _b: Gf2_128) -> Gf2_128 {
        Gf2_128::ZERO
    }

    fn mul(&mut self, _a: Gf2_128, _b: Gf2_128) -> Gf2_128 {
        self.ands += 1;
        Gf2_128::ZERO
    }

    fn mul_const(&mut self, a: Gf2_128, b: Gf2) -> MaybeConst<Gf2_128, Gf2> {
        if b == Gf2::zero() {
            MaybeConst::Const(Gf2::zero())
        } else if b == Gf2::one() {
            MaybeConst::Var(a)
        } else {
            MaybeConst::Var(self.mul(a, a))
        }
    }

    fn constant(&mut self, _v: Gf2) -> Gf2_128 {
        Gf2_128::ZERO
    }

    fn assert_const(&mut self, _v: Gf2_128, _expected: Gf2) -> Result<(), ()> {
        Ok(())
    }
}
