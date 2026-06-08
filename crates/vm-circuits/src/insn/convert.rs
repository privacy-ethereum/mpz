use mpz_fields::gf2::Gf2;
use mpz_vm_memory::{I32, I64};

use super::CircuitContext;

pub struct I32Extend8S;

impl I32Extend8S {
    pub const COST: usize = 0;

    pub fn eval<C: CircuitContext>(_ctx: &mut C, a: I32) -> I32 {
        I32::from(crate::sign_extend_low_in_place::<C, 32>(a.to_wires(), 8))
    }
}

pub struct I32Extend16S;

impl I32Extend16S {
    pub const COST: usize = 0;

    pub fn eval<C: CircuitContext>(_ctx: &mut C, a: I32) -> I32 {
        I32::from(crate::sign_extend_low_in_place::<C, 32>(a.to_wires(), 16))
    }
}

pub struct I64Extend8S;

impl I64Extend8S {
    pub const COST: usize = 0;

    pub fn eval<C: CircuitContext>(_ctx: &mut C, a: I64) -> I64 {
        I64::from(crate::sign_extend_low_in_place::<C, 64>(a.to_wires(), 8))
    }
}

pub struct I64Extend16S;

impl I64Extend16S {
    pub const COST: usize = 0;

    pub fn eval<C: CircuitContext>(_ctx: &mut C, a: I64) -> I64 {
        I64::from(crate::sign_extend_low_in_place::<C, 64>(a.to_wires(), 16))
    }
}

pub struct I64Extend32S;

impl I64Extend32S {
    pub const COST: usize = 0;

    pub fn eval<C: CircuitContext>(_ctx: &mut C, a: I64) -> I64 {
        I64::from(crate::sign_extend_low_in_place::<C, 64>(a.to_wires(), 32))
    }
}

pub struct I32WrapI64;

impl I32WrapI64 {
    pub const COST: usize = 0;

    pub fn eval<C: CircuitContext>(_ctx: &mut C, a: I64) -> I32 {
        let wires = a.to_wires();
        let mut out = [wires[0]; 32];
        out.copy_from_slice(&wires[..32]);
        I32::from(out)
    }
}

pub struct I64ExtendI32S;

impl I64ExtendI32S {
    pub const COST: usize = 0;

    pub fn eval<C: CircuitContext>(_ctx: &mut C, a: I32) -> I64 {
        let wires = a.to_wires();
        let sign = wires[31];
        let mut out = [sign; 64];
        out[..32].copy_from_slice(&wires);
        I64::from(out)
    }
}

pub struct I64ExtendI32U;

impl I64ExtendI32U {
    pub const COST: usize = 0;

    pub fn eval<C: CircuitContext>(ctx: &mut C, a: I32) -> I64 {
        let wires = a.to_wires();
        let zero = ctx.constant(Gf2(false));
        let mut out = [zero; 64];
        out[..32].copy_from_slice(&wires);
        I64::from(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::insn::{dummy_i32, dummy_i64};

    #[test]
    fn costs_match_gate_counts() {
        assert_cost!(I32Extend8S::COST, |ctx| I32Extend8S::eval(ctx, dummy_i32()));
        assert_cost!(I32Extend16S::COST, |ctx| I32Extend16S::eval(
            ctx,
            dummy_i32()
        ));
        assert_cost!(I64Extend8S::COST, |ctx| I64Extend8S::eval(ctx, dummy_i64()));
        assert_cost!(I64Extend16S::COST, |ctx| I64Extend16S::eval(
            ctx,
            dummy_i64()
        ));
        assert_cost!(I64Extend32S::COST, |ctx| I64Extend32S::eval(
            ctx,
            dummy_i64()
        ));
        assert_cost!(I32WrapI64::COST, |ctx| I32WrapI64::eval(ctx, dummy_i64()));
        assert_cost!(I64ExtendI32S::COST, |ctx| I64ExtendI32S::eval(
            ctx,
            dummy_i32()
        ));
        assert_cost!(I64ExtendI32U::COST, |ctx| I64ExtendI32U::eval(
            ctx,
            dummy_i32()
        ));
    }
}
