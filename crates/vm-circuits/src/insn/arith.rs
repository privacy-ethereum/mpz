use mpz_vm_memory::{I32, I64};

use super::CircuitContext;

use super::{const_i32, const_i64};

pub struct I32Add;

impl I32Add {
    pub const COST: usize = 32;

    pub fn eval<C: CircuitContext>(ctx: &mut C, a: I32, b: I32) -> I32 {
        I32::from(crate::add_n::<C, 32>(ctx, a.to_wires(), b.to_wires()))
    }
}

pub struct I32Sub;

impl I32Sub {
    pub const COST: usize = 32;

    pub fn eval<C: CircuitContext>(ctx: &mut C, a: I32, b: I32) -> I32 {
        I32::from(crate::sub_n::<C, 32>(ctx, a.to_wires(), b.to_wires()))
    }
}

pub struct I32Mul;

impl I32Mul {
    pub const COST: usize = 2358;
    pub const COST_CONST: usize = 2358;

    pub fn eval<C: CircuitContext>(ctx: &mut C, a: I32, b: I32) -> I32 {
        I32::from(crate::mul_n::<C, 32>(ctx, a.to_wires(), b.to_wires()))
    }

    pub fn eval_const<C: CircuitContext>(ctx: &mut C, a: I32, konst: i32) -> I32 {
        let k = const_i32(ctx, konst);
        I32::from(crate::mul_n::<C, 32>(ctx, a.to_wires(), k.to_wires()))
    }
}

pub struct I64Add;

impl I64Add {
    pub const COST: usize = 64;

    pub fn eval<C: CircuitContext>(ctx: &mut C, a: I64, b: I64) -> I64 {
        I64::from(crate::add_n::<C, 64>(ctx, a.to_wires(), b.to_wires()))
    }
}

pub struct I64Sub;

impl I64Sub {
    pub const COST: usize = 64;

    pub fn eval<C: CircuitContext>(ctx: &mut C, a: I64, b: I64) -> I64 {
        I64::from(crate::sub_n::<C, 64>(ctx, a.to_wires(), b.to_wires()))
    }
}

pub struct I64Mul;

impl I64Mul {
    pub const COST: usize = 7669;
    pub const COST_CONST: usize = 7669;

    pub fn eval<C: CircuitContext>(ctx: &mut C, a: I64, b: I64) -> I64 {
        I64::from(crate::mul_n::<C, 64>(ctx, a.to_wires(), b.to_wires()))
    }

    pub fn eval_const<C: CircuitContext>(ctx: &mut C, a: I64, konst: i64) -> I64 {
        let k = const_i64(ctx, konst);
        I64::from(crate::mul_n::<C, 64>(ctx, a.to_wires(), k.to_wires()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::insn::{dummy_i32, dummy_i64};

    #[test]
    fn costs_match_gate_counts() {
        assert_cost!(I32Add::COST, |ctx| I32Add::eval(
            ctx,
            dummy_i32(),
            dummy_i32()
        ));
        assert_cost!(I32Sub::COST, |ctx| I32Sub::eval(
            ctx,
            dummy_i32(),
            dummy_i32()
        ));
        assert_cost!(I32Mul::COST, |ctx| I32Mul::eval(
            ctx,
            dummy_i32(),
            dummy_i32()
        ));
        assert_cost!(I32Mul::COST_CONST, |ctx| I32Mul::eval_const(
            ctx,
            dummy_i32(),
            0
        ));
        assert_cost!(I64Add::COST, |ctx| I64Add::eval(
            ctx,
            dummy_i64(),
            dummy_i64()
        ));
        assert_cost!(I64Sub::COST, |ctx| I64Sub::eval(
            ctx,
            dummy_i64(),
            dummy_i64()
        ));
        assert_cost!(I64Mul::COST, |ctx| I64Mul::eval(
            ctx,
            dummy_i64(),
            dummy_i64()
        ));
        assert_cost!(I64Mul::COST_CONST, |ctx| I64Mul::eval_const(
            ctx,
            dummy_i64(),
            0
        ));
    }
}
