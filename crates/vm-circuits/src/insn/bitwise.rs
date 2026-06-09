use mpz_vm_memory::{I32, I64};

use super::CircuitContext;

use super::{const_i32, const_i64};

pub struct I32And;

impl I32And {
    pub const COST: usize = 32;
    pub const COST_CONST: usize = 32;

    pub fn eval<C: CircuitContext>(ctx: &mut C, a: I32, b: I32) -> I32 {
        I32::from(crate::and_arr::<C, 32>(ctx, a.to_wires(), b.to_wires()))
    }

    pub fn eval_const<C: CircuitContext>(ctx: &mut C, a: I32, konst: i32) -> I32 {
        let k = const_i32(ctx, konst);
        I32::from(crate::and_arr::<C, 32>(ctx, a.to_wires(), k.to_wires()))
    }
}

pub struct I32Or;

impl I32Or {
    pub const COST: usize = 32;
    pub const COST_CONST: usize = 32;

    pub fn eval<C: CircuitContext>(ctx: &mut C, a: I32, b: I32) -> I32 {
        I32::from(crate::or_arr::<C, 32>(ctx, a.to_wires(), b.to_wires()))
    }

    pub fn eval_const<C: CircuitContext>(ctx: &mut C, a: I32, konst: i32) -> I32 {
        let k = const_i32(ctx, konst);
        I32::from(crate::or_arr::<C, 32>(ctx, a.to_wires(), k.to_wires()))
    }
}

pub struct I32Xor;

impl I32Xor {
    pub const COST: usize = 0;

    pub fn eval<C: CircuitContext>(ctx: &mut C, a: I32, b: I32) -> I32 {
        I32::from(crate::xor_arr::<C, 32>(ctx, a.to_wires(), b.to_wires()))
    }
}

pub struct I64And;

impl I64And {
    pub const COST: usize = 64;
    pub const COST_CONST: usize = 64;

    pub fn eval<C: CircuitContext>(ctx: &mut C, a: I64, b: I64) -> I64 {
        I64::from(crate::and_arr::<C, 64>(ctx, a.to_wires(), b.to_wires()))
    }

    pub fn eval_const<C: CircuitContext>(ctx: &mut C, a: I64, konst: i64) -> I64 {
        let k = const_i64(ctx, konst);
        I64::from(crate::and_arr::<C, 64>(ctx, a.to_wires(), k.to_wires()))
    }
}

pub struct I64Or;

impl I64Or {
    pub const COST: usize = 64;
    pub const COST_CONST: usize = 64;

    pub fn eval<C: CircuitContext>(ctx: &mut C, a: I64, b: I64) -> I64 {
        I64::from(crate::or_arr::<C, 64>(ctx, a.to_wires(), b.to_wires()))
    }

    pub fn eval_const<C: CircuitContext>(ctx: &mut C, a: I64, konst: i64) -> I64 {
        let k = const_i64(ctx, konst);
        I64::from(crate::or_arr::<C, 64>(ctx, a.to_wires(), k.to_wires()))
    }
}

pub struct I64Xor;

impl I64Xor {
    pub const COST: usize = 0;

    pub fn eval<C: CircuitContext>(ctx: &mut C, a: I64, b: I64) -> I64 {
        I64::from(crate::xor_arr::<C, 64>(ctx, a.to_wires(), b.to_wires()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::insn::{dummy_i32, dummy_i64};

    #[test]
    fn costs_match_gate_counts() {
        assert_cost!(I32And::COST, |ctx| I32And::eval(
            ctx,
            dummy_i32(),
            dummy_i32()
        ));
        assert_cost!(I32And::COST_CONST, |ctx| I32And::eval_const(
            ctx,
            dummy_i32(),
            0
        ));
        assert_cost!(I32Or::COST, |ctx| I32Or::eval(
            ctx,
            dummy_i32(),
            dummy_i32()
        ));
        assert_cost!(I32Or::COST_CONST, |ctx| I32Or::eval_const(
            ctx,
            dummy_i32(),
            0
        ));
        assert_cost!(I32Xor::COST, |ctx| I32Xor::eval(
            ctx,
            dummy_i32(),
            dummy_i32()
        ));
        assert_cost!(I64And::COST, |ctx| I64And::eval(
            ctx,
            dummy_i64(),
            dummy_i64()
        ));
        assert_cost!(I64And::COST_CONST, |ctx| I64And::eval_const(
            ctx,
            dummy_i64(),
            0
        ));
        assert_cost!(I64Or::COST, |ctx| I64Or::eval(
            ctx,
            dummy_i64(),
            dummy_i64()
        ));
        assert_cost!(I64Or::COST_CONST, |ctx| I64Or::eval_const(
            ctx,
            dummy_i64(),
            0
        ));
        assert_cost!(I64Xor::COST, |ctx| I64Xor::eval(
            ctx,
            dummy_i64(),
            dummy_i64()
        ));
    }
}
