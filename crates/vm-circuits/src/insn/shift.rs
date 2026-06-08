use mpz_vm_memory::{I32, I64};

use super::CircuitContext;

pub struct I32Shl;

impl I32Shl {
    pub const COST: usize = 160;
    pub const COST_CONST_AMOUNT: usize = 0;

    pub fn eval<C: CircuitContext>(ctx: &mut C, value: I32, amount: I32) -> I32 {
        I32::from(crate::shl_n::<C, 32>(
            ctx,
            value.to_wires(),
            amount.to_wires(),
        ))
    }

    pub fn eval_const_amount<C: CircuitContext>(ctx: &mut C, value: I32, amount: i32) -> I32 {
        let z = crate::zero(ctx);
        I32::from(crate::shift_left_const(
            value.to_wires(),
            (amount as u32 % 32) as usize,
            z,
        ))
    }
}

pub struct I32ShrS;

impl I32ShrS {
    pub const COST: usize = 160;
    pub const COST_CONST_AMOUNT: usize = 0;

    pub fn eval<C: CircuitContext>(ctx: &mut C, value: I32, amount: I32) -> I32 {
        I32::from(crate::shr_s_n::<C, 32>(
            ctx,
            value.to_wires(),
            amount.to_wires(),
        ))
    }

    pub fn eval_const_amount(value: I32, amount: i32) -> I32 {
        let w = value.to_wires();
        let sign = w[31];
        I32::from(crate::shift_right_const(
            w,
            (amount as u32 % 32) as usize,
            sign,
        ))
    }
}

pub struct I32ShrU;

impl I32ShrU {
    pub const COST: usize = 160;
    pub const COST_CONST_AMOUNT: usize = 0;

    pub fn eval<C: CircuitContext>(ctx: &mut C, value: I32, amount: I32) -> I32 {
        I32::from(crate::shr_u_n::<C, 32>(
            ctx,
            value.to_wires(),
            amount.to_wires(),
        ))
    }

    pub fn eval_const_amount<C: CircuitContext>(ctx: &mut C, value: I32, amount: i32) -> I32 {
        let z = crate::zero(ctx);
        I32::from(crate::shift_right_const(
            value.to_wires(),
            (amount as u32 % 32) as usize,
            z,
        ))
    }
}

pub struct I32Rotl;

impl I32Rotl {
    pub const COST: usize = 160;
    pub const COST_CONST_AMOUNT: usize = 0;

    pub fn eval<C: CircuitContext>(ctx: &mut C, value: I32, amount: I32) -> I32 {
        I32::from(crate::rotl_n::<C, 32>(
            ctx,
            value.to_wires(),
            amount.to_wires(),
        ))
    }

    pub fn eval_const_amount(value: I32, amount: i32) -> I32 {
        I32::from(crate::rotate_left_const(
            value.to_wires(),
            (amount as u32 % 32) as usize,
        ))
    }
}

pub struct I32Rotr;

impl I32Rotr {
    pub const COST: usize = 160;
    pub const COST_CONST_AMOUNT: usize = 0;

    pub fn eval<C: CircuitContext>(ctx: &mut C, value: I32, amount: I32) -> I32 {
        I32::from(crate::rotr_n::<C, 32>(
            ctx,
            value.to_wires(),
            amount.to_wires(),
        ))
    }

    pub fn eval_const_amount(value: I32, amount: i32) -> I32 {
        I32::from(crate::rotate_right_const(
            value.to_wires(),
            (amount as u32 % 32) as usize,
        ))
    }
}

pub struct I64Shl;

impl I64Shl {
    pub const COST: usize = 384;
    pub const COST_CONST_AMOUNT: usize = 0;

    pub fn eval<C: CircuitContext>(ctx: &mut C, value: I64, amount: I64) -> I64 {
        I64::from(crate::shl_n::<C, 64>(
            ctx,
            value.to_wires(),
            amount.to_wires(),
        ))
    }

    pub fn eval_const_amount<C: CircuitContext>(ctx: &mut C, value: I64, amount: i64) -> I64 {
        let z = crate::zero(ctx);
        I64::from(crate::shift_left_const(
            value.to_wires(),
            (amount as u32 % 64) as usize,
            z,
        ))
    }
}

pub struct I64ShrS;

impl I64ShrS {
    pub const COST: usize = 384;
    pub const COST_CONST_AMOUNT: usize = 0;

    pub fn eval<C: CircuitContext>(ctx: &mut C, value: I64, amount: I64) -> I64 {
        I64::from(crate::shr_s_n::<C, 64>(
            ctx,
            value.to_wires(),
            amount.to_wires(),
        ))
    }

    pub fn eval_const_amount(value: I64, amount: i64) -> I64 {
        let w = value.to_wires();
        let sign = w[63];
        I64::from(crate::shift_right_const(
            w,
            (amount as u32 % 64) as usize,
            sign,
        ))
    }
}

pub struct I64ShrU;

impl I64ShrU {
    pub const COST: usize = 384;
    pub const COST_CONST_AMOUNT: usize = 0;

    pub fn eval<C: CircuitContext>(ctx: &mut C, value: I64, amount: I64) -> I64 {
        I64::from(crate::shr_u_n::<C, 64>(
            ctx,
            value.to_wires(),
            amount.to_wires(),
        ))
    }

    pub fn eval_const_amount<C: CircuitContext>(ctx: &mut C, value: I64, amount: i64) -> I64 {
        let z = crate::zero(ctx);
        I64::from(crate::shift_right_const(
            value.to_wires(),
            (amount as u32 % 64) as usize,
            z,
        ))
    }
}

pub struct I64Rotl;

impl I64Rotl {
    pub const COST: usize = 384;
    pub const COST_CONST_AMOUNT: usize = 0;

    pub fn eval<C: CircuitContext>(ctx: &mut C, value: I64, amount: I64) -> I64 {
        I64::from(crate::rotl_n::<C, 64>(
            ctx,
            value.to_wires(),
            amount.to_wires(),
        ))
    }

    pub fn eval_const_amount(value: I64, amount: i64) -> I64 {
        I64::from(crate::rotate_left_const(
            value.to_wires(),
            (amount as u32 % 64) as usize,
        ))
    }
}

pub struct I64Rotr;

impl I64Rotr {
    pub const COST: usize = 384;
    pub const COST_CONST_AMOUNT: usize = 0;

    pub fn eval<C: CircuitContext>(ctx: &mut C, value: I64, amount: I64) -> I64 {
        I64::from(crate::rotr_n::<C, 64>(
            ctx,
            value.to_wires(),
            amount.to_wires(),
        ))
    }

    pub fn eval_const_amount(value: I64, amount: i64) -> I64 {
        I64::from(crate::rotate_right_const(
            value.to_wires(),
            (amount as u32 % 64) as usize,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::insn::{dummy_i32, dummy_i64};

    #[test]
    fn costs_match_gate_counts() {
        assert_cost!(I32Shl::COST, |ctx| I32Shl::eval(
            ctx,
            dummy_i32(),
            dummy_i32()
        ));
        assert_cost!(I32Shl::COST_CONST_AMOUNT, |ctx| I32Shl::eval_const_amount(
            ctx,
            dummy_i32(),
            0
        ));
        assert_cost!(I32ShrS::COST, |ctx| I32ShrS::eval(
            ctx,
            dummy_i32(),
            dummy_i32()
        ));
        assert_cost!(I32ShrS::COST_CONST_AMOUNT, |_ctx| {
            I32ShrS::eval_const_amount(dummy_i32(), 0)
        });
        assert_cost!(I32ShrU::COST, |ctx| I32ShrU::eval(
            ctx,
            dummy_i32(),
            dummy_i32()
        ));
        assert_cost!(
            I32ShrU::COST_CONST_AMOUNT,
            |ctx| I32ShrU::eval_const_amount(ctx, dummy_i32(), 0)
        );
        assert_cost!(I32Rotl::COST, |ctx| I32Rotl::eval(
            ctx,
            dummy_i32(),
            dummy_i32()
        ));
        assert_cost!(I32Rotl::COST_CONST_AMOUNT, |_ctx| {
            I32Rotl::eval_const_amount(dummy_i32(), 0)
        });
        assert_cost!(I32Rotr::COST, |ctx| I32Rotr::eval(
            ctx,
            dummy_i32(),
            dummy_i32()
        ));
        assert_cost!(I32Rotr::COST_CONST_AMOUNT, |_ctx| {
            I32Rotr::eval_const_amount(dummy_i32(), 0)
        });
        assert_cost!(I64Shl::COST, |ctx| I64Shl::eval(
            ctx,
            dummy_i64(),
            dummy_i64()
        ));
        assert_cost!(I64Shl::COST_CONST_AMOUNT, |ctx| I64Shl::eval_const_amount(
            ctx,
            dummy_i64(),
            0
        ));
        assert_cost!(I64ShrS::COST, |ctx| I64ShrS::eval(
            ctx,
            dummy_i64(),
            dummy_i64()
        ));
        assert_cost!(I64ShrS::COST_CONST_AMOUNT, |_ctx| {
            I64ShrS::eval_const_amount(dummy_i64(), 0)
        });
        assert_cost!(I64ShrU::COST, |ctx| I64ShrU::eval(
            ctx,
            dummy_i64(),
            dummy_i64()
        ));
        assert_cost!(
            I64ShrU::COST_CONST_AMOUNT,
            |ctx| I64ShrU::eval_const_amount(ctx, dummy_i64(), 0)
        );
        assert_cost!(I64Rotl::COST, |ctx| I64Rotl::eval(
            ctx,
            dummy_i64(),
            dummy_i64()
        ));
        assert_cost!(I64Rotl::COST_CONST_AMOUNT, |_ctx| {
            I64Rotl::eval_const_amount(dummy_i64(), 0)
        });
        assert_cost!(I64Rotr::COST, |ctx| I64Rotr::eval(
            ctx,
            dummy_i64(),
            dummy_i64()
        ));
        assert_cost!(I64Rotr::COST_CONST_AMOUNT, |_ctx| {
            I64Rotr::eval_const_amount(dummy_i64(), 0)
        });
    }
}
