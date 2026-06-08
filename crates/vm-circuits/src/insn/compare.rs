use mpz_vm_memory::{I32, I64};

use super::CircuitContext;

pub struct I32Eq;

impl I32Eq {
    pub const COST: usize = 31;

    pub fn eval<C: CircuitContext>(ctx: &mut C, a: I32, b: I32) -> I32 {
        let bit = crate::eq_n::<C, 32>(ctx, a.to_wires(), b.to_wires());
        super::zero_extend_bit(ctx, bit)
    }
}

pub struct I32Ne;

impl I32Ne {
    pub const COST: usize = 31;

    pub fn eval<C: CircuitContext>(ctx: &mut C, a: I32, b: I32) -> I32 {
        let bit = crate::ne_n::<C, 32>(ctx, a.to_wires(), b.to_wires());
        super::zero_extend_bit(ctx, bit)
    }
}

pub struct I32LtS;

impl I32LtS {
    pub const COST: usize = 32;

    pub fn eval<C: CircuitContext>(ctx: &mut C, left: I32, right: I32) -> I32 {
        let bit = crate::lt_s_n::<C, 32>(ctx, left.to_wires(), right.to_wires());
        super::zero_extend_bit(ctx, bit)
    }
}

pub struct I32LtU;

impl I32LtU {
    pub const COST: usize = 32;

    pub fn eval<C: CircuitContext>(ctx: &mut C, left: I32, right: I32) -> I32 {
        let bit = crate::lt_u_n::<C, 32>(ctx, left.to_wires(), right.to_wires());
        super::zero_extend_bit(ctx, bit)
    }
}

pub struct I32GtS;

impl I32GtS {
    pub const COST: usize = 32;

    pub fn eval<C: CircuitContext>(ctx: &mut C, left: I32, right: I32) -> I32 {
        let bit = crate::lt_s_n::<C, 32>(ctx, right.to_wires(), left.to_wires());
        super::zero_extend_bit(ctx, bit)
    }
}

pub struct I32GtU;

impl I32GtU {
    pub const COST: usize = 32;

    pub fn eval<C: CircuitContext>(ctx: &mut C, left: I32, right: I32) -> I32 {
        let bit = crate::lt_u_n::<C, 32>(ctx, right.to_wires(), left.to_wires());
        super::zero_extend_bit(ctx, bit)
    }
}

pub struct I32LeS;

impl I32LeS {
    pub const COST: usize = 32;

    pub fn eval<C: CircuitContext>(ctx: &mut C, left: I32, right: I32) -> I32 {
        let gt = crate::lt_s_n::<C, 32>(ctx, right.to_wires(), left.to_wires());
        let bit = crate::not(ctx, gt);
        super::zero_extend_bit(ctx, bit)
    }
}

pub struct I32LeU;

impl I32LeU {
    pub const COST: usize = 32;

    pub fn eval<C: CircuitContext>(ctx: &mut C, left: I32, right: I32) -> I32 {
        let gt = crate::lt_u_n::<C, 32>(ctx, right.to_wires(), left.to_wires());
        let bit = crate::not(ctx, gt);
        super::zero_extend_bit(ctx, bit)
    }
}

pub struct I32GeS;

impl I32GeS {
    pub const COST: usize = 32;

    pub fn eval<C: CircuitContext>(ctx: &mut C, left: I32, right: I32) -> I32 {
        let lt = crate::lt_s_n::<C, 32>(ctx, left.to_wires(), right.to_wires());
        let bit = crate::not(ctx, lt);
        super::zero_extend_bit(ctx, bit)
    }
}

pub struct I32GeU;

impl I32GeU {
    pub const COST: usize = 32;

    pub fn eval<C: CircuitContext>(ctx: &mut C, left: I32, right: I32) -> I32 {
        let lt = crate::lt_u_n::<C, 32>(ctx, left.to_wires(), right.to_wires());
        let bit = crate::not(ctx, lt);
        super::zero_extend_bit(ctx, bit)
    }
}

pub struct I32Eqz;

impl I32Eqz {
    pub const COST: usize = 31;

    pub fn eval<C: CircuitContext>(ctx: &mut C, a: I32) -> I32 {
        let bit = crate::eqz_n::<C, 32>(ctx, a.to_wires());
        super::zero_extend_bit(ctx, bit)
    }
}

pub struct I64Eq;

impl I64Eq {
    pub const COST: usize = 63;

    pub fn eval<C: CircuitContext>(ctx: &mut C, a: I64, b: I64) -> I32 {
        let bit = crate::eq_n::<C, 64>(ctx, a.to_wires(), b.to_wires());
        super::zero_extend_bit(ctx, bit)
    }
}

pub struct I64Ne;

impl I64Ne {
    pub const COST: usize = 63;

    pub fn eval<C: CircuitContext>(ctx: &mut C, a: I64, b: I64) -> I32 {
        let bit = crate::ne_n::<C, 64>(ctx, a.to_wires(), b.to_wires());
        super::zero_extend_bit(ctx, bit)
    }
}

pub struct I64LtS;

impl I64LtS {
    pub const COST: usize = 64;

    pub fn eval<C: CircuitContext>(ctx: &mut C, left: I64, right: I64) -> I32 {
        let bit = crate::lt_s_n::<C, 64>(ctx, left.to_wires(), right.to_wires());
        super::zero_extend_bit(ctx, bit)
    }
}

pub struct I64LtU;

impl I64LtU {
    pub const COST: usize = 64;

    pub fn eval<C: CircuitContext>(ctx: &mut C, left: I64, right: I64) -> I32 {
        let bit = crate::lt_u_n::<C, 64>(ctx, left.to_wires(), right.to_wires());
        super::zero_extend_bit(ctx, bit)
    }
}

pub struct I64GtS;

impl I64GtS {
    pub const COST: usize = 64;

    pub fn eval<C: CircuitContext>(ctx: &mut C, left: I64, right: I64) -> I32 {
        let bit = crate::lt_s_n::<C, 64>(ctx, right.to_wires(), left.to_wires());
        super::zero_extend_bit(ctx, bit)
    }
}

pub struct I64GtU;

impl I64GtU {
    pub const COST: usize = 64;

    pub fn eval<C: CircuitContext>(ctx: &mut C, left: I64, right: I64) -> I32 {
        let bit = crate::lt_u_n::<C, 64>(ctx, right.to_wires(), left.to_wires());
        super::zero_extend_bit(ctx, bit)
    }
}

pub struct I64LeS;

impl I64LeS {
    pub const COST: usize = 64;

    pub fn eval<C: CircuitContext>(ctx: &mut C, left: I64, right: I64) -> I32 {
        let gt = crate::lt_s_n::<C, 64>(ctx, right.to_wires(), left.to_wires());
        let bit = crate::not(ctx, gt);
        super::zero_extend_bit(ctx, bit)
    }
}

pub struct I64LeU;

impl I64LeU {
    pub const COST: usize = 64;

    pub fn eval<C: CircuitContext>(ctx: &mut C, left: I64, right: I64) -> I32 {
        let gt = crate::lt_u_n::<C, 64>(ctx, right.to_wires(), left.to_wires());
        let bit = crate::not(ctx, gt);
        super::zero_extend_bit(ctx, bit)
    }
}

pub struct I64GeS;

impl I64GeS {
    pub const COST: usize = 64;

    pub fn eval<C: CircuitContext>(ctx: &mut C, left: I64, right: I64) -> I32 {
        let lt = crate::lt_s_n::<C, 64>(ctx, left.to_wires(), right.to_wires());
        let bit = crate::not(ctx, lt);
        super::zero_extend_bit(ctx, bit)
    }
}

pub struct I64GeU;

impl I64GeU {
    pub const COST: usize = 64;

    pub fn eval<C: CircuitContext>(ctx: &mut C, left: I64, right: I64) -> I32 {
        let lt = crate::lt_u_n::<C, 64>(ctx, left.to_wires(), right.to_wires());
        let bit = crate::not(ctx, lt);
        super::zero_extend_bit(ctx, bit)
    }
}

pub struct I64Eqz;

impl I64Eqz {
    pub const COST: usize = 63;

    pub fn eval<C: CircuitContext>(ctx: &mut C, a: I64) -> I32 {
        let bit = crate::eqz_n::<C, 64>(ctx, a.to_wires());
        super::zero_extend_bit(ctx, bit)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::insn::{dummy_i32, dummy_i64};

    #[test]
    fn costs_match_gate_counts() {
        assert_cost!(I32Eq::COST, |ctx| I32Eq::eval(
            ctx,
            dummy_i32(),
            dummy_i32()
        ));
        assert_cost!(I32Ne::COST, |ctx| I32Ne::eval(
            ctx,
            dummy_i32(),
            dummy_i32()
        ));
        assert_cost!(I32LtS::COST, |ctx| I32LtS::eval(
            ctx,
            dummy_i32(),
            dummy_i32()
        ));
        assert_cost!(I32LtU::COST, |ctx| I32LtU::eval(
            ctx,
            dummy_i32(),
            dummy_i32()
        ));
        assert_cost!(I32GtS::COST, |ctx| I32GtS::eval(
            ctx,
            dummy_i32(),
            dummy_i32()
        ));
        assert_cost!(I32GtU::COST, |ctx| I32GtU::eval(
            ctx,
            dummy_i32(),
            dummy_i32()
        ));
        assert_cost!(I32LeS::COST, |ctx| I32LeS::eval(
            ctx,
            dummy_i32(),
            dummy_i32()
        ));
        assert_cost!(I32LeU::COST, |ctx| I32LeU::eval(
            ctx,
            dummy_i32(),
            dummy_i32()
        ));
        assert_cost!(I32GeS::COST, |ctx| I32GeS::eval(
            ctx,
            dummy_i32(),
            dummy_i32()
        ));
        assert_cost!(I32GeU::COST, |ctx| I32GeU::eval(
            ctx,
            dummy_i32(),
            dummy_i32()
        ));
        assert_cost!(I32Eqz::COST, |ctx| I32Eqz::eval(ctx, dummy_i32()));
        assert_cost!(I64Eq::COST, |ctx| I64Eq::eval(
            ctx,
            dummy_i64(),
            dummy_i64()
        ));
        assert_cost!(I64Ne::COST, |ctx| I64Ne::eval(
            ctx,
            dummy_i64(),
            dummy_i64()
        ));
        assert_cost!(I64LtS::COST, |ctx| I64LtS::eval(
            ctx,
            dummy_i64(),
            dummy_i64()
        ));
        assert_cost!(I64LtU::COST, |ctx| I64LtU::eval(
            ctx,
            dummy_i64(),
            dummy_i64()
        ));
        assert_cost!(I64GtS::COST, |ctx| I64GtS::eval(
            ctx,
            dummy_i64(),
            dummy_i64()
        ));
        assert_cost!(I64GtU::COST, |ctx| I64GtU::eval(
            ctx,
            dummy_i64(),
            dummy_i64()
        ));
        assert_cost!(I64LeS::COST, |ctx| I64LeS::eval(
            ctx,
            dummy_i64(),
            dummy_i64()
        ));
        assert_cost!(I64LeU::COST, |ctx| I64LeU::eval(
            ctx,
            dummy_i64(),
            dummy_i64()
        ));
        assert_cost!(I64GeS::COST, |ctx| I64GeS::eval(
            ctx,
            dummy_i64(),
            dummy_i64()
        ));
        assert_cost!(I64GeU::COST, |ctx| I64GeU::eval(
            ctx,
            dummy_i64(),
            dummy_i64()
        ));
        assert_cost!(I64Eqz::COST, |ctx| I64Eqz::eval(ctx, dummy_i64()));
    }
}
