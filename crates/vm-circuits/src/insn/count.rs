use mpz_memory_core_new::{I32, I64};

use super::CircuitContext;

pub struct I32Clz;

impl I32Clz {
    pub const COST: usize = 1088;
    /// Advice bits the caller commits as the witness.
    pub const ADVICE: usize = 32;
    /// Verifying AND gates plus the committed advice.
    pub const COST_WITH_ADVICE: usize = 119 + Self::ADVICE;

    pub fn advice_values(a: u32) -> u32 {
        crate::clz_advice_values(a as u64, 32) as u32
    }

    pub fn eval<C: CircuitContext>(ctx: &mut C, a: I32) -> I32 {
        I32::from(crate::clz_n::<C, 32>(ctx, a.to_wires()))
    }

    pub fn eval_with_advice<C: CircuitContext>(
        ctx: &mut C,
        a: I32,
        advice: I32,
    ) -> Result<I32, C::Error> {
        let out = crate::clz_advice_n::<C, 32>(ctx, a.to_wires(), advice.to_wires())?;
        Ok(I32::from(out))
    }
}

pub struct I32Ctz;

impl I32Ctz {
    pub const COST: usize = 1088;
    /// Advice bits the caller commits as the witness.
    pub const ADVICE: usize = 32;
    /// Verifying AND gates plus the committed advice.
    pub const COST_WITH_ADVICE: usize = 119 + Self::ADVICE;

    pub fn advice_values(a: u32) -> u32 {
        crate::ctz_advice_values(a as u64, 32) as u32
    }

    pub fn eval<C: CircuitContext>(ctx: &mut C, a: I32) -> I32 {
        I32::from(crate::ctz_n::<C, 32>(ctx, a.to_wires()))
    }

    pub fn eval_with_advice<C: CircuitContext>(
        ctx: &mut C,
        a: I32,
        advice: I32,
    ) -> Result<I32, C::Error> {
        let out = crate::ctz_advice_n::<C, 32>(ctx, a.to_wires(), advice.to_wires())?;
        Ok(I32::from(out))
    }
}

pub struct I32Popcnt;

impl I32Popcnt {
    pub const COST: usize = 88;

    pub fn eval<C: CircuitContext>(ctx: &mut C, a: I32) -> I32 {
        I32::from(crate::popcnt_tree_n::<C, 32>(ctx, a.to_wires()))
    }
}

pub struct I64Clz;

impl I64Clz {
    pub const COST: usize = 4224;
    /// Advice bits the caller commits as the witness.
    pub const ADVICE: usize = 64;
    /// Verifying AND gates plus the committed advice.
    pub const COST_WITH_ADVICE: usize = 246 + Self::ADVICE;

    pub fn advice_values(a: u64) -> u64 {
        crate::clz_advice_values(a, 64)
    }

    pub fn eval<C: CircuitContext>(ctx: &mut C, a: I64) -> I64 {
        I64::from(crate::clz_n::<C, 64>(ctx, a.to_wires()))
    }

    pub fn eval_with_advice<C: CircuitContext>(
        ctx: &mut C,
        a: I64,
        advice: I64,
    ) -> Result<I64, C::Error> {
        let out = crate::clz_advice_n::<C, 64>(ctx, a.to_wires(), advice.to_wires())?;
        Ok(I64::from(out))
    }
}

pub struct I64Ctz;

impl I64Ctz {
    pub const COST: usize = 4224;
    /// Advice bits the caller commits as the witness.
    pub const ADVICE: usize = 64;
    /// Verifying AND gates plus the committed advice.
    pub const COST_WITH_ADVICE: usize = 246 + Self::ADVICE;

    pub fn advice_values(a: u64) -> u64 {
        crate::ctz_advice_values(a, 64)
    }

    pub fn eval<C: CircuitContext>(ctx: &mut C, a: I64) -> I64 {
        I64::from(crate::ctz_n::<C, 64>(ctx, a.to_wires()))
    }

    pub fn eval_with_advice<C: CircuitContext>(
        ctx: &mut C,
        a: I64,
        advice: I64,
    ) -> Result<I64, C::Error> {
        let out = crate::ctz_advice_n::<C, 64>(ctx, a.to_wires(), advice.to_wires())?;
        Ok(I64::from(out))
    }
}

pub struct I64Popcnt;

impl I64Popcnt {
    pub const COST: usize = 183;

    pub fn eval<C: CircuitContext>(ctx: &mut C, a: I64) -> I64 {
        I64::from(crate::popcnt_tree_n::<C, 64>(ctx, a.to_wires()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::insn::{dummy_i32, dummy_i64};

    #[test]
    fn costs_match_gate_counts() {
        assert_cost!(I32Clz::COST, |ctx| I32Clz::eval(ctx, dummy_i32()));
        assert_cost!(I32Clz::COST_WITH_ADVICE - I32Clz::ADVICE, |ctx| I32Clz::eval_with_advice(
            ctx,
            dummy_i32(),
            dummy_i32()
        ));
        assert_cost!(I32Ctz::COST, |ctx| I32Ctz::eval(ctx, dummy_i32()));
        assert_cost!(I32Ctz::COST_WITH_ADVICE - I32Ctz::ADVICE, |ctx| I32Ctz::eval_with_advice(
            ctx,
            dummy_i32(),
            dummy_i32()
        ));
        assert_cost!(I32Popcnt::COST, |ctx| I32Popcnt::eval(ctx, dummy_i32()));
        assert_cost!(I64Clz::COST, |ctx| I64Clz::eval(ctx, dummy_i64()));
        assert_cost!(I64Clz::COST_WITH_ADVICE - I64Clz::ADVICE, |ctx| I64Clz::eval_with_advice(
            ctx,
            dummy_i64(),
            dummy_i64()
        ));
        assert_cost!(I64Ctz::COST, |ctx| I64Ctz::eval(ctx, dummy_i64()));
        assert_cost!(I64Ctz::COST_WITH_ADVICE - I64Ctz::ADVICE, |ctx| I64Ctz::eval_with_advice(
            ctx,
            dummy_i64(),
            dummy_i64()
        ));
        assert_cost!(I64Popcnt::COST, |ctx| I64Popcnt::eval(ctx, dummy_i64()));
    }
}
