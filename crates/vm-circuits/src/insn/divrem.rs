use mpz_vm_memory::{I32, I64};

use super::CircuitContext;

use super::{const_i32, const_i64};

pub struct I32DivS;

impl I32DivS {
    pub const COST: usize = 2304;
    pub const COST_CONST_DIVISOR: usize = 2304;
    /// Advice bits the caller commits as the witness.
    pub const ADVICE: usize = 64;
    /// Verifying AND gates plus the committed advice.
    pub const COST_WITH_ADVICE: usize = 2582 + Self::ADVICE;

    pub fn advice_values(dividend: i32, divisor: i32) -> (i32, i32) {
        let (q, r) =
            crate::divrem_s_advice_values(dividend as u32 as u64, divisor as u32 as u64, 32);
        (q as u32 as i32, r as u32 as i32)
    }

    pub fn eval<C: CircuitContext>(ctx: &mut C, dividend: I32, divisor: I32) -> I32 {
        let (q, _r) = crate::divrem_s_n::<C, 32>(ctx, dividend.to_wires(), divisor.to_wires());
        I32::from(q)
    }

    pub fn eval_const_divisor<C: CircuitContext>(ctx: &mut C, dividend: I32, divisor: i32) -> I32 {
        let d = const_i32(ctx, divisor);
        let (q, _r) = crate::divrem_s_n::<C, 32>(ctx, dividend.to_wires(), d.to_wires());
        I32::from(q)
    }

    pub fn eval_with_advice<C: CircuitContext>(
        ctx: &mut C,
        dividend: I32,
        divisor: I32,
        q: I32,
        r: I32,
    ) -> Result<I32, C::Error> {
        let (quot, _rem) = crate::divrem_s_advice_n::<C, 32>(
            ctx,
            dividend.to_wires(),
            divisor.to_wires(),
            q.to_wires(),
            r.to_wires(),
        )?;
        Ok(I32::from(quot))
    }
}

pub struct I32DivU;

impl I32DivU {
    pub const COST: usize = 2048;
    pub const COST_CONST_DIVISOR: usize = 2048;
    /// Advice bits the caller commits as the witness.
    pub const ADVICE: usize = 64;
    /// Verifying AND gates plus the committed advice.
    pub const COST_WITH_ADVICE: usize = 2422 + Self::ADVICE;

    pub fn advice_values(dividend: u32, divisor: u32) -> (u32, u32) {
        let (q, r) = crate::divrem_u_advice_values(dividend as u64, divisor as u64, 32);
        (q as u32, r as u32)
    }

    pub fn eval<C: CircuitContext>(ctx: &mut C, dividend: I32, divisor: I32) -> I32 {
        let (q, _r) = crate::divrem_u_n::<C, 32>(ctx, dividend.to_wires(), divisor.to_wires());
        I32::from(q)
    }

    pub fn eval_const_divisor<C: CircuitContext>(ctx: &mut C, dividend: I32, divisor: i32) -> I32 {
        let d = const_i32(ctx, divisor);
        let (q, _r) = crate::divrem_u_n::<C, 32>(ctx, dividend.to_wires(), d.to_wires());
        I32::from(q)
    }

    pub fn eval_with_advice<C: CircuitContext>(
        ctx: &mut C,
        dividend: I32,
        divisor: I32,
        q: I32,
        r: I32,
    ) -> Result<I32, C::Error> {
        let (quot, _rem) = crate::divrem_u_advice_n::<C, 32>(
            ctx,
            dividend.to_wires(),
            divisor.to_wires(),
            q.to_wires(),
            r.to_wires(),
        )?;
        Ok(I32::from(quot))
    }
}

pub struct I32RemS;

impl I32RemS {
    pub const COST: usize = 2304;
    pub const COST_CONST_DIVISOR: usize = 2304;
    /// Advice bits the caller commits as the witness.
    pub const ADVICE: usize = 64;
    /// Verifying AND gates plus the committed advice.
    pub const COST_WITH_ADVICE: usize = 2582 + Self::ADVICE;

    pub fn advice_values(dividend: i32, divisor: i32) -> (i32, i32) {
        let (q, r) =
            crate::divrem_s_advice_values(dividend as u32 as u64, divisor as u32 as u64, 32);
        (q as u32 as i32, r as u32 as i32)
    }

    pub fn eval<C: CircuitContext>(ctx: &mut C, dividend: I32, divisor: I32) -> I32 {
        let (_q, r) = crate::divrem_s_n::<C, 32>(ctx, dividend.to_wires(), divisor.to_wires());
        I32::from(r)
    }

    pub fn eval_const_divisor<C: CircuitContext>(ctx: &mut C, dividend: I32, divisor: i32) -> I32 {
        let d = const_i32(ctx, divisor);
        let (_q, r) = crate::divrem_s_n::<C, 32>(ctx, dividend.to_wires(), d.to_wires());
        I32::from(r)
    }

    pub fn eval_with_advice<C: CircuitContext>(
        ctx: &mut C,
        dividend: I32,
        divisor: I32,
        q: I32,
        r: I32,
    ) -> Result<I32, C::Error> {
        let (_quot, rem) = crate::divrem_s_advice_n::<C, 32>(
            ctx,
            dividend.to_wires(),
            divisor.to_wires(),
            q.to_wires(),
            r.to_wires(),
        )?;
        Ok(I32::from(rem))
    }
}

pub struct I32RemU;

impl I32RemU {
    pub const COST: usize = 2048;
    pub const COST_CONST_DIVISOR: usize = 2048;
    /// Advice bits the caller commits as the witness.
    pub const ADVICE: usize = 64;
    /// Verifying AND gates plus the committed advice.
    pub const COST_WITH_ADVICE: usize = 2422 + Self::ADVICE;

    pub fn advice_values(dividend: u32, divisor: u32) -> (u32, u32) {
        let (q, r) = crate::divrem_u_advice_values(dividend as u64, divisor as u64, 32);
        (q as u32, r as u32)
    }

    pub fn eval<C: CircuitContext>(ctx: &mut C, dividend: I32, divisor: I32) -> I32 {
        let (_q, r) = crate::divrem_u_n::<C, 32>(ctx, dividend.to_wires(), divisor.to_wires());
        I32::from(r)
    }

    pub fn eval_const_divisor<C: CircuitContext>(ctx: &mut C, dividend: I32, divisor: i32) -> I32 {
        let d = const_i32(ctx, divisor);
        let (_q, r) = crate::divrem_u_n::<C, 32>(ctx, dividend.to_wires(), d.to_wires());
        I32::from(r)
    }

    pub fn eval_with_advice<C: CircuitContext>(
        ctx: &mut C,
        dividend: I32,
        divisor: I32,
        q: I32,
        r: I32,
    ) -> Result<I32, C::Error> {
        let (_quot, rem) = crate::divrem_u_advice_n::<C, 32>(
            ctx,
            dividend.to_wires(),
            divisor.to_wires(),
            q.to_wires(),
            r.to_wires(),
        )?;
        Ok(I32::from(rem))
    }
}

pub struct I64DivS;

impl I64DivS {
    pub const COST: usize = 8704;
    pub const COST_CONST_DIVISOR: usize = 8704;
    /// Advice bits the caller commits as the witness.
    pub const ADVICE: usize = 128;
    /// Verifying AND gates plus the committed advice.
    pub const COST_WITH_ADVICE: usize = 8117 + Self::ADVICE;

    pub fn advice_values(dividend: i64, divisor: i64) -> (i64, i64) {
        let (q, r) = crate::divrem_s_advice_values(dividend as u64, divisor as u64, 64);
        (q as i64, r as i64)
    }

    pub fn eval<C: CircuitContext>(ctx: &mut C, dividend: I64, divisor: I64) -> I64 {
        let (q, _r) = crate::divrem_s_n::<C, 64>(ctx, dividend.to_wires(), divisor.to_wires());
        I64::from(q)
    }

    pub fn eval_const_divisor<C: CircuitContext>(ctx: &mut C, dividend: I64, divisor: i64) -> I64 {
        let d = const_i64(ctx, divisor);
        let (q, _r) = crate::divrem_s_n::<C, 64>(ctx, dividend.to_wires(), d.to_wires());
        I64::from(q)
    }

    pub fn eval_with_advice<C: CircuitContext>(
        ctx: &mut C,
        dividend: I64,
        divisor: I64,
        q: I64,
        r: I64,
    ) -> Result<I64, C::Error> {
        let (quot, _rem) = crate::divrem_s_advice_n::<C, 64>(
            ctx,
            dividend.to_wires(),
            divisor.to_wires(),
            q.to_wires(),
            r.to_wires(),
        )?;
        Ok(I64::from(quot))
    }
}

pub struct I64DivU;

impl I64DivU {
    pub const COST: usize = 8192;
    pub const COST_CONST_DIVISOR: usize = 8192;
    /// Advice bits the caller commits as the witness.
    pub const ADVICE: usize = 128;
    /// Verifying AND gates plus the committed advice.
    pub const COST_WITH_ADVICE: usize = 7797 + Self::ADVICE;

    pub fn advice_values(dividend: u64, divisor: u64) -> (u64, u64) {
        crate::divrem_u_advice_values(dividend, divisor, 64)
    }

    pub fn eval<C: CircuitContext>(ctx: &mut C, dividend: I64, divisor: I64) -> I64 {
        let (q, _r) = crate::divrem_u_n::<C, 64>(ctx, dividend.to_wires(), divisor.to_wires());
        I64::from(q)
    }

    pub fn eval_const_divisor<C: CircuitContext>(ctx: &mut C, dividend: I64, divisor: i64) -> I64 {
        let d = const_i64(ctx, divisor);
        let (q, _r) = crate::divrem_u_n::<C, 64>(ctx, dividend.to_wires(), d.to_wires());
        I64::from(q)
    }

    pub fn eval_with_advice<C: CircuitContext>(
        ctx: &mut C,
        dividend: I64,
        divisor: I64,
        q: I64,
        r: I64,
    ) -> Result<I64, C::Error> {
        let (quot, _rem) = crate::divrem_u_advice_n::<C, 64>(
            ctx,
            dividend.to_wires(),
            divisor.to_wires(),
            q.to_wires(),
            r.to_wires(),
        )?;
        Ok(I64::from(quot))
    }
}

pub struct I64RemS;

impl I64RemS {
    pub const COST: usize = 8704;
    pub const COST_CONST_DIVISOR: usize = 8704;
    /// Advice bits the caller commits as the witness.
    pub const ADVICE: usize = 128;
    /// Verifying AND gates plus the committed advice.
    pub const COST_WITH_ADVICE: usize = 8117 + Self::ADVICE;

    pub fn advice_values(dividend: i64, divisor: i64) -> (i64, i64) {
        let (q, r) = crate::divrem_s_advice_values(dividend as u64, divisor as u64, 64);
        (q as i64, r as i64)
    }

    pub fn eval<C: CircuitContext>(ctx: &mut C, dividend: I64, divisor: I64) -> I64 {
        let (_q, r) = crate::divrem_s_n::<C, 64>(ctx, dividend.to_wires(), divisor.to_wires());
        I64::from(r)
    }

    pub fn eval_const_divisor<C: CircuitContext>(ctx: &mut C, dividend: I64, divisor: i64) -> I64 {
        let d = const_i64(ctx, divisor);
        let (_q, r) = crate::divrem_s_n::<C, 64>(ctx, dividend.to_wires(), d.to_wires());
        I64::from(r)
    }

    pub fn eval_with_advice<C: CircuitContext>(
        ctx: &mut C,
        dividend: I64,
        divisor: I64,
        q: I64,
        r: I64,
    ) -> Result<I64, C::Error> {
        let (_quot, rem) = crate::divrem_s_advice_n::<C, 64>(
            ctx,
            dividend.to_wires(),
            divisor.to_wires(),
            q.to_wires(),
            r.to_wires(),
        )?;
        Ok(I64::from(rem))
    }
}

pub struct I64RemU;

impl I64RemU {
    pub const COST: usize = 8192;
    pub const COST_CONST_DIVISOR: usize = 8192;
    /// Advice bits the caller commits as the witness.
    pub const ADVICE: usize = 128;
    /// Verifying AND gates plus the committed advice.
    pub const COST_WITH_ADVICE: usize = 7797 + Self::ADVICE;

    pub fn advice_values(dividend: u64, divisor: u64) -> (u64, u64) {
        crate::divrem_u_advice_values(dividend, divisor, 64)
    }

    pub fn eval<C: CircuitContext>(ctx: &mut C, dividend: I64, divisor: I64) -> I64 {
        let (_q, r) = crate::divrem_u_n::<C, 64>(ctx, dividend.to_wires(), divisor.to_wires());
        I64::from(r)
    }

    pub fn eval_const_divisor<C: CircuitContext>(ctx: &mut C, dividend: I64, divisor: i64) -> I64 {
        let d = const_i64(ctx, divisor);
        let (_q, r) = crate::divrem_u_n::<C, 64>(ctx, dividend.to_wires(), d.to_wires());
        I64::from(r)
    }

    pub fn eval_with_advice<C: CircuitContext>(
        ctx: &mut C,
        dividend: I64,
        divisor: I64,
        q: I64,
        r: I64,
    ) -> Result<I64, C::Error> {
        let (_quot, rem) = crate::divrem_u_advice_n::<C, 64>(
            ctx,
            dividend.to_wires(),
            divisor.to_wires(),
            q.to_wires(),
            r.to_wires(),
        )?;
        Ok(I64::from(rem))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::insn::{dummy_i32, dummy_i64};

    #[test]
    fn costs_match_gate_counts() {
        assert_cost!(I32DivS::COST, |ctx| I32DivS::eval(
            ctx,
            dummy_i32(),
            dummy_i32()
        ));
        assert_cost!(I32DivS::COST_CONST_DIVISOR, |ctx| {
            I32DivS::eval_const_divisor(ctx, dummy_i32(), 0)
        });
        assert_cost!(I32DivS::COST_WITH_ADVICE - I32DivS::ADVICE, |ctx| {
            I32DivS::eval_with_advice(ctx, dummy_i32(), dummy_i32(), dummy_i32(), dummy_i32())
        });
        assert_cost!(I32DivU::COST, |ctx| I32DivU::eval(
            ctx,
            dummy_i32(),
            dummy_i32()
        ));
        assert_cost!(I32DivU::COST_CONST_DIVISOR, |ctx| {
            I32DivU::eval_const_divisor(ctx, dummy_i32(), 0)
        });
        assert_cost!(I32DivU::COST_WITH_ADVICE - I32DivU::ADVICE, |ctx| {
            I32DivU::eval_with_advice(ctx, dummy_i32(), dummy_i32(), dummy_i32(), dummy_i32())
        });
        assert_cost!(I32RemS::COST, |ctx| I32RemS::eval(
            ctx,
            dummy_i32(),
            dummy_i32()
        ));
        assert_cost!(I32RemS::COST_CONST_DIVISOR, |ctx| {
            I32RemS::eval_const_divisor(ctx, dummy_i32(), 0)
        });
        assert_cost!(I32RemS::COST_WITH_ADVICE - I32RemS::ADVICE, |ctx| {
            I32RemS::eval_with_advice(ctx, dummy_i32(), dummy_i32(), dummy_i32(), dummy_i32())
        });
        assert_cost!(I32RemU::COST, |ctx| I32RemU::eval(
            ctx,
            dummy_i32(),
            dummy_i32()
        ));
        assert_cost!(I32RemU::COST_CONST_DIVISOR, |ctx| {
            I32RemU::eval_const_divisor(ctx, dummy_i32(), 0)
        });
        assert_cost!(I32RemU::COST_WITH_ADVICE - I32RemU::ADVICE, |ctx| {
            I32RemU::eval_with_advice(ctx, dummy_i32(), dummy_i32(), dummy_i32(), dummy_i32())
        });
        assert_cost!(I64DivS::COST, |ctx| I64DivS::eval(
            ctx,
            dummy_i64(),
            dummy_i64()
        ));
        assert_cost!(I64DivS::COST_CONST_DIVISOR, |ctx| {
            I64DivS::eval_const_divisor(ctx, dummy_i64(), 0)
        });
        assert_cost!(I64DivS::COST_WITH_ADVICE - I64DivS::ADVICE, |ctx| {
            I64DivS::eval_with_advice(ctx, dummy_i64(), dummy_i64(), dummy_i64(), dummy_i64())
        });
        assert_cost!(I64DivU::COST, |ctx| I64DivU::eval(
            ctx,
            dummy_i64(),
            dummy_i64()
        ));
        assert_cost!(I64DivU::COST_CONST_DIVISOR, |ctx| {
            I64DivU::eval_const_divisor(ctx, dummy_i64(), 0)
        });
        assert_cost!(I64DivU::COST_WITH_ADVICE - I64DivU::ADVICE, |ctx| {
            I64DivU::eval_with_advice(ctx, dummy_i64(), dummy_i64(), dummy_i64(), dummy_i64())
        });
        assert_cost!(I64RemS::COST, |ctx| I64RemS::eval(
            ctx,
            dummy_i64(),
            dummy_i64()
        ));
        assert_cost!(I64RemS::COST_CONST_DIVISOR, |ctx| {
            I64RemS::eval_const_divisor(ctx, dummy_i64(), 0)
        });
        assert_cost!(I64RemS::COST_WITH_ADVICE - I64RemS::ADVICE, |ctx| {
            I64RemS::eval_with_advice(ctx, dummy_i64(), dummy_i64(), dummy_i64(), dummy_i64())
        });
        assert_cost!(I64RemU::COST, |ctx| I64RemU::eval(
            ctx,
            dummy_i64(),
            dummy_i64()
        ));
        assert_cost!(I64RemU::COST_CONST_DIVISOR, |ctx| {
            I64RemU::eval_const_divisor(ctx, dummy_i64(), 0)
        });
        assert_cost!(I64RemU::COST_WITH_ADVICE - I64RemU::ADVICE, |ctx| {
            I64RemU::eval_with_advice(ctx, dummy_i64(), dummy_i64(), dummy_i64(), dummy_i64())
        });
    }
}
