//! Replay of a captured execution trace into a zero-knowledge circuit.
//!
//! Re-executes the [`Directive`](mpz_vm_core::Directive) sequence recorded
//! during evaluation, applying each directive to the
//! [`AuthState`] of authenticated values while emitting the corresponding
//! gadget operations through a [`ZkExec`] backend. This is the step that turns
//! a witnessed run into the constraints proven by the
//! [`Prover`](crate::Prover) and checked by the [`Verifier`](crate::Verifier).
//!
//! Directive registers are absolute (see [`Op`]), so replay applies them to
//! [`AuthState::regs`] directly without tracking per-frame register bases. A
//! returning frame's register range is reclaimed so a later call reuses those
//! slots, mirroring the thread's bounded register file.
//!
//! Trapping directives are replayed separately so that the committed trap
//! reason can be re-derived and constrained against its operands.

use itybity::{GetBit, Lsb0};
use mpz_circuits::Context;
use mpz_fields::{gf2::Gf2, gf2_128::Gf2_128};
use mpz_vm_core::{Directive, Op, Operand, Reg, Trap, ValType, value::Value};
use mpz_vm_ir::{BinaryOp, LoadKind, MemArg, Module, StoreKind, UnaryOp};
use rand_chacha::ChaCha12Rng;

use mpz_vm_memory::{AuthState, AuthValue, Bit, I32, I64};

use mpz_vm_circuits as circ;

use crate::{
    capture::is_import,
    error::{Result, ZkVmError, unsupported_binary, unsupported_op, unsupported_unary},
    finalize,
    host::RevealEvent,
};

// ============================================================
// Execution backend
// ============================================================

/// The prover's accumulate-pass circuit context over a segment's MAC tape.
pub(crate) type ProverCtx<'a> =
    mpz_zk_core::prover::Prover<'a, mpz_zk_core::prover::Accumulate<ChaCha12Rng>>;

/// The verifier's accumulate-pass circuit context over a segment's key tape.
pub(crate) type VerifierCtx<'a> =
    mpz_zk_core::verifier::Verifier<'a, mpz_zk_core::verifier::Accumulate<ChaCha12Rng>>;

/// The prover/verifier-side capabilities replay needs on top of a circuit
/// [`Context`]: public-bit constants and blind witness advice.
pub(crate) trait ZkExec: Context<Wire = Gf2_128, Field = Gf2> {
    fn public_bit(&mut self, value: bool) -> Gf2_128;

    /// Commits a 32-bit witness value as blind advice and returns the
    /// authenticated bundle. The prover commits the bits of `compute()`; the
    /// verifier commits blanks and never runs `compute`.
    fn advise_i32(&mut self, compute: impl FnOnce() -> u32) -> I32;

    /// 64-bit [`advise_i32`](ZkExec::advise_i32).
    fn advise_i64(&mut self, compute: impl FnOnce() -> u64) -> I64;
}

impl ZkExec for mpz_zk_core::Commit<'_> {
    fn public_bit(&mut self, value: bool) -> Gf2_128 {
        self.input_public(value)
    }

    fn advise_i32(&mut self, compute: impl FnOnce() -> u32) -> I32 {
        let v = compute();
        I32::from(core::array::from_fn(|i| self.input((v >> i) & 1 != 0)))
    }

    fn advise_i64(&mut self, compute: impl FnOnce() -> u64) -> I64 {
        let v = compute();
        I64::from(core::array::from_fn(|i| self.input((v >> i) & 1 != 0)))
    }
}

impl ZkExec for ProverCtx<'_> {
    fn public_bit(&mut self, value: bool) -> Gf2_128 {
        self.input_public(value)
    }

    fn advise_i32(&mut self, compute: impl FnOnce() -> u32) -> I32 {
        let v = compute();
        I32::from(core::array::from_fn(|i| self.input((v >> i) & 1 != 0)))
    }

    fn advise_i64(&mut self, compute: impl FnOnce() -> u64) -> I64 {
        let v = compute();
        I64::from(core::array::from_fn(|i| self.input((v >> i) & 1 != 0)))
    }
}

impl ZkExec for VerifierCtx<'_> {
    fn public_bit(&mut self, value: bool) -> Gf2_128 {
        self.input_public(value)
    }

    fn advise_i32(&mut self, _compute: impl FnOnce() -> u32) -> I32 {
        I32::from(core::array::from_fn(|_| self.input()))
    }

    fn advise_i64(&mut self, _compute: impl FnOnce() -> u64) -> I64 {
        I64::from(core::array::from_fn(|_| self.input()))
    }
}

// ============================================================
// Replay loop
// ============================================================

#[derive(Debug)]
pub(crate) struct ReplayState {
    pub(crate) output_reg: Option<Reg>,
}

impl ReplayState {
    pub(crate) fn root() -> Self {
        Self { output_reg: None }
    }
}

#[tracing::instrument(level = "trace", skip_all, fields(events = trace.len()))]
pub(crate) fn replay<C>(
    trace: &[Directive],
    reveal_actions: &[RevealEvent],
    module: &Module,
    auth: &mut AuthState,
    exec: &mut C,
    state: &mut ReplayState,
) -> Result<()>
where
    C: ZkExec,
    C::Error: core::fmt::Debug,
{
    let mut reveal_cursor = 0;
    for directive in trace.iter() {
        match directive {
            Directive::Op(op) => match op {
                Op::Copy { dst, src } => {
                    auth.regs.copy(*dst, *src);
                }
                Op::GlobalGet { dst, global_idx } => {
                    let av = auth
                        .globals
                        .get(Reg(*global_idx))
                        .cloned()
                        .ok_or(ZkVmError::GlobalAuthMissing { idx: *global_idx })?;
                    auth.regs.set(*dst, av);
                }
                Op::GlobalSet { global_idx, src } => {
                    let av = operand_value(src, auth, exec)?;
                    auth.globals.set(Reg(*global_idx), av);
                }
                Op::Binary {
                    dst,
                    op: bop,
                    lhs,
                    rhs,
                } => {
                    let av = binary_eval(exec, auth, *bop, lhs, rhs)?;
                    auth.regs.set(*dst, av);
                }
                Op::Unary { dst, op: uop, src } => {
                    let a = auth
                        .regs
                        .get(*src)
                        .cloned()
                        .ok_or(ZkVmError::RegAuthMissing { reg: *src })?;
                    let av = unary_eval(*uop, exec, a)?;
                    auth.regs.set(*dst, av);
                }
                Op::Load {
                    kind,
                    dst,
                    addr,
                    memarg,
                    concrete,
                    symbolic_mask,
                } => {
                    if kind.is_float() {
                        return Err(unsupported_op(op));
                    }
                    mem_load(auth, *dst, *kind, addr, memarg, *concrete, *symbolic_mask)?;
                }
                Op::Store {
                    kind,
                    addr,
                    val,
                    memarg,
                } => {
                    if kind.is_float() {
                        return Err(unsupported_op(op));
                    }
                    mem_store(exec, auth, *kind, addr, val, memarg)?;
                }
                _ => return Err(unsupported_op(op)),
            },
            Directive::Call {
                func_idx,
                args,
                param_base,
                ..
            } => {
                if is_import(module, *func_idx) {
                    // Imported calls carry a reveal, opened in-order: the source
                    // register/byte MACs are still live at this point in the
                    // trace.
                    let action = reveal_actions.get(reveal_cursor).ok_or_else(|| {
                        ZkVmError::Internal("reveal action missing for imported call".into())
                    })?;
                    reveal_cursor += 1;
                    apply_reveal(action, auth, exec)?;
                } else {
                    propagate_args(auth, *param_base, args);
                }
            }
            Directive::Return { dst, src, reclaim } => {
                handle_return(auth, state, *dst, *src, *reclaim);
            }
            Directive::Branch { .. } => {}
        }
    }
    Ok(())
}

// ============================================================
// Operand resolution
// ============================================================

/// Resolves an operand to its authenticated value: a symbol is cloned from the
/// register file; a public constant is materialized as public-bit MACs.
fn operand_value<C>(operand: &Operand, auth: &AuthState, exec: &mut C) -> Result<AuthValue>
where
    C: ZkExec,
{
    match operand {
        Operand::Symbol { reg, .. } => auth
            .regs
            .get(*reg)
            .cloned()
            .ok_or(ZkVmError::RegAuthMissing { reg: *reg }),
        Operand::Concrete(v) => const_auth(exec, v),
    }
}

/// Encodes a public constant as an [`AuthValue`] of public-bit MACs.
fn const_auth<C>(exec: &mut C, v: &Value) -> Result<AuthValue>
where
    C: ZkExec,
{
    let (ty, width, raw) = decode_concrete(v)?;
    let bits: Vec<Bit> = (0..width)
        .map(|i| Bit(exec.public_bit((raw >> i) & 1 != 0)))
        .collect();
    Ok(AuthValue::from_bits(ty, &bits)?)
}

fn decode_concrete(v: &Value) -> Result<(ValType, usize, u64)> {
    match v {
        Value::I32(x) => Ok((ValType::I32, 32, *x as u32 as u64)),
        Value::I64(x) => Ok((ValType::I64, 64, *x as u64)),
        _ => Err(ZkVmError::Unsupported(
            "float IT-MAC not supported in zk-vm".into(),
        )),
    }
}

/// The `i32` value of a concrete operand (used for the public-constant gadget
/// paths in [`binary_eval`]).
fn const_i32(op: &Operand) -> Result<i32> {
    match op {
        Operand::Concrete(Value::I32(x)) => Ok(*x),
        other => Err(ZkVmError::Internal(format!(
            "expected i32 constant operand, got {other:?}"
        ))),
    }
}

/// The `i64` value of a concrete operand.
fn const_i64(op: &Operand) -> Result<i64> {
    match op {
        Operand::Concrete(Value::I64(x)) => Ok(*x),
        other => Err(ZkVmError::Internal(format!(
            "expected i64 constant operand, got {other:?}"
        ))),
    }
}

/// Concrete integer value carried by a wire bundle, read from the pointer bit
/// (LSB) of each wire. Meaningful only on the prover, where it feeds the advice
/// closures that compute a gadget's witness.
fn wire_value(wires: &[Gf2_128]) -> u64 {
    let mut out = 0u64;
    for (i, w) in wires.iter().enumerate() {
        if GetBit::<Lsb0>::get_bit(w, 0) {
            out |= 1 << i;
        }
    }
    out
}

// ============================================================
// Op dispatch
// ============================================================

fn binary_eval<C>(
    exec: &mut C,
    auth: &AuthState,
    op: BinaryOp,
    lhs: &Operand,
    rhs: &Operand,
) -> Result<AuthValue>
where
    C: ZkExec,
    C::Error: core::fmt::Debug,
{
    use BinaryOp::*;
    // Both operands are resolved up front. A public-constant right operand takes
    // the cheaper constant-specialized circuit (guarded arms below); resolving
    // `b` anyway is free (public-bit MACs, no tape/gates).
    let a = operand_value(lhs, auth, exec)?;
    let b = operand_value(rhs, auth, exec)?;
    Ok(match op {
        I32Eq => circ::I32Eq::eval(exec, a.try_into_i32()?, b.try_into_i32()?).into(),
        I32Ne => circ::I32Ne::eval(exec, a.try_into_i32()?, b.try_into_i32()?).into(),
        I32LtS => circ::I32LtS::eval(exec, a.try_into_i32()?, b.try_into_i32()?).into(),
        I32LtU => circ::I32LtU::eval(exec, a.try_into_i32()?, b.try_into_i32()?).into(),
        I32GtS => circ::I32GtS::eval(exec, a.try_into_i32()?, b.try_into_i32()?).into(),
        I32GtU => circ::I32GtU::eval(exec, a.try_into_i32()?, b.try_into_i32()?).into(),
        I32LeS => circ::I32LeS::eval(exec, a.try_into_i32()?, b.try_into_i32()?).into(),
        I32LeU => circ::I32LeU::eval(exec, a.try_into_i32()?, b.try_into_i32()?).into(),
        I32GeS => circ::I32GeS::eval(exec, a.try_into_i32()?, b.try_into_i32()?).into(),
        I32GeU => circ::I32GeU::eval(exec, a.try_into_i32()?, b.try_into_i32()?).into(),
        I64Eq => circ::I64Eq::eval(exec, a.try_into_i64()?, b.try_into_i64()?).into(),
        I64Ne => circ::I64Ne::eval(exec, a.try_into_i64()?, b.try_into_i64()?).into(),
        I64LtS => circ::I64LtS::eval(exec, a.try_into_i64()?, b.try_into_i64()?).into(),
        I64LtU => circ::I64LtU::eval(exec, a.try_into_i64()?, b.try_into_i64()?).into(),
        I64GtS => circ::I64GtS::eval(exec, a.try_into_i64()?, b.try_into_i64()?).into(),
        I64GtU => circ::I64GtU::eval(exec, a.try_into_i64()?, b.try_into_i64()?).into(),
        I64LeS => circ::I64LeS::eval(exec, a.try_into_i64()?, b.try_into_i64()?).into(),
        I64LeU => circ::I64LeU::eval(exec, a.try_into_i64()?, b.try_into_i64()?).into(),
        I64GeS => circ::I64GeS::eval(exec, a.try_into_i64()?, b.try_into_i64()?).into(),
        I64GeU => circ::I64GeU::eval(exec, a.try_into_i64()?, b.try_into_i64()?).into(),
        I32Add => circ::I32Add::eval(exec, a.try_into_i32()?, b.try_into_i32()?).into(),
        I32Sub => circ::I32Sub::eval(exec, a.try_into_i32()?, b.try_into_i32()?).into(),
        I32Mul if rhs.is_concrete() => {
            circ::I32Mul::eval_const(exec, a.try_into_i32()?, const_i32(rhs)?).into()
        }
        I32Mul => circ::I32Mul::eval(exec, a.try_into_i32()?, b.try_into_i32()?).into(),
        I32And if rhs.is_concrete() => {
            circ::I32And::eval_const(exec, a.try_into_i32()?, const_i32(rhs)?).into()
        }
        I32And => circ::I32And::eval(exec, a.try_into_i32()?, b.try_into_i32()?).into(),
        I32Or if rhs.is_concrete() => {
            circ::I32Or::eval_const(exec, a.try_into_i32()?, const_i32(rhs)?).into()
        }
        I32Or => circ::I32Or::eval(exec, a.try_into_i32()?, b.try_into_i32()?).into(),
        I32Xor => circ::I32Xor::eval(exec, a.try_into_i32()?, b.try_into_i32()?).into(),
        I32Shl if rhs.is_concrete() => {
            circ::I32Shl::eval_const_amount(exec, a.try_into_i32()?, const_i32(rhs)?).into()
        }
        I32Shl => circ::I32Shl::eval(exec, a.try_into_i32()?, b.try_into_i32()?).into(),
        I32ShrS if rhs.is_concrete() => {
            circ::I32ShrS::eval_const_amount(a.try_into_i32()?, const_i32(rhs)?).into()
        }
        I32ShrS => circ::I32ShrS::eval(exec, a.try_into_i32()?, b.try_into_i32()?).into(),
        I32ShrU if rhs.is_concrete() => {
            circ::I32ShrU::eval_const_amount(exec, a.try_into_i32()?, const_i32(rhs)?).into()
        }
        I32ShrU => circ::I32ShrU::eval(exec, a.try_into_i32()?, b.try_into_i32()?).into(),
        I32Rotl if rhs.is_concrete() => {
            circ::I32Rotl::eval_const_amount(a.try_into_i32()?, const_i32(rhs)?).into()
        }
        I32Rotl => circ::I32Rotl::eval(exec, a.try_into_i32()?, b.try_into_i32()?).into(),
        I32Rotr if rhs.is_concrete() => {
            circ::I32Rotr::eval_const_amount(a.try_into_i32()?, const_i32(rhs)?).into()
        }
        I32Rotr => circ::I32Rotr::eval(exec, a.try_into_i32()?, b.try_into_i32()?).into(),
        I32DivU if rhs.is_concrete() => {
            circ::I32DivU::eval_const_divisor(exec, a.try_into_i32()?, const_i32(rhs)?).into()
        }
        I32DivU => div_rem_i32(exec, a.try_into_i32()?, b.try_into_i32()?, I32DivU)?,
        I32RemU if rhs.is_concrete() => {
            circ::I32RemU::eval_const_divisor(exec, a.try_into_i32()?, const_i32(rhs)?).into()
        }
        I32RemU => div_rem_i32(exec, a.try_into_i32()?, b.try_into_i32()?, I32RemU)?,
        I32DivS if rhs.is_concrete() => {
            circ::I32DivS::eval_const_divisor(exec, a.try_into_i32()?, const_i32(rhs)?).into()
        }
        I32DivS => div_rem_i32(exec, a.try_into_i32()?, b.try_into_i32()?, I32DivS)?,
        I32RemS if rhs.is_concrete() => {
            circ::I32RemS::eval_const_divisor(exec, a.try_into_i32()?, const_i32(rhs)?).into()
        }
        I32RemS => div_rem_i32(exec, a.try_into_i32()?, b.try_into_i32()?, I32RemS)?,
        I64Add => circ::I64Add::eval(exec, a.try_into_i64()?, b.try_into_i64()?).into(),
        I64Sub => circ::I64Sub::eval(exec, a.try_into_i64()?, b.try_into_i64()?).into(),
        I64Mul if rhs.is_concrete() => {
            circ::I64Mul::eval_const(exec, a.try_into_i64()?, const_i64(rhs)?).into()
        }
        I64Mul => circ::I64Mul::eval(exec, a.try_into_i64()?, b.try_into_i64()?).into(),
        I64And if rhs.is_concrete() => {
            circ::I64And::eval_const(exec, a.try_into_i64()?, const_i64(rhs)?).into()
        }
        I64And => circ::I64And::eval(exec, a.try_into_i64()?, b.try_into_i64()?).into(),
        I64Or if rhs.is_concrete() => {
            circ::I64Or::eval_const(exec, a.try_into_i64()?, const_i64(rhs)?).into()
        }
        I64Or => circ::I64Or::eval(exec, a.try_into_i64()?, b.try_into_i64()?).into(),
        I64Xor => circ::I64Xor::eval(exec, a.try_into_i64()?, b.try_into_i64()?).into(),
        I64Shl if rhs.is_concrete() => {
            circ::I64Shl::eval_const_amount(exec, a.try_into_i64()?, const_i64(rhs)?).into()
        }
        I64Shl => circ::I64Shl::eval(exec, a.try_into_i64()?, b.try_into_i64()?).into(),
        I64ShrS if rhs.is_concrete() => {
            circ::I64ShrS::eval_const_amount(a.try_into_i64()?, const_i64(rhs)?).into()
        }
        I64ShrS => circ::I64ShrS::eval(exec, a.try_into_i64()?, b.try_into_i64()?).into(),
        I64ShrU if rhs.is_concrete() => {
            circ::I64ShrU::eval_const_amount(exec, a.try_into_i64()?, const_i64(rhs)?).into()
        }
        I64ShrU => circ::I64ShrU::eval(exec, a.try_into_i64()?, b.try_into_i64()?).into(),
        I64Rotl if rhs.is_concrete() => {
            circ::I64Rotl::eval_const_amount(a.try_into_i64()?, const_i64(rhs)?).into()
        }
        I64Rotl => circ::I64Rotl::eval(exec, a.try_into_i64()?, b.try_into_i64()?).into(),
        I64Rotr if rhs.is_concrete() => {
            circ::I64Rotr::eval_const_amount(a.try_into_i64()?, const_i64(rhs)?).into()
        }
        I64Rotr => circ::I64Rotr::eval(exec, a.try_into_i64()?, b.try_into_i64()?).into(),
        I64DivU if rhs.is_concrete() => {
            circ::I64DivU::eval_const_divisor(exec, a.try_into_i64()?, const_i64(rhs)?).into()
        }
        I64DivU => div_rem_i64(exec, a.try_into_i64()?, b.try_into_i64()?, I64DivU)?,
        I64RemU if rhs.is_concrete() => {
            circ::I64RemU::eval_const_divisor(exec, a.try_into_i64()?, const_i64(rhs)?).into()
        }
        I64RemU => div_rem_i64(exec, a.try_into_i64()?, b.try_into_i64()?, I64RemU)?,
        I64DivS if rhs.is_concrete() => {
            circ::I64DivS::eval_const_divisor(exec, a.try_into_i64()?, const_i64(rhs)?).into()
        }
        I64DivS => div_rem_i64(exec, a.try_into_i64()?, b.try_into_i64()?, I64DivS)?,
        I64RemS if rhs.is_concrete() => {
            circ::I64RemS::eval_const_divisor(exec, a.try_into_i64()?, const_i64(rhs)?).into()
        }
        I64RemS => div_rem_i64(exec, a.try_into_i64()?, b.try_into_i64()?, I64RemS)?,
        _ => return unsupported_binary(op),
    })
}

/// Commits the `(q, r)` advice for a 32-bit division/remainder and emits the
/// verifying circuit. The quotient/remainder are computed by the gadget on the
/// prover and committed as blind advice; the verifier commits blanks.
fn div_rem_i32<C>(exec: &mut C, a: I32, b: I32, op: BinaryOp) -> Result<AuthValue>
where
    C: ZkExec,
    C::Error: core::fmt::Debug,
{
    use BinaryOp::*;
    let dividend = wire_value(&a.to_wires()) as u32;
    let divisor = wire_value(&b.to_wires()) as u32;
    let signed = matches!(op, I32DivS | I32RemS);
    let advice = || {
        if signed {
            let (q, r) = circ::I32DivS::advice_values(dividend as i32, divisor as i32);
            (q as u32, r as u32)
        } else {
            circ::I32DivU::advice_values(dividend, divisor)
        }
    };
    let q = exec.advise_i32(|| advice().0);
    let r = exec.advise_i32(|| advice().1);
    let out = match op {
        I32DivU => circ::I32DivU::eval_with_advice(exec, a, b, q, r),
        I32RemU => circ::I32RemU::eval_with_advice(exec, a, b, q, r),
        I32DivS => circ::I32DivS::eval_with_advice(exec, a, b, q, r),
        I32RemS => circ::I32RemS::eval_with_advice(exec, a, b, q, r),
        other => return Err(ZkVmError::Internal(format!("div_rem_i32 on {other:?}"))),
    }
    .map_err(|e| ZkVmError::Internal(format!("div/rem assert: {e:?}")))?;
    Ok(out.into())
}

/// 64-bit counterpart of [`div_rem_i32`].
fn div_rem_i64<C>(exec: &mut C, a: I64, b: I64, op: BinaryOp) -> Result<AuthValue>
where
    C: ZkExec,
    C::Error: core::fmt::Debug,
{
    use BinaryOp::*;
    let dividend = wire_value(&a.to_wires());
    let divisor = wire_value(&b.to_wires());
    let signed = matches!(op, I64DivS | I64RemS);
    let advice = || {
        if signed {
            let (q, r) = circ::I64DivS::advice_values(dividend as i64, divisor as i64);
            (q as u64, r as u64)
        } else {
            circ::I64DivU::advice_values(dividend, divisor)
        }
    };
    let q = exec.advise_i64(|| advice().0);
    let r = exec.advise_i64(|| advice().1);
    let out = match op {
        I64DivU => circ::I64DivU::eval_with_advice(exec, a, b, q, r),
        I64RemU => circ::I64RemU::eval_with_advice(exec, a, b, q, r),
        I64DivS => circ::I64DivS::eval_with_advice(exec, a, b, q, r),
        I64RemS => circ::I64RemS::eval_with_advice(exec, a, b, q, r),
        other => return Err(ZkVmError::Internal(format!("div_rem_i64 on {other:?}"))),
    }
    .map_err(|e| ZkVmError::Internal(format!("div/rem assert: {e:?}")))?;
    Ok(out.into())
}

/// Commits the count-leading/trailing-zeros advice and emits the verifying
/// circuit for a 32-bit value.
fn count_i32<C>(exec: &mut C, a: I32, clz: bool) -> Result<AuthValue>
where
    C: ZkExec,
    C::Error: core::fmt::Debug,
{
    let val = wire_value(&a.to_wires()) as u32;
    let advice = exec.advise_i32(|| {
        if clz {
            circ::I32Clz::advice_values(val)
        } else {
            circ::I32Ctz::advice_values(val)
        }
    });
    let out = if clz {
        circ::I32Clz::eval_with_advice(exec, a, advice)
    } else {
        circ::I32Ctz::eval_with_advice(exec, a, advice)
    }
    .map_err(|e| ZkVmError::Internal(format!("count assert: {e:?}")))?;
    Ok(out.into())
}

/// 64-bit counterpart of [`count_i32`].
fn count_i64<C>(exec: &mut C, a: I64, clz: bool) -> Result<AuthValue>
where
    C: ZkExec,
    C::Error: core::fmt::Debug,
{
    let val = wire_value(&a.to_wires());
    let advice = exec.advise_i64(|| {
        if clz {
            circ::I64Clz::advice_values(val)
        } else {
            circ::I64Ctz::advice_values(val)
        }
    });
    let out = if clz {
        circ::I64Clz::eval_with_advice(exec, a, advice)
    } else {
        circ::I64Ctz::eval_with_advice(exec, a, advice)
    }
    .map_err(|e| ZkVmError::Internal(format!("count assert: {e:?}")))?;
    Ok(out.into())
}

fn unary_eval<C>(op: UnaryOp, exec: &mut C, a: AuthValue) -> Result<AuthValue>
where
    C: ZkExec,
    C::Error: core::fmt::Debug,
{
    use UnaryOp::*;
    Ok(match op {
        I32Eqz => circ::I32Eqz::eval(exec, a.try_into_i32()?).into(),
        I64Eqz => circ::I64Eqz::eval(exec, a.try_into_i64()?).into(),
        I32Clz => count_i32(exec, a.try_into_i32()?, true)?,
        I32Ctz => count_i32(exec, a.try_into_i32()?, false)?,
        I32Popcnt => circ::I32Popcnt::eval(exec, a.try_into_i32()?).into(),
        I64Clz => count_i64(exec, a.try_into_i64()?, true)?,
        I64Ctz => count_i64(exec, a.try_into_i64()?, false)?,
        I64Popcnt => circ::I64Popcnt::eval(exec, a.try_into_i64()?).into(),
        I32WrapI64 => circ::I32WrapI64::eval(exec, a.try_into_i64()?).into(),
        I64ExtendI32S => circ::I64ExtendI32S::eval(exec, a.try_into_i32()?).into(),
        I64ExtendI32U => circ::I64ExtendI32U::eval(exec, a.try_into_i32()?).into(),
        I32Extend8S => circ::I32Extend8S::eval(exec, a.try_into_i32()?).into(),
        I32Extend16S => circ::I32Extend16S::eval(exec, a.try_into_i32()?).into(),
        I64Extend8S => circ::I64Extend8S::eval(exec, a.try_into_i64()?).into(),
        I64Extend16S => circ::I64Extend16S::eval(exec, a.try_into_i64()?).into(),
        I64Extend32S => circ::I64Extend32S::eval(exec, a.try_into_i64()?).into(),
        _ => return unsupported_unary(op),
    })
}

// ============================================================
// Memory
// ============================================================

/// Loads `kind` at the effective address, taking symbolic bytes from committed
/// memory and the remaining (public) bytes from `concrete` per `symbolic_mask`.
fn mem_load(
    auth: &mut AuthState,
    dst: Reg,
    kind: LoadKind,
    addr: &Operand,
    memarg: &MemArg,
    concrete: u64,
    symbolic_mask: u8,
) -> Result<()> {
    use LoadKind::*;
    let eff = crate::memlog::eff_addr(addr, memarg)?;
    let m = &auth.memory;
    let av: AuthValue = match kind {
        I32 => m
            .load_i32_mixed(eff, concrete, symbolic_mask)
            .map(Into::into),
        I64 => m
            .load_i64_mixed(eff, concrete, symbolic_mask)
            .map(Into::into),
        I32Load8U => m
            .load_i32_8u_mixed(eff, concrete, symbolic_mask)
            .map(Into::into),
        I32Load8S => m
            .load_i32_8s_mixed(eff, concrete, symbolic_mask)
            .map(Into::into),
        I32Load16U => m
            .load_i32_16u_mixed(eff, concrete, symbolic_mask)
            .map(Into::into),
        I32Load16S => m
            .load_i32_16s_mixed(eff, concrete, symbolic_mask)
            .map(Into::into),
        I64Load8U => m
            .load_i64_8u_mixed(eff, concrete, symbolic_mask)
            .map(Into::into),
        I64Load8S => m
            .load_i64_8s_mixed(eff, concrete, symbolic_mask)
            .map(Into::into),
        I64Load16U => m
            .load_i64_16u_mixed(eff, concrete, symbolic_mask)
            .map(Into::into),
        I64Load16S => m
            .load_i64_16s_mixed(eff, concrete, symbolic_mask)
            .map(Into::into),
        I64Load32U => m
            .load_i64_32u_mixed(eff, concrete, symbolic_mask)
            .map(Into::into),
        I64Load32S => m
            .load_i64_32s_mixed(eff, concrete, symbolic_mask)
            .map(Into::into),
        F32 | F64 => {
            return Err(ZkVmError::Internal(
                "zk-vm: float load not supported".into(),
            ));
        }
    }
    .ok_or(ZkVmError::MemAuthMissing { addr: eff })?;
    auth.regs.set(dst, av);
    Ok(())
}

fn mem_store<C>(
    exec: &mut C,
    auth: &mut AuthState,
    kind: StoreKind,
    addr: &Operand,
    val: &Operand,
    memarg: &MemArg,
) -> Result<()>
where
    C: ZkExec,
{
    use StoreKind::*;
    let eff = crate::memlog::eff_addr(addr, memarg)?;
    let av = operand_value(val, auth, exec)?;
    match kind {
        I32 => auth.memory.store_i32(eff, av.try_as_i32()?),
        I64 => auth.memory.store_i64(eff, av.try_as_i64()?),
        I32Store8 => auth.memory.store_i32_8(eff, av.try_as_i32()?),
        I32Store16 => auth.memory.store_i32_16(eff, av.try_as_i32()?),
        I64Store8 => auth.memory.store_i64_8(eff, av.try_as_i64()?),
        I64Store16 => auth.memory.store_i64_16(eff, av.try_as_i64()?),
        I64Store32 => auth.memory.store_i64_32(eff, av.try_as_i64()?),
        F32 | F64 => {
            return Err(ZkVmError::Internal(
                "zk-vm: float store not supported".into(),
            ));
        }
    }
    Ok(())
}

// ============================================================
// Reveals, returns, traps
// ============================================================

fn apply_reveal<C>(event: &RevealEvent, auth: &mut AuthState, exec: &mut C) -> Result<()>
where
    C: ZkExec,
    C::Error: core::fmt::Debug,
{
    match event {
        RevealEvent::OpenScalar {
            src,
            value,
            handle_dst,
            id,
        } => {
            // Open the disclosed value against the live source MAC. A `None`
            // source means the value was already public, so there is nothing to
            // open.
            if let Some(src) = src {
                finalize::assert_output(exec, auth, *src, *value)?;
            }
            // The reveal returns the public handle id.
            set_public_reg(auth, exec, *handle_dst, &Value::I32(*id as i32))?;
        }
        // The wait binds the now-public revealed value into its destination.
        RevealEvent::WaitScalar { dst, value } => {
            set_public_reg(auth, exec, *dst, value)?;
        }
        RevealEvent::OpenBytes {
            ptr,
            bytes,
            handle_dst,
            id,
        } => {
            // Open the disclosed bytes against the live byte MACs at this point
            // in the trace (before any later store could overwrite them).
            crate::reveal::assert_bytes(exec, auth, *ptr, bytes)?;
            set_public_reg(auth, exec, *handle_dst, &Value::I32(*id as i32))?;
        }
        // The byte wait's effect was applied to memory during capture.
        RevealEvent::WaitBytes => {}
    }
    Ok(())
}

fn set_public_reg<C>(auth: &mut AuthState, exec: &mut C, reg: Reg, value: &Value) -> Result<()>
where
    C: ZkExec,
{
    auth.regs.set(reg, const_auth(exec, value)?);
    Ok(())
}

fn handle_return(
    auth: &mut AuthState,
    state: &mut ReplayState,
    dst: Option<Reg>,
    src: Option<Reg>,
    reclaim: Option<(Reg, u32)>,
) {
    match (dst, src) {
        // Non-root return into a caller register: bind the result's MAC there
        // before the source range is reclaimed below.
        (Some(d), Some(s)) => auth.regs.copy(d, s),
        // Outermost return (carries `dst = None`, `reclaim = None`): record the
        // result register for finalize to open.
        (None, Some(s)) if reclaim.is_none() => state.output_reg = Some(s),
        _ => {}
    }
    if let Some((base, count)) = reclaim {
        auth.regs.drop_range(base, count);
    }
}

pub(crate) fn replay_trap<C>(
    directive: &Directive,
    reason: &Trap,
    auth: &AuthState,
    exec: &mut C,
) -> Result<()>
where
    C: ZkExec,
    C::Error: core::fmt::Debug,
{
    let (lhs, rhs, width) = trap_operands(directive)?;
    match reason {
        Trap::DivideByZero => {
            let b = operand_value(rhs, auth, exec)?;
            assert_divisor_zero(exec, &b, width)
        }
        Trap::IntegerOverflow => {
            let a = operand_value(lhs, auth, exec)?;
            let b = operand_value(rhs, auth, exec)?;
            assert_overflow(exec, &a, &b, width)
        }
        other => Err(ZkVmError::Internal(format!(
            "replay: unproven committed trap reason {other:?} for {directive:?}"
        ))),
    }
}

fn trap_operands(directive: &Directive) -> Result<(&Operand, &Operand, usize)> {
    use BinaryOp::*;
    match directive {
        Directive::Op(Op::Binary { op, lhs, rhs, .. }) => match op {
            I32DivU | I32RemU | I32DivS | I32RemS => Ok((lhs, rhs, 32)),
            I64DivU | I64RemU | I64DivS | I64RemS => Ok((lhs, rhs, 64)),
            other => Err(ZkVmError::Internal(format!(
                "replay: trap directive op is not a div/rem: {other:?}"
            ))),
        },
        other => Err(ZkVmError::Internal(format!(
            "replay: trap directive is not a binary op: {other:?}"
        ))),
    }
}

fn assert_const_bits<C>(ctx: &mut C, value: &AuthValue, width: usize, bits: u64) -> Result<()>
where
    C: Context<Wire = Gf2_128, Field = Gf2>,
    C::Error: core::fmt::Debug,
{
    let wires = match width {
        32 => value.try_as_i32()?.to_wires().to_vec(),
        64 => value.try_as_i64()?.to_wires().to_vec(),
        other => {
            return Err(ZkVmError::Internal(format!(
                "replay: unexpected trap operand width {other}"
            )));
        }
    };
    for (i, w) in wires.into_iter().enumerate() {
        ctx.assert_const(w, Gf2((bits >> i) & 1 != 0))
            .map_err(|e| ZkVmError::Internal(format!("assert_const: {e:?}")))?;
    }
    Ok(())
}

fn assert_divisor_zero<C>(ctx: &mut C, divisor: &AuthValue, width: usize) -> Result<()>
where
    C: Context<Wire = Gf2_128, Field = Gf2>,
    C::Error: core::fmt::Debug,
{
    assert_const_bits(ctx, divisor, width, 0)
}

fn assert_overflow<C>(ctx: &mut C, lhs: &AuthValue, rhs: &AuthValue, width: usize) -> Result<()>
where
    C: Context<Wire = Gf2_128, Field = Gf2>,
    C::Error: core::fmt::Debug,
{
    let all_ones = if width == 64 {
        u64::MAX
    } else {
        (1u64 << width) - 1
    };
    let int_min = 1u64 << (width - 1);
    assert_const_bits(ctx, rhs, width, all_ones)?;
    assert_const_bits(ctx, lhs, width, int_min)
}

fn propagate_args(auth: &mut AuthState, param_base: Reg, args: &[Operand]) {
    for (i, arg) in args.iter().enumerate() {
        // Call-arg operands carry absolute source registers; bind each to the
        // callee's parameter register `param_base + i`.
        if let Operand::Symbol { reg, .. } = arg {
            auth.regs.copy(param_base + i as u32, *reg);
        }
    }
}
