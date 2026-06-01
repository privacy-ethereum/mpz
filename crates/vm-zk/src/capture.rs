//! Chunked capture of a thread's execution trace.
//!
//! [`capture_chunk`] drives a [`Thread`] forward, recording each emitted
//! [`Directive`] until the chunk's gate-bit cap is reached, the thread
//! completes, or it traps. Imported calls are serviced inline, with the reveal
//! they carry recorded alongside the trace. The resulting [`ChunkCapture`]
//! carries the trace, its accumulated gate/advice cost, and the terminal
//! outcome (a return value or a [`TrapPoint`]).
//!
//! Both prover and verifier run this loop over the same program; driving them
//! with the same module and inputs yields identical directive/frame skeletons,
//! which is what lets the verifier check the prover's announced trace and trap.

use std::collections::BTreeMap;

use mpz_vm_core_new::{Directive, Global, Pending, Reg, StepResult, Thread, Trap, value::Value};
use mpz_vm_ir::{Function, Module};

use crate::{
    cost,
    error::{Result, ZkVmError},
    host::{self, RevealEvent, RevealPayload, RevealState},
};

/// Returns whether `func_idx` names an imported (host) function.
pub(crate) fn is_import(module: &Module, func_idx: u32) -> bool {
    matches!(module.function(func_idx), Some(Function::Import(_)))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Role {
    Prover,
    Verifier,
}

#[derive(Clone, Debug)]
pub(crate) struct TrapPoint {
    pub(crate) index: u64,
    pub(crate) directive: Option<Directive>,
    pub(crate) trap: Trap,
}

pub(crate) struct ChunkCapture {
    pub(crate) trace: Vec<Directive>,
    pub(crate) cost: usize,
    pub(crate) done: bool,
    pub(crate) result: Option<Value>,
    pub(crate) result_symbolic: bool,
    pub(crate) trap: Option<TrapPoint>,
    /// Reveal events, one per imported `Directive::Call` in `trace` and in the
    /// same order, that replay opens against the authenticated state.
    pub(crate) reveal_actions: Vec<RevealEvent>,
    /// Payloads newly disclosed by reveals in this chunk, to announce (prover)
    /// or already merged (verifier). Keyed by reveal id.
    pub(crate) reveals: BTreeMap<u32, RevealPayload>,
}

#[tracing::instrument(level = "trace", skip_all, fields(cap, ?role, announced_trap))]
pub(crate) fn capture_chunk(
    module: &Module,
    global: &mut Global,
    thread: &mut Thread,
    cap: Option<usize>,
    role: Role,
    announced_trap: Option<(u64, Trap)>,
    reveal_state: &mut RevealState,
) -> Result<ChunkCapture> {
    let mut trace: Vec<Directive> = Vec::new();
    let mut cost: usize = 0;
    let mut reveal_actions: Vec<RevealEvent> = Vec::new();
    let mut reveals: BTreeMap<u32, RevealPayload> = BTreeMap::new();

    loop {
        let directive = match thread.step(module, global)? {
            StepResult::Continue => continue,
            // An imported call surfaces as a `Directive::Call`. Service it now —
            // recording the reveal action and resolving the call — then push the
            // directive so replay opens it in-order. Other directives fall
            // through to cost accounting and the trace.
            StepResult::Directive(Directive::Call {
                dst,
                func_idx,
                args,
                ..
            }) if is_import(module, func_idx) => {
                let (action, value, visibility) = host::service_reveal(
                    role,
                    reveal_state,
                    &mut reveals,
                    module,
                    global,
                    func_idx,
                    dst,
                    &args,
                )?;
                reveal_actions.push(action);
                thread.resolve_host_call(value, visibility)?;
                trace.push(Directive::Call {
                    dst,
                    func_idx,
                    args,
                    param_base: Reg(0),
                });
                continue;
            }
            // A could-trap op (e.g. div/rem with an unheld operand) emits as an
            // ordinary directive. `op_counter` was bumped past the op before
            // `step` returned, so the emitted op sits at the announced index `i`
            // when `op_counter() == i + 1`. This is the trapping op: validate it
            // and end the chunk terminal — it is tape-free and never enters the
            // trace.
            StepResult::Directive(d)
                if let Some((i, reason)) = &announced_trap
                    && thread.op_counter() == *i + 1 =>
            {
                validate_trap_directive(&d, reason)?;
                return Ok(ChunkCapture {
                    trace,
                    cost,
                    done: true,
                    result: None,
                    result_symbolic: false,
                    trap: Some(TrapPoint {
                        index: *i,
                        directive: Some(d),
                        trap: reason.clone(),
                    }),
                    reveal_actions,
                    reveals,
                });
            }
            StepResult::Directive(d) => d,
            // A could-trap op resolved to a trap by the stepping driver itself
            // (the prover, or the verifier when the trap-determining operand is
            // public). The trapping directive is not pushed into the trace: it
            // is tape-free, consumes no cost, and rides on the capture for the
            // separate trap-replay pass. The chunk ends terminal with no result.
            StepResult::Trapped {
                index,
                directive,
                trap,
            } => {
                // If the prover announced a trap index, a verifier reaching the
                // trap locally must land on the same op.
                if let Some((announced, _)) = &announced_trap {
                    if *announced != index {
                        return Err(ZkVmError::Internal(format!(
                            "local trap at index {index} but prover announced {announced}"
                        )));
                    }
                }
                return Ok(ChunkCapture {
                    trace,
                    cost,
                    done: true,
                    result: None,
                    result_symbolic: false,
                    trap: Some(TrapPoint {
                        index,
                        directive,
                        trap,
                    }),
                    reveal_actions,
                    reveals,
                });
            }
            // Blocked on a condition the zk-vm does not support: private
            // branching, indirect-call dispatch, and memory.grow all need a
            // value fed back into execution. (A could-trap op no longer blocks —
            // it emits as an ordinary directive and is matched by index below.)
            StepResult::Blocked(pending) => match pending {
                Pending::Branch => {
                    return Err(ZkVmError::Unsupported(
                        "private branching not supported in zk-vm".into(),
                    ));
                }
                // Imported calls are serviced when their `Directive::Call` is
                // emitted, so the thread is never stepped while a host call is
                // unresolved here.
                Pending::HostCall { .. } => {
                    return Err(ZkVmError::Internal(
                        "host call surfaced as blocked but should be serviced at its directive"
                            .into(),
                    ));
                }
                Pending::CallIndirect { .. } => {
                    return Err(ZkVmError::Unsupported(
                        "private indirect-call dispatch not supported in zk-vm".into(),
                    ));
                }
                Pending::MemoryGrow { .. } => {
                    return Err(ZkVmError::Unsupported(
                        "private memory.grow not supported in zk-vm".into(),
                    ));
                }
            },
            StepResult::Done { result, symbolic } => {
                return Ok(ChunkCapture {
                    trace,
                    cost,
                    done: true,
                    result,
                    result_symbolic: symbolic,
                    trap: None,
                    reveal_actions,
                    reveals,
                });
            }
        };

        match &directive {
            Directive::Op(op) => {
                cost += cost::op_cost(op)?;
            }
            _ => {}
        }

        trace.push(directive);

        if let Some(c) = cap {
            if cost >= c {
                return Ok(ChunkCapture {
                    trace,
                    cost,
                    done: false,
                    result: None,
                    result_symbolic: false,
                    trap: None,
                    reveal_actions,
                    reveals,
                });
            }
        }
    }
}

fn validate_trap_directive(directive: &Directive, reason: &Trap) -> Result<()> {
    use mpz_vm_core_new::Op;
    use mpz_vm_ir::BinaryOp::*;
    let op = match directive {
        Directive::Op(Op::Binary { op, .. }) => *op,
        other => {
            return Err(ZkVmError::Internal(format!(
                "announced trap directive is not a binary op: {other:?}"
            )));
        }
    };
    let ok = match reason {
        Trap::DivideByZero => matches!(
            op,
            I32DivU | I32RemU | I32DivS | I32RemS | I64DivU | I64RemU | I64DivS | I64RemS
        ),
        Trap::IntegerOverflow => matches!(op, I32DivS | I64DivS),
        _ => false,
    };
    if ok {
        Ok(())
    } else {
        Err(ZkVmError::Internal(format!(
            "announced trap reason {reason:?} not provable for op {op:?}"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mpz_vm_core_new::{Call, Op, Param};
    use mpz_vm_ir::{ExportKind, Module, ValType};

    fn capture_trace(
        module: &Module,
        func_idx: u32,
        role: Role,
        params: Vec<Param>,
    ) -> Vec<Directive> {
        let mut global = Global::new(module).unwrap();
        let mut thread = Thread::new();
        thread
            .call(module, &mut global, Call { func_idx, params })
            .unwrap();
        let mut reveal_state = RevealState::default();
        capture_chunk(
            module,
            &mut global,
            &mut thread,
            None,
            role,
            None,
            &mut reveal_state,
        )
        .unwrap()
        .trace
    }

    fn skeleton(directive: &Directive) -> String {
        match directive {
            Directive::Op(Op::Copy { dst, src }) => format!("copy {dst} {src}"),
            Directive::Op(Op::Binary { dst, op, .. }) => format!("binary {dst} {op:?}"),
            Directive::Op(Op::GlobalGet { dst, global_idx }) => format!("gget {dst} {global_idx}"),
            Directive::Op(Op::GlobalSet { global_idx, .. }) => format!("gset {global_idx}"),
            Directive::Call {
                dst,
                func_idx,
                param_base,
                ..
            } => format!("call {dst:?} {func_idx} pb{param_base}"),
            Directive::Return { dst, src, reclaim } => format!("ret {dst:?} {src:?} {reclaim:?}"),
            other => format!("{other:?}"),
        }
    }

    #[test]
    fn prover_and_verifier_capture_identical_skeletons() {
        let wat = r#"(module
            (func $helper (param i32) (result i32)
                local.get 0 local.get 0 i32.add)
            (func $main (export "main") (param i32) (result i32)
                local.get 0 call $helper))"#;
        let module = Module::parse(&wat::parse_str(wat).unwrap()).unwrap();
        let idx = module
            .exports()
            .iter()
            .find_map(|e| match e.kind {
                ExportKind::Func(i) if e.name == "main" => Some(i),
                _ => None,
            })
            .unwrap();

        let prover = capture_trace(
            &module,
            idx,
            Role::Prover,
            vec![Param::Private(Value::I32(7))],
        );
        let verifier = capture_trace(
            &module,
            idx,
            Role::Verifier,
            vec![Param::Blind(ValType::I32)],
        );

        let ps: Vec<_> = prover.iter().map(skeleton).collect();
        let vs: Vec<_> = verifier.iter().map(skeleton).collect();
        assert_eq!(
            ps, vs,
            "prover and verifier must capture identical directive skeletons"
        );
        assert!(
            ps.iter().any(|k| k.starts_with("call")),
            "the test program must exercise a Call"
        );
    }
}
