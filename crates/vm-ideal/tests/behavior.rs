//! Behavioral memory I/O tests for the ideal VM, via the shared
//! [`mpz_vm_test_harness::behavior`] harness. Distinct from the WASM spec
//! conformance tests in `spec_runner.rs`: these drive the host-side
//! write/reveal/read surface rather than guest functions.

use futures::{
    executor::block_on,
    future::{join, try_join},
};
use mpz_common::context::test_st_context;
use mpz_vm_ir::Module;
use mpz_vm_core_new::{Param, Vm, Write, value::Value};
use mpz_vm_ideal::{IdealError, Instance};
use mpz_vm_test_harness::behavior::{
    Agreement, MemStep, MemVm, Observation, ReadOutcome, func_index,
};

/// A pair of ideal-VM instances exchanging over an in-process channel.
struct IdealPair {
    a: Instance,
    b: Instance,
}

impl MemVm for IdealPair {
    type Error = IdealError;

    fn instantiate(module: &Module) -> Result<Self, String> {
        Ok(Self {
            a: Instance::new(module.clone()).map_err(|e| format!("{e:?}"))?,
            b: Instance::new(module.clone()).map_err(|e| format!("{e:?}"))?,
        })
    }

    fn run_scenario(&mut self, steps: &[MemStep]) -> Result<Vec<Observation>, IdealError> {
        let mut observations = Vec::new();
        for step in steps {
            match step {
                MemStep::WritePrivateA { ptr, bytes } => {
                    self.a.write(*ptr, Write::Private(bytes))?;
                    self.b.write(*ptr, Write::Blind(bytes.len()))?;
                }
                MemStep::WritePrivateB { ptr, bytes } => {
                    self.a.write(*ptr, Write::Blind(bytes.len()))?;
                    self.b.write(*ptr, Write::Private(bytes))?;
                }
                MemStep::WritePublic { ptr, bytes } => {
                    self.a.write(*ptr, Write::Public(bytes))?;
                    self.b.write(*ptr, Write::Public(bytes))?;
                }
                MemStep::WritePublicDivergent {
                    ptr,
                    bytes_a,
                    bytes_b,
                } => {
                    self.a.write(*ptr, Write::Public(bytes_a))?;
                    self.b.write(*ptr, Write::Public(bytes_b))?;
                }
                MemStep::Reveal { ptr, len } => {
                    self.a.reveal(*ptr, *len)?;
                    self.b.reveal(*ptr, *len)?;
                }
                MemStep::Read { ptr, len } => {
                    let a = read_outcome(self.a.read(*ptr, *len));
                    let b = read_outcome(self.b.read(*ptr, *len));
                    observations.push(Observation::Read { a, b });
                }
                MemStep::Call { func, args } => {
                    let idx = func_index(self.a.module(), func)
                        .ok_or_else(|| IdealError::Internal(format!("no export {func}")))?;
                    let params: Vec<Param> = args.iter().copied().map(Param::Public).collect();
                    let (mut ctx_a, mut ctx_b) = test_st_context(8);
                    let (a, b) = block_on(try_join(
                        self.a.call(&mut ctx_a, idx, params.clone()),
                        self.b.call(&mut ctx_b, idx, params),
                    ))?;
                    observations.push(Observation::Call { a, b });
                }
                MemStep::CheckedCall { func, args } => {
                    let idx = func_index(self.a.module(), func)
                        .ok_or_else(|| IdealError::Internal(format!("no export {func}")))?;
                    let params: Vec<Param> = args.iter().copied().map(Param::Public).collect();
                    let (mut ctx_a, mut ctx_b) = test_st_context(8);
                    // `join` (not `try_join`): drive both parties to completion
                    // even if one errors, so the disagreement is observed rather
                    // than aborting the scenario.
                    let (a, b) = block_on(join(
                        self.a.call(&mut ctx_a, idx, params.clone()),
                        self.b.call(&mut ctx_b, idx, params),
                    ));
                    observations.push(Observation::Agreement(agreement(a, b)));
                }
            }
        }
        Ok(observations)
    }

    fn is_expected_unsupported(err: &IdealError) -> bool {
        err.is_expected_unsupported()
    }
}

fn read_outcome(result: Result<&[u8], IdealError>) -> ReadOutcome {
    match result {
        Ok(bytes) => ReadOutcome::Ok(bytes.to_vec()),
        Err(_) => ReadOutcome::Err,
    }
}

fn agreement(
    a: Result<Option<Value>, IdealError>,
    b: Result<Option<Value>, IdealError>,
) -> Agreement {
    match (a, b) {
        (Ok(a), Ok(b)) if a == b => Agreement::Agreed,
        _ => Agreement::Disagreed,
    }
}

mpz_vm_test_harness::mem_behavior_tests!(IdealPair);
