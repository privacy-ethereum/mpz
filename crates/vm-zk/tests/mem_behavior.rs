//! Behavioral memory I/O tests for the zkVM, via the shared
//! [`mpz_vm_test_harness::behavior`] harness. Distinct from the WASM spec
//! conformance tests in `spec.rs`: these drive the host-side write/reveal/read
//! surface through the real prover/verifier protocol.
//!
//! The verifier is the blind party and never holds private data, so scenarios
//! that write a private value on party B are expected to surface an
//! `Unsupported` error and are recorded as skips.

use futures::{
    executor::block_on,
    future::{join, try_join},
};
use mpz_common::context::test_st_context;
use mpz_core::Block;
use mpz_ot::ideal::rcot::ideal_rcot;
use mpz_vm_core::{Param, Vm, Write, value::Value};
use mpz_vm_ir::Module;
use mpz_vm_test_harness::behavior::{
    Agreement, MemStep, MemVm, Observation, ReadOutcome, func_index, parse_module,
};
use mpz_vm_zk::{Prover, Verifier, ZkVmError};
use rand::{Rng, SeedableRng, rngs::StdRng};

struct ZkPair {
    module: Module,
    prover: Prover<mpz_ot::ideal::rcot::IdealRCOTReceiver>,
    verifier: Verifier<mpz_ot::ideal::rcot::IdealRCOTSender>,
}

impl MemVm for ZkPair {
    fn instantiate(module: &Module) -> Result<Self, String> {
        let mut rng = StdRng::seed_from_u64(0);
        let mut delta: Block = rng.random();
        delta.set_lsb(true);
        let (svole_sender, svole_receiver) = ideal_rcot(rng.random(), delta);
        let prover = Prover::new(module.clone(), svole_receiver).map_err(|e| format!("{e:?}"))?;
        let verifier = Verifier::new(module.clone(), svole_sender).map_err(|e| format!("{e:?}"))?;
        Ok(Self {
            module: module.clone(),
            prover,
            verifier,
        })
    }

    type Error = ZkVmError;

    fn run_scenario(&mut self, steps: &[MemStep]) -> Result<Vec<Observation>, ZkVmError> {
        let mut observations = Vec::new();
        for step in steps {
            match step {
                MemStep::WritePrivateA { ptr, bytes } => {
                    self.prover.write(*ptr, Write::Private(bytes))?;
                    self.verifier.write(*ptr, Write::Blind(bytes.len()))?;
                }
                MemStep::WritePrivateB { ptr, bytes } => {
                    self.prover.write(*ptr, Write::Blind(bytes.len()))?;
                    self.verifier.write(*ptr, Write::Private(bytes))?;
                }
                MemStep::WritePublic { ptr, bytes } => {
                    self.prover.write(*ptr, Write::Public(bytes))?;
                    self.verifier.write(*ptr, Write::Public(bytes))?;
                }
                MemStep::WritePublicDivergent {
                    ptr,
                    bytes_a,
                    bytes_b,
                } => {
                    self.prover.write(*ptr, Write::Public(bytes_a))?;
                    self.verifier.write(*ptr, Write::Public(bytes_b))?;
                }
                MemStep::Reveal { ptr, len } => {
                    self.prover.reveal(*ptr, *len)?;
                    self.verifier.reveal(*ptr, *len)?;
                }
                MemStep::Read { ptr, len } => {
                    let a = read_outcome(self.prover.read(*ptr, *len));
                    let b = read_outcome(self.verifier.read(*ptr, *len));
                    observations.push(Observation::Read { a, b });
                }
                MemStep::Call { func, args } => {
                    let idx = func_index(&self.module, func)
                        .ok_or_else(|| ZkVmError::Internal(format!("no export {func}")))?;
                    let params: Vec<Param> = args.iter().copied().map(Param::Public).collect();
                    let (mut ctx_p, mut ctx_v) = test_st_context(1024 * 1024);
                    let (a, b) = block_on(try_join(
                        self.prover.call(&mut ctx_p, idx, params.clone()),
                        self.verifier.call(&mut ctx_v, idx, params),
                    ))?;
                    observations.push(Observation::Call { a, b });
                }
                MemStep::CheckedCall { func, args } => {
                    let idx = func_index(&self.module, func)
                        .ok_or_else(|| ZkVmError::Internal(format!("no export {func}")))?;
                    let params: Vec<Param> = args.iter().copied().map(Param::Public).collect();
                    let (mut ctx_p, mut ctx_v) = test_st_context(1024 * 1024);
                    // `join` (not `try_join`): drive both parties to completion
                    // so a divergence surfaces as a disagreement rather than
                    // aborting the scenario.
                    let (a, b) = block_on(join(
                        self.prover.call(&mut ctx_p, idx, params.clone()),
                        self.verifier.call(&mut ctx_v, idx, params),
                    ));
                    observations.push(Observation::Agreement(agreement(a, b)));
                }
                MemStep::Commit => {
                    let (mut ctx_p, mut ctx_v) = test_st_context(1024 * 1024);
                    block_on(try_join(
                        self.prover.commit(&mut ctx_p),
                        self.verifier.commit(&mut ctx_v),
                    ))?;
                }
                MemStep::CallLocal { func, args } => {
                    let idx = func_index(&self.module, func)
                        .ok_or_else(|| ZkVmError::Internal(format!("no export {func}")))?;
                    let params: Vec<Param> = args.iter().copied().map(Param::Public).collect();
                    let a = self.prover.call_local(idx, params.clone())?;
                    let b = self.verifier.call_local(idx, params)?;
                    observations.push(Observation::Call { a, b });
                }
            }
        }
        Ok(observations)
    }

    fn is_expected_unsupported(err: &ZkVmError) -> bool {
        err.is_expected_unsupported()
    }
}

fn read_outcome(result: Result<&[u8], ZkVmError>) -> ReadOutcome {
    match result {
        Ok(bytes) => ReadOutcome::Ok(bytes.to_vec()),
        Err(_) => ReadOutcome::Err,
    }
}

fn agreement(
    a: Result<Option<Value>, ZkVmError>,
    b: Result<Option<Value>, ZkVmError>,
) -> Agreement {
    match (a, b) {
        (Ok(a), Ok(b)) if a == b => Agreement::Agreed,
        _ => Agreement::Disagreed,
    }
}

mpz_vm_test_harness::mem_behavior_tests!(ZkPair);

/// `call_local` refuses a private parameter: committing it requires a proving
/// round.
#[test]
fn call_local_rejects_private_param() {
    let module =
        parse_module("(module (func (export \"id\") (param i32) (result i32) local.get 0))")
            .unwrap();
    let mut pair = ZkPair::instantiate(&module).unwrap();
    let idx = func_index(&pair.module, "id").unwrap();
    let err = pair
        .prover
        .call_local(idx, vec![Param::Private(Value::I32(1))])
        .unwrap_err();
    assert!(
        matches!(err, ZkVmError::RequiresCommunication(_)),
        "got {err:?}"
    );
}

/// `call_local` refuses to run once execution turns symbolic: a committed
/// private write feeds a load, which can only be evaluated under proof. The
/// same program runs fine through a full `call` (see
/// `commit_then_call_consumes_memory`).
#[test]
fn call_local_rejects_symbolic_execution() {
    let module = parse_module(
        "(module (memory 1)
            (func (export \"loadadd\") (result i32)
                i32.const 0 i32.load i32.const 1 i32.add))",
    )
    .unwrap();
    let mut pair = ZkPair::instantiate(&module).unwrap();
    pair.prover
        .write(0, Write::Private(&7i32.to_le_bytes()))
        .unwrap();
    pair.verifier.write(0, Write::Blind(4)).unwrap();
    let (mut ctx_p, mut ctx_v) = test_st_context(1024 * 1024);
    block_on(try_join(
        pair.prover.commit(&mut ctx_p),
        pair.verifier.commit(&mut ctx_v),
    ))
    .unwrap();
    let idx = func_index(&pair.module, "loadadd").unwrap();
    let err = pair.prover.call_local(idx, vec![]).unwrap_err();
    assert!(
        matches!(err, ZkVmError::RequiresCommunication(_)),
        "got {err:?}"
    );
}
