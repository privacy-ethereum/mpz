//! WebAssembly spec-conformance tests for the zkVM, via the shared
//! [`mpz_vm_test_harness`] harness.
//!
//! `spec_all` runs the entire WASM core spec suite through the real
//! prover/verifier protocol. The zkVM supports only a subset of WebAssembly, so
//! the harness is configured to treat unsupported ops, private control flow, and
//! symbolic value/address errors as expected skips rather than failures.

use futures::{executor::block_on, future::try_join};
use mpz_common::context::test_st_context;
use mpz_core::Block;
use mpz_vm_ir::Module;
use mpz_ot::ideal::rcot::{IdealRCOTReceiver, IdealRCOTSender, ideal_rcot};
use mpz_vm_core_new::{Param, Vm, value::Value};
use mpz_vm_test_harness::{SpecConfig, SpecVm, run_suite, suites};
use mpz_vm_zk::{Prover, Verifier, ZkVmError};
use rand::{Rng, SeedableRng, rngs::StdRng};

/// A prover/verifier pair wired over ideal sVOLE.
struct ZkPair {
    prover: Prover<IdealRCOTReceiver>,
    verifier: Verifier<IdealRCOTSender>,
}

impl SpecVm for ZkPair {
    type Error = ZkVmError;

    fn variants() -> Vec<String> {
        // Default (unbounded chunk) plus a small-cap variant that drives the
        // whole spec corpus through multi-chunk proving, exercising cross-chunk
        // authenticated-state liveness on every construct rather than on a few
        // hand-written programs.
        vec![String::new(), "chunk64".to_string()]
    }

    fn instantiate(module: &Module, variant: &str) -> Result<Self, String> {
        let cap = match variant {
            "" => None,
            "chunk64" => Some(64),
            other => return Err(format!("unknown variant: {other}")),
        };
        let mut rng = StdRng::seed_from_u64(0);
        let mut delta: Block = rng.random();
        delta.set_lsb(true);
        let (svole_sender, svole_receiver) = ideal_rcot(rng.random(), delta);
        let prover = Prover::new(module.clone(), svole_receiver)
            .map_err(|e| format!("{:?}", e))?
            .with_chunk_cap(cap);
        let verifier = Verifier::new(module.clone(), svole_sender)
            .map_err(|e| format!("{:?}", e))?
            .with_chunk_cap(cap);
        Ok(Self { prover, verifier })
    }

    fn run(
        &mut self,
        func_idx: u32,
        params_a: Vec<Param>,
        params_b: Vec<Param>,
    ) -> Result<(Option<Value>, Option<Value>), ZkVmError> {
        let (mut ctx_p, mut ctx_v) = test_st_context(1024 * 1024);
        // `try_join` (not `join`) so that if one party errors mid-protocol the
        // other future is dropped rather than left blocked on a recv.
        block_on(try_join(
            self.prover.call(&mut ctx_p, func_idx, params_a),
            self.verifier.call(&mut ctx_v, func_idx, params_b),
        ))
    }

    fn is_expected_unsupported(err: &ZkVmError) -> bool {
        err.is_expected_unsupported()
    }
}

fn zk_config() -> SpecConfig {
    SpecConfig {
        run_private_passes: true,
    }
}

/// Run the entire WASM spec suite against the zkVM through the real
/// prover/verifier protocol.
#[test]
fn spec_all() {
    let (mut passed, mut failed, mut skipped) = (0usize, 0usize, 0usize);
    let mut failures: Vec<String> = Vec::new();
    for &(name, wast) in suites::ALL {
        let stats = run_suite::<ZkPair>(wast, &zk_config());
        println!(
            "{name}: {} passed, {} failed, {} skipped",
            stats.passed, stats.failed, stats.skipped
        );
        for (category, count) in stats.skip_summary() {
            println!("  skipped {count:>5}  {category}");
        }
        for msg in &stats.failure_messages {
            failures.push(format!("[{name}] {msg}"));
        }
        passed += stats.passed;
        failed += stats.failed;
        skipped += stats.skipped;
    }
    println!("TOTAL: {passed} passed, {failed} failed, {skipped} skipped");
    for (i, msg) in failures.iter().enumerate() {
        println!("  failure {}. {}", i + 1, msg);
    }
    assert_eq!(failed, 0, "zkVM spec suites had {failed} failure(s)");
}
