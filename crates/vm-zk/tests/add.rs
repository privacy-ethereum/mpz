//! End-to-end integration test for the zero-authenticated-work path: an
//! all-public, non-trapping call must not deadlock. Op/result correctness with
//! private inputs is covered far more broadly by the shared spec harness
//! (`tests/spec.rs`).

mod common;

use futures::{executor::block_on, future::join};
use mpz_common::context::test_st_context;
use mpz_vm_ir::{ExportKind, Module};
use mpz_ot::ideal::rcot::ideal_rcot;
use mpz_vm_core::{Param, Vm, value::Value};
use mpz_vm_zk::{Prover, Verifier};
use rand::{SeedableRng, rngs::StdRng};

fn func_idx(module: &Module, name: &str) -> u32 {
    module
        .exports()
        .iter()
        .find_map(|e| match e.kind {
            ExportKind::Func(idx) if e.name == name => Some(idx),
            _ => None,
        })
        .expect("function should be exported")
}

// An all-public, non-trapping call does zero authenticated work (no committed
// inputs, no gates), so both sides must skip the allocate/commit/challenge/proof
// exchange in lockstep. `join` (not `try_join`) and `block_on` give a hang
// nowhere to hide: if either side blocks, the test never returns.
#[test]
fn test_add_public_no_deadlock() {
    common::init_tracing();
    let wat = r#"
        (module
            (func $add (export "add") (param i32 i32) (result i32)
                local.get 0
                local.get 1
                i32.add))
    "#;
    let binary = wat::parse_str(wat).expect("valid WAT");
    let module = Module::parse(&binary).expect("valid module");
    let idx = func_idx(&module, "add");

    let mut rng = StdRng::seed_from_u64(0);
    let mut delta: mpz_core::Block = rand::Rng::random(&mut rng);
    delta.set_lsb(true);
    let (svole_sender, svole_receiver) = ideal_rcot(rand::Rng::random(&mut rng), delta);

    let mut prover = Prover::new(module.clone(), svole_receiver).unwrap();
    let mut verifier = Verifier::new(module, svole_sender).unwrap();

    let (mut ctx_p, mut ctx_v) = test_st_context(1024 * 1024);

    let params = || vec![Param::Public(Value::I32(2)), Param::Public(Value::I32(3))];

    let (result_p, result_v) = block_on(join(
        async { prover.call(&mut ctx_p, idx, params()).await.unwrap() },
        async { verifier.call(&mut ctx_v, idx, params()).await.unwrap() },
    ));

    assert_eq!(result_p, Some(Value::I32(5)));
    assert_eq!(result_v, Some(Value::I32(5)));
}
