//! Float parameters must be rejected at `Vm::call` entry, not later
//! deep in the pipeline.

mod common;

use futures::executor::block_on;
use mpz_common::context::test_st_context;
use mpz_vm_ir::{ExportKind, Module};
use mpz_ot::ideal::rcot::ideal_rcot;
use mpz_vm_core::{Param, Vm, value::Value};
use mpz_vm_zk::{Prover, ZkVmError};
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

#[test]
fn private_f32_is_rejected_up_front() {
    common::init_tracing();
    let wat = r#"
        (module
            (func $id (export "id") (param f32) (result f32)
                local.get 0))
    "#;
    let binary = wat::parse_str(wat).unwrap();
    let module = Module::parse(&binary).unwrap();
    let idx = func_idx(&module, "id");

    let mut rng = StdRng::seed_from_u64(13);
    let mut delta: mpz_core::Block = rand::Rng::random(&mut rng);
    delta.set_lsb(true);
    let (_svole_sender, svole_receiver) = ideal_rcot(rand::Rng::random(&mut rng), delta);
    let mut prover = Prover::new(module, svole_receiver).unwrap();
    let (mut ctx_p, _ctx_v) = test_st_context(1024);

    let err = block_on(async {
        prover
            .call(&mut ctx_p, idx, vec![Param::Private(Value::F32(1.0))])
            .await
            .unwrap_err()
    });
    assert!(
        matches!(err, ZkVmError::Unsupported(_)),
        "expected Unsupported, got {err:?}"
    );
}
