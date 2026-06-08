//! A function that does symbolic work (real gates over a private input) but
//! returns a public constant. Per the VC spec, a concrete return value is
//! already public, so the prover transmits no output and binds nothing — the
//! verifier reconstructs the result locally.

mod common;

use futures::{executor::block_on, future::join};
use mpz_common::context::test_st_context;
use mpz_vm_ir::{ExportKind, Module, ValType};
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

#[test]
fn symbolic_work_public_const_return() {
    common::init_tracing();
    // Adds the private input to itself (a symbolic gate), discards it into an
    // unused local, then returns the public constant 42.
    let wat = r#"
        (module
            (func $f (export "f") (param i32) (result i32)
                (local $t i32)
                local.get 0
                local.get 0
                i32.add
                local.set $t
                i32.const 42))
    "#;
    let binary = wat::parse_str(wat).expect("valid WAT");
    let module = Module::parse(&binary).expect("valid module");
    let idx = func_idx(&module, "f");

    let mut rng = StdRng::seed_from_u64(0);
    let mut delta: mpz_core::Block = rand::Rng::random(&mut rng);
    delta.set_lsb(true);
    let (svole_sender, svole_receiver) = ideal_rcot(rand::Rng::random(&mut rng), delta);

    let mut prover = Prover::new(module.clone(), svole_receiver).unwrap();
    let mut verifier = Verifier::new(module, svole_sender).unwrap();

    let (mut ctx_p, mut ctx_v) = test_st_context(1024 * 1024);

    // Plain `join`: if the prover still errored mid-protocol on the concrete
    // output, the verifier would block on a recv and this would never return.
    let (result_p, result_v) = block_on(join(
        async {
            prover
                .call(&mut ctx_p, idx, vec![Param::Private(Value::I32(7))])
                .await
                .unwrap()
        },
        async {
            verifier
                .call(&mut ctx_v, idx, vec![Param::Blind(ValType::I32)])
                .await
                .unwrap()
        },
    ));

    assert_eq!(result_p, Some(Value::I32(42)));
    assert_eq!(result_v, Some(Value::I32(42)));
}
