//! Stress the chunk-loop with a tight cap that forces a chunk per
//! `i32.add`. Catches AuthMap-across-chunks regressions: each gate's
//! output is needed by the next chunk's gate.

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
fn chunk_per_gate() {
    common::init_tracing();
    // Five chained adds = 5 × 32 = 160 sVOLE bits. Cap at 1 forces
    // one chunk per i32.add — the AuthMap entry written by chunk N
    // must still be live in chunk N+1.
    let wat = r#"
        (module
            (func $sum6 (export "sum6")
                (param i32 i32 i32 i32 i32 i32) (result i32)
                local.get 0
                local.get 1
                i32.add
                local.get 2
                i32.add
                local.get 3
                i32.add
                local.get 4
                i32.add
                local.get 5
                i32.add))
    "#;
    let binary = wat::parse_str(wat).unwrap();
    let module = Module::parse(&binary).unwrap();
    let idx = func_idx(&module, "sum6");

    let mut rng = StdRng::seed_from_u64(17);
    let mut delta: mpz_core::Block = rand::Rng::random(&mut rng);
    delta.set_lsb(true);
    let (svole_sender, svole_receiver) = ideal_rcot(rand::Rng::random(&mut rng), delta);

    let mut prover = Prover::new(module.clone(), svole_receiver)
        .unwrap()
        .with_chunk_cap(Some(1));
    let mut verifier = Verifier::new(module, svole_sender)
        .unwrap()
        .with_chunk_cap(Some(1));

    let (mut ctx_p, mut ctx_v) = test_st_context(1024 * 1024);

    let (rp, rv) = block_on(join(
        async {
            prover
                .call(
                    &mut ctx_p,
                    idx,
                    vec![
                        Param::Private(Value::I32(1)),
                        Param::Private(Value::I32(2)),
                        Param::Private(Value::I32(3)),
                        Param::Private(Value::I32(4)),
                        Param::Private(Value::I32(5)),
                        Param::Private(Value::I32(6)),
                    ],
                )
                .await
                .unwrap()
        },
        async {
            verifier
                .call(
                    &mut ctx_v,
                    idx,
                    vec![
                        Param::Blind(ValType::I32),
                        Param::Blind(ValType::I32),
                        Param::Blind(ValType::I32),
                        Param::Blind(ValType::I32),
                        Param::Blind(ValType::I32),
                        Param::Blind(ValType::I32),
                    ],
                )
                .await
                .unwrap()
        },
    ));

    assert_eq!(rp, Some(Value::I32(21)));
    assert_eq!(rv, Some(Value::I32(21)));
}
