//! Segmented proving repro for the sha256 guest: the bench workload over
//! ideal sVOLE, small message, low segment cost — fails fast and
//! deterministically if boundary stitching is broken.

use futures::{executor::block_on, future::try_join};
use mpz_common::context::test_st_context;
use mpz_core::Block;
use mpz_ot::ideal::rcot::ideal_rcot;
use mpz_vm_core::{Param, Vm, Write, value::Value};
use mpz_vm_ir::{ExportKind, Module};
use mpz_vm_zk::{Prover, Verifier};
use rand::{Rng, SeedableRng, rngs::StdRng};
use sha2::{Digest, Sha256};

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
fn sha256_segmented() {
    let wasm = include_bytes!("../benches/guests/sha256.wasm");
    let module = Module::parse(wasm).unwrap();

    let len: usize = 64;
    let msg: Vec<u8> = (0..len).map(|i| i as u8).collect();
    // The guest writes the digest at a fixed `ptr + 4096`, past the (up to
    // 4 KiB) message region.
    let alloc = 4096 + 32_u32;

    let mut rng = StdRng::seed_from_u64(0);
    let mut delta: Block = rng.random();
    delta.set_lsb(true);
    let (svole_sender, svole_receiver) = ideal_rcot(rng.random(), delta);
    let mut prover = Prover::new(module.clone(), svole_receiver)
        .unwrap()
        .with_segment_cost(Some(5_000));
    let mut verifier = Verifier::new(module.clone(), svole_sender)
        .unwrap()
        .with_segment_cost(Some(5_000));

    // Allocate the input buffer in-guest, mirroring the bench.
    let realloc = func_idx(&module, "cabi_realloc");
    let alloc_args = || {
        vec![
            Param::Public(Value::I32(0)),
            Param::Public(Value::I32(0)),
            Param::Public(Value::I32(1)),
            Param::Public(Value::I32(alloc as i32)),
        ]
    };
    let (mut ctx_p, mut ctx_v) = test_st_context(8 << 20);
    let (rp, rv) = block_on(try_join(
        prover.call(&mut ctx_p, realloc, alloc_args()),
        verifier.call(&mut ctx_v, realloc, alloc_args()),
    ))
    .unwrap();
    assert_eq!(rp, rv);
    let ptr = match rp {
        Some(Value::I32(p)) => p as u32,
        other => panic!("cabi_realloc returned {other:?}"),
    };

    prover.write(ptr, Write::Private(&msg)).unwrap();
    verifier.write(ptr, Write::Blind(msg.len())).unwrap();

    let hash = func_idx(&module, "hash");
    let params = |_: ()| {
        vec![
            Param::Public(Value::I32(ptr as i32)),
            Param::Public(Value::I32(len as i32)),
        ]
    };
    let (rp, rv) = block_on(try_join(
        prover.call(&mut ctx_p, hash, params(())),
        verifier.call(&mut ctx_v, hash, params(())),
    ))
    .unwrap();
    assert_eq!(rp, rv);

    // The guest reveals the digest at ptr + 4096.
    let digest = verifier.read(ptr + 4096, 32).unwrap().to_vec();
    assert_eq!(digest.as_slice(), Sha256::digest(&msg).as_slice());
}
