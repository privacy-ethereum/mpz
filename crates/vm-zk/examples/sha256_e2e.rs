//! Isolated end-to-end sha256 runs for profiling.
//!
//! Does exactly what one iteration of the `vm` bench measures — build the
//! full crypto stack (base OT, SoftSpoken, Ferret), allocate the guest buffer, stage
//! the message, prove the hash, check the revealed digest — without
//! criterion, cross-variant validation runs, or per-iteration worker-pool
//! churn. The executor pair (the session) is created once, like a long-lived
//! connection.
//!
//! ```text
//! cargo run --release -p mpz-vm-zk --example sha256_e2e -- \
//!     [--len 4096] [--segment-cost 25000] [--iters 10]
//! ```
//!
//! Profile with e.g. `samply record -- target/release/examples/sha256_e2e
//! --segment-cost 25000 --iters 20`.

use std::time::Instant;

use futures::executor::block_on;
use mpz_common::{Context, context::test_mt_context};
use mpz_core::Block;
use mpz_ot::{chou_orlandi, ferret, softspoken};
use mpz_vm_core::{Param, Vm, Write, value::Value};
use mpz_vm_ir::{ExportKind, Module};
use mpz_vm_zk::{Prover, Verifier};
use rand::{Rng, SeedableRng, rngs::StdRng};
use sha2::{Digest, Sha256};

type ProverSvole = ferret::Receiver<softspoken::Receiver<chou_orlandi::Sender>>;
type VerifierSvole = ferret::Sender<softspoken::Sender<chou_orlandi::Receiver>>;

fn rcot_stack(seed: u64) -> (VerifierSvole, ProverSvole) {
    let mut rng = StdRng::seed_from_u64(seed);
    let mut delta: Block = rng.random();
    delta.set_lsb(true);

    let verifier = ferret::Sender::new(
        ferret::FerretConfig::default(),
        rng.random(),
        softspoken::Sender::new(
            softspoken::SenderConfig::default(),
            delta,
            chou_orlandi::Receiver::new(),
        ),
    );
    let prover = ferret::Receiver::new(
        ferret::FerretConfig::default(),
        rng.random(),
        softspoken::Receiver::new(softspoken::ReceiverConfig::default(), chou_orlandi::Sender::new()),
    );
    (verifier, prover)
}

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

fn call_both(
    prover: &mut Prover<ProverSvole>,
    verifier: &mut Verifier<VerifierSvole>,
    ctx_p: &mut Context,
    ctx_v: &mut Context,
    func: u32,
    p_params: Vec<Param>,
    v_params: Vec<Param>,
) -> (Option<Value>, Option<Value>) {
    std::thread::scope(|s| {
        let hp = s.spawn(move || block_on(prover.call(ctx_p, func, p_params)).unwrap());
        let hv = s.spawn(move || block_on(verifier.call(ctx_v, func, v_params)).unwrap());
        (hp.join().unwrap(), hv.join().unwrap())
    })
}

fn arg(name: &str, default: usize) -> usize {
    let mut args = std::env::args();
    while let Some(a) = args.next() {
        if a == name {
            return args
                .next()
                .and_then(|v| v.parse().ok())
                .unwrap_or_else(|| panic!("{name} expects a number"));
        }
    }
    default
}

fn main() {
    let len = arg("--len", 4096);
    let segment_cost = arg("--segment-cost", 0);
    let segment_cost = (segment_cost > 0).then_some(segment_cost);
    let chunk_cap = arg("--chunk-cap", 0);
    let chunk_cap = (chunk_cap > 0).then_some(chunk_cap);
    let iters = arg("--iters", 1);

    let wasm = include_bytes!("../benches/guests/sha256.wasm");
    let module = Module::parse(wasm).unwrap();
    let realloc = func_idx(&module, "cabi_realloc");
    let hash = func_idx(&module, "hash");
    let msg: Vec<u8> = (0..len).map(|i| i as u8).collect();
    let expected = Sha256::digest(&msg);

    // The session: created once, reused across iterations.
    let (exec_p, exec_v) = test_mt_context(32 << 20);
    let mut ctx_p = exec_p.new_context().unwrap();
    let mut ctx_v = exec_v.new_context().unwrap();

    println!("len={len} segment_cost={segment_cost:?} iters={iters}");
    for i in 0..iters {
        let start = Instant::now();

        // Everything below is one end-to-end run: fresh crypto stack and
        // prover/verifier state.
        let (v_svole, p_svole) = rcot_stack(0);
        let mut prover = Prover::new(module.clone(), p_svole)
            .unwrap()
            .with_segment_cost(segment_cost);
        let mut verifier = Verifier::new(module.clone(), v_svole)
            .unwrap()
            .with_segment_cost(segment_cost);
        if let Some(cap) = chunk_cap {
            prover = prover.with_chunk_cap(Some(cap));
            verifier = verifier.with_chunk_cap(Some(cap));
        }

        // The buffer must hold the message [0, len) and the digest the guest
        // writes at [4096, 4128); 4 KiB was the original hard-coded design point.
        let buf_size = len.max(4128) as i32;
        let alloc_args = || {
            vec![
                Param::Public(Value::I32(0)),
                Param::Public(Value::I32(0)),
                Param::Public(Value::I32(1)),
                Param::Public(Value::I32(buf_size)),
            ]
        };
        let (rp, rv) = call_both(
            &mut prover,
            &mut verifier,
            &mut ctx_p,
            &mut ctx_v,
            realloc,
            alloc_args(),
            alloc_args(),
        );
        assert_eq!(rp, rv, "cabi_realloc must agree");
        let ptr = match rp {
            Some(Value::I32(p)) => p as u32,
            other => panic!("cabi_realloc returned {other:?}"),
        };
        prover.write(ptr, Write::Private(&msg)).unwrap();
        verifier.write(ptr, Write::Blind(msg.len())).unwrap();

        let params = vec![
            Param::Public(Value::I32(ptr as i32)),
            Param::Public(Value::I32(len as i32)),
        ];
        let (rp, rv) = call_both(
            &mut prover,
            &mut verifier,
            &mut ctx_p,
            &mut ctx_v,
            hash,
            params.clone(),
            params,
        );
        assert_eq!(rp, rv, "hash result must agree");

        // The guest writes and reveals the digest at ptr + 4096.
        let digest = verifier.read(ptr + 4096, 32).unwrap();
        assert_eq!(digest, expected.as_slice(), "digest must match reference");

        println!("iter {i}: {:.1} ms", start.elapsed().as_secs_f64() * 1e3);
    }

    exec_p.shutdown();
    exec_v.shutdown();
}
