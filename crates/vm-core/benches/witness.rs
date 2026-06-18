//! Benchmark: witness generation for a private SHA-256 over a 64 KiB message.
//!
//! The prover's witness is the directive trace produced by executing the guest
//! with its private input: every symbolic [`Op`](mpz_vm_core::value) is
//! evaluated concretely (the prover holds the bits) while the resulting
//! [`Directive`] stream is recorded. This is the single-threaded front-end that
//! a zk prover runs before any parallel proving, so it is benchmarked here in
//! isolation, over the real `mpz-vm-core` interpreter.
//!
//! The guest hashes a private message and reveals the digest; host (reveal)
//! calls are resolved with a dummy handle so execution runs to completion —
//! their values do not feed back into the hash.

use criterion::{Criterion, Throughput, black_box, criterion_group, criterion_main};
use mpz_vm_core::{
    Call, Directive, Global, Module, Param, StepResult, Thread, Visibility, value::Value,
};
use mpz_vm_ir::ExportKind;
use sha2::{Digest, Sha256};

/// Private message length: 64 KiB.
const MSG_LEN: usize = 64 * 1024;

/// Resolves an exported function's index by name.
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

/// Drives `thread` to completion, recording each emitted [`Directive`] into
/// `trace` (the witness), and returns the call's result.
///
/// Imported (host) calls — the guest's reveals — are resolved with a dummy
/// handle so execution proceeds; their return values do not affect the
/// computation being witnessed.
fn execute(
    module: &Module,
    global: &mut Global,
    thread: &mut Thread,
    trace: &mut Vec<Directive>,
) -> Option<Value> {
    loop {
        match thread.step(module, global).expect("step should not fault") {
            StepResult::Continue => {}
            StepResult::Directive(d) => {
                if let Directive::Call { func_idx, dst, .. } = &d
                    && module.function(*func_idx).is_some_and(|f| f.is_import())
                {
                    let value = dst.map(|_| Value::I32(0));
                    thread
                        .resolve_host_call(value, Visibility::Public)
                        .expect("host call should resolve");
                }
                trace.push(d);
            }
            StepResult::Blocked(p) => panic!("witness generation blocked: {p:?}"),
            StepResult::Trapped { trap, .. } => panic!("witness generation trapped: {trap:?}"),
            StepResult::Done { result, .. } => return result,
        }
    }
}

fn bench_witness_sha256(c: &mut Criterion) {
    let wasm = include_bytes!("guests/sha256.wasm");
    let module = Module::parse(wasm).unwrap();
    let realloc = func_idx(&module, "cabi_realloc");
    let hash = func_idx(&module, "hash");

    let msg: Vec<u8> = (0..MSG_LEN).map(|i| i as u8).collect();

    // Allocate the message buffer inside the running module via its canonical
    // `cabi_realloc` export, exactly as the zk harness does, so the staged
    // region is in bounds and memory is grown by the guest's own allocator.
    let mut global = Global::new(&module).unwrap();
    let ptr = {
        let mut thread = Thread::new();
        thread
            .call(
                &module,
                &mut global,
                Call {
                    func_idx: realloc,
                    params: vec![
                        Param::Public(Value::I32(0)),
                        Param::Public(Value::I32(0)),
                        Param::Public(Value::I32(1)),
                        Param::Public(Value::I32(MSG_LEN as i32)),
                    ],
                },
            )
            .unwrap();
        match execute(&module, &mut global, &mut thread, &mut Vec::new()) {
            Some(Value::I32(p)) => p as u32,
            other => panic!("cabi_realloc returned {other:?}"),
        }
    };

    // Stage the message privately: its loads become symbolic, so the whole hash
    // executes symbolically and emits the full directive trace (the witness).
    let stage = |global: &mut Global| {
        global.memory_mut().unwrap().write_bytes(ptr, &msg).unwrap();
        global.set_memory_visibility(ptr, MSG_LEN, Visibility::Private);
    };
    stage(&mut global);

    let params = vec![
        Param::Public(Value::I32(ptr as i32)),
        Param::Public(Value::I32(MSG_LEN as i32)),
    ];

    // Validate once: the witnessed run must produce a correct SHA-256 digest
    // (the prover evaluates the private computation concretely). `hash` returns
    // the address of the digest it wrote to its own freshly allocated buffer.
    {
        let mut thread = Thread::new();
        thread
            .call(
                &module,
                &mut global,
                Call {
                    func_idx: hash,
                    params: params.clone(),
                },
            )
            .unwrap();
        let digest_ptr = match execute(&module, &mut global, &mut thread, &mut Vec::new()) {
            Some(Value::I32(p)) => p as u32,
            other => panic!("hash returned {other:?}"),
        };
        let digest = global.memory().unwrap().read_bytes(digest_ptr, 32).unwrap();
        assert_eq!(
            digest,
            Sha256::digest(&msg).as_slice(),
            "witness must encode a correct SHA-256 of the private message"
        );
    }

    let mut group = c.benchmark_group("vm-core/witness");
    group.sample_size(10);
    group.throughput(Throughput::Bytes(MSG_LEN as u64));
    group.bench_function("sha256_private_64k", |b| {
        b.iter(|| {
            let mut thread = Thread::new();
            thread
                .call(
                    &module,
                    &mut global,
                    Call {
                        func_idx: hash,
                        params: params.clone(),
                    },
                )
                .unwrap();
            let mut trace = Vec::new();
            execute(&module, &mut global, &mut thread, &mut trace);
            black_box(trace.len())
        });
    });
    group.finish();
}

criterion_group!(benches, bench_witness_sha256);
criterion_main!(benches);
