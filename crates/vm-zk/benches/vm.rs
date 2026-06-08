//! Benchmark harness for the zk-vm over a real OT stack.
//!
//! Each measured iteration runs a wasm module end to end through the
//! [`Prover`]/[`Verifier`] pair, with correlated randomness drawn from a real
//! `CO15 -> KOS -> Ferret` RCOT stack (Chou-Orlandi base OT, KOS extension,
//! Ferret expansion) rather than an ideal functionality — so the measurement
//! reflects the cost of the actual protocol, including OT/VOLE generation.
//!
//! The harness is module-agnostic: describe a [`Workload`] (a module, an
//! exported function, private memory, and arguments) and bench it. The headline
//! workload is SHA-256 of a 4 KiB message.

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use futures::executor::block_on;
use mpz_common::context::{test_mt_context, test_st_context};
use mpz_core::Block;
use mpz_ot::{chou_orlandi, ferret, kos};
use mpz_vm_core_new::{Param, Vm, Write, value::Value};
use mpz_vm_ir::{ExportKind, Module};
use mpz_vm_zk::{Prover, Verifier};
use rand::{Rng, SeedableRng, rngs::StdRng};
use sha2::{Digest, Sha256};

/// The prover's RCOT receiver: Ferret over KOS over a Chou-Orlandi base OT.
type ProverSvole = ferret::Receiver<kos::Receiver<chou_orlandi::Sender>>;
/// The verifier's RCOT sender: Ferret over KOS over a Chou-Orlandi base OT.
type VerifierSvole = ferret::Sender<kos::Sender<chou_orlandi::Receiver>>;

/// Builds the real RCOT stack for both parties from `seed`.
///
/// The verifier is the RCOT sender and holds the correlation `delta` (its lsb
/// forced to 1, as the zk-vm requires); the prover is the RCOT receiver. The
/// base-OT roles are swapped relative to the extension: the verifier's KOS
/// sender is bootstrapped by a Chou-Orlandi receiver, the prover's KOS receiver
/// by a Chou-Orlandi sender.
fn rcot_stack(seed: u64) -> (VerifierSvole, ProverSvole) {
    let mut rng = StdRng::seed_from_u64(seed);
    let mut delta: Block = rng.random();
    delta.set_lsb(true);

    let verifier = ferret::Sender::new(
        ferret::FerretConfig::default(),
        rng.random(),
        kos::Sender::new(kos::SenderConfig::default(), delta, chou_orlandi::Receiver::new()),
    );
    let prover = ferret::Receiver::new(
        ferret::FerretConfig::default(),
        rng.random(),
        kos::Receiver::new(kos::ReceiverConfig::default(), chou_orlandi::Sender::new()),
    );
    (verifier, prover)
}

/// A call argument: `Secret` is private to the prover (blind to the verifier),
/// `Public` is known to both.
#[derive(Clone)]
enum Arg {
    Secret(Value),
    Public(Value),
}

/// A unit of work to benchmark.
#[derive(Clone)]
struct Workload {
    module: Module,
    func: u32,
    /// Private memory regions to stage as `(ptr, bytes)`.
    mem: Vec<(u32, Vec<u8>)>,
    args: Vec<Arg>,
    chunk_cap: Option<usize>,
}

impl Workload {
    fn new(module: Module, func_name: &str) -> Self {
        let func = func_idx(&module, func_name);
        Self {
            module,
            func,
            mem: Vec::new(),
            args: Vec::new(),
            chunk_cap: None,
        }
    }

    fn private_mem(mut self, ptr: u32, bytes: Vec<u8>) -> Self {
        self.mem.push((ptr, bytes));
        self
    }

    fn args(mut self, args: Vec<Arg>) -> Self {
        self.args = args;
        self
    }
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

/// Runs the workload once through the prover/verifier over the real OT stack,
/// optionally reading back a memory range from the verifier afterwards (used to
/// recover a revealed result). Panics if the two sides disagree.
fn run_reading(wl: &Workload, read: Option<(u32, usize)>) -> (Option<Value>, Option<Vec<u8>>) {
    let (v_svole, p_svole) = rcot_stack(0);
    let mut prover = Prover::new(wl.module.clone(), p_svole)
        .unwrap()
        .with_chunk_cap(wl.chunk_cap);
    let mut verifier = Verifier::new(wl.module.clone(), v_svole)
        .unwrap()
        .with_chunk_cap(wl.chunk_cap);

    for (ptr, bytes) in &wl.mem {
        prover.write(*ptr, Write::Private(bytes)).unwrap();
        verifier.write(*ptr, Write::Blind(bytes.len())).unwrap();
    }

    let p_params: Vec<Param> = wl
        .args
        .iter()
        .map(|a| match a {
            Arg::Secret(v) => Param::Private(*v),
            Arg::Public(v) => Param::Public(*v),
        })
        .collect();
    let v_params: Vec<Param> = wl
        .args
        .iter()
        .map(|a| match a {
            Arg::Secret(v) => Param::Blind(v.ty()),
            Arg::Public(v) => Param::Public(*v),
        })
        .collect();

    // Multithreaded contexts so each party can parallelize internally; the two
    // parties run on separate OS threads, as they would in a real deployment.
    let (exec_p, exec_v) = test_mt_context(32 << 20);
    let mut ctx_p = exec_p.new_context().unwrap();
    let mut ctx_v = exec_v.new_context().unwrap();
    let func = wl.func;

    let (rp, rv) = std::thread::scope(|s| {
        let prover = &mut prover;
        let verifier = &mut verifier;
        let ctx_p = &mut ctx_p;
        let ctx_v = &mut ctx_v;
        let hp = s.spawn(move || block_on(prover.call(ctx_p, func, p_params)).unwrap());
        let hv = s.spawn(move || block_on(verifier.call(ctx_v, func, v_params)).unwrap());
        (hp.join().unwrap(), hv.join().unwrap())
    });
    exec_p.shutdown();
    exec_v.shutdown();

    assert_eq!(rp, rv, "prover and verifier results must agree");
    let bytes = read.map(|(ptr, len)| verifier.read(ptr, len).unwrap().to_vec());
    (rp, bytes)
}

fn run(wl: &Workload) -> Option<Value> {
    run_reading(wl, None).0
}

/// Evaluates an `i32`-returning export on the ideal VM — used to recover a
/// guest-allocated buffer address (via `cabi_realloc`) without measured cost.
fn ideal_i32(module: &Module, func_name: &str, args: Vec<Value>) -> i32 {
    use mpz_vm_ideal::Instance;
    let mut vm = Instance::new(module.clone()).unwrap();
    let idx = func_idx(module, func_name);
    let (mut ctx, _) = test_st_context(1 << 20);
    let params: Vec<Param> = args.into_iter().map(Param::Public).collect();
    match block_on(vm.call(&mut ctx, idx, params)).unwrap() {
        Some(Value::I32(p)) => p,
        other => panic!("{func_name} returned {other:?}"),
    }
}

/// A minimal workload that squares a private input — enough committed work to
/// exercise the OT/VOLE path end to end.
fn bench_square(c: &mut Criterion) {
    let wat = r#"(module (func (export "f") (param i32) (result i32)
        (i32.mul (local.get 0) (local.get 0))))"#;
    let module = Module::parse(&wat::parse_str(wat).unwrap()).unwrap();
    let wl = Workload::new(module, "f").args(vec![Arg::Secret(Value::I32(7))]);
    assert_eq!(run(&wl), Some(Value::I32(49)));

    let mut group = c.benchmark_group("zk-vm");
    group.sample_size(10);
    group.bench_function("square_i32", |b| b.iter(|| run(&wl)));
    group.finish();
}

/// Message sizes (bytes) to benchmark SHA-256 over. The headline is 4 KiB.
const SHA256_SIZES: &[usize] = &[4096];

/// SHA-256 of a private message: the guest hashes the staged bytes and reveals
/// the digest. Each size is validated once against a reference SHA-256 (proving
/// the guest + VM + reveal are correct) before being timed.
fn bench_sha256(c: &mut Criterion) {
    let wasm = include_bytes!("guests/sha256.wasm");
    let module = Module::parse(wasm).unwrap();
    // Allocate the message + digest block through the guest's canonical
    // `cabi_realloc(old_ptr, old_size, align, new_size)` export.
    let in_ptr =
        ideal_i32(&module, "cabi_realloc", vec![Value::I32(0), Value::I32(0), Value::I32(1), Value::I32(4128)]) as u32;
    let digest_ptr = in_ptr + 4096;

    let mut group = c.benchmark_group("zk-vm/sha256");
    group.sample_size(10);
    for &len in SHA256_SIZES {
        let msg: Vec<u8> = (0..len).map(|i| i as u8).collect();
        let wl = Workload::new(module.clone(), "hash")
            .private_mem(in_ptr, msg.clone())
            .args(vec![
                Arg::Public(Value::I32(in_ptr as i32)),
                Arg::Public(Value::I32(len as i32)),
            ]);

        // Validate: the revealed digest must match a reference SHA-256.
        let (_, digest) = run_reading(&wl, Some((digest_ptr, 32)));
        let expected = Sha256::digest(&msg);
        assert_eq!(
            digest.as_deref(),
            Some(expected.as_slice()),
            "revealed digest must match reference SHA-256 for {len} bytes"
        );

        group.throughput(Throughput::Bytes(len as u64));
        group.bench_with_input(BenchmarkId::from_parameter(len), &wl, |b, wl| {
            b.iter(|| run(wl))
        });
    }
    group.finish();
}

criterion_group!(benches, bench_square, bench_sha256);
criterion_main!(benches);
