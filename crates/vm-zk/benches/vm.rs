//! Benchmark harness for the zk-vm over a real OT stack.
//!
//! Each measured iteration runs a wasm module end to end through the
//! [`Prover`]/[`Verifier`] pair, with correlated randomness drawn from a real
//! `CO15 -> KOS -> Ferret` RCOT stack (Chou-Orlandi base OT, KOS extension,
//! Ferret expansion) rather than an ideal functionality — so the measurement
//! reflects the cost of the actual protocol, including OT/VOLE generation.
//!
//! The harness is module-agnostic: describe a [`Workload`] (a module, an
//! exported function, an optional private input buffer, and arguments) and
//! bench it. The headline workload is SHA-256 of a 4 KiB message.

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use futures::executor::block_on;
use mpz_common::{Context, context::test_mt_context, executor::Executor};
use mpz_core::Block;
use mpz_ot::{chou_orlandi, ferret, kos};
use mpz_vm_core::{Param, Vm, Write, value::Value};
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
        kos::Sender::new(
            kos::SenderConfig::default(),
            delta,
            chou_orlandi::Receiver::new(),
        ),
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
    /// Optional private input as `(bytes, alloc_size)`. Before the call the
    /// harness allocates `alloc_size` bytes through the guest's `cabi_realloc`
    /// export, stages `bytes` there privately, and passes the resulting pointer
    /// as `func`'s first argument. `alloc_size` may exceed `bytes.len()` to
    /// cover scratch the guest writes past the input (e.g. the digest).
    input: Option<(Vec<u8>, u32)>,
    args: Vec<Arg>,
    chunk_cap: Option<usize>,
    segment_cost: Option<usize>,
}

impl Workload {
    fn new(module: Module, func_name: &str) -> Self {
        let func = func_idx(&module, func_name);
        Self {
            module,
            func,
            input: None,
            args: Vec::new(),
            chunk_cap: None,
            segment_cost: None,
        }
    }

    fn input(mut self, bytes: Vec<u8>, alloc_size: u32) -> Self {
        self.input = Some((bytes, alloc_size));
        self
    }

    fn args(mut self, args: Vec<Arg>) -> Self {
        self.args = args;
        self
    }

    fn segment_cost(mut self, cost: Option<usize>) -> Self {
        self.segment_cost = cost;
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

/// The long-lived transport between the parties: a multithreaded executor
/// pair and one context per side. Created once and reused across iterations
/// so worker-pool spawn/teardown stays out of the measurement; everything
/// cryptographic (base OT, KOS, Ferret, prover/verifier state) is rebuilt
/// inside each iteration so the measured time stays end-to-end.
struct Session {
    exec_p: Executor,
    exec_v: Executor,
    ctx_p: Context,
    ctx_v: Context,
}

impl Session {
    fn new() -> Self {
        let (exec_p, exec_v) = test_mt_context(32 << 20);
        let ctx_p = exec_p.new_context().unwrap();
        let ctx_v = exec_v.new_context().unwrap();
        Self {
            exec_p,
            exec_v,
            ctx_p,
            ctx_v,
        }
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.exec_p.shutdown();
        self.exec_v.shutdown();
    }
}

/// Drives one `call` on the prover and verifier concurrently and returns their
/// results. The two parties exchange messages during a call, so both must run
/// together; they execute on separate OS threads, as in a real deployment.
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

/// Runs the workload once through the prover/verifier over the real OT stack,
/// optionally reading back a memory range (offset relative to the input buffer)
/// from the verifier afterwards. Panics if the two sides disagree.
///
/// The whole crypto stack is built from scratch — only `session`'s executors
/// and contexts are reused.
fn run_reading(
    wl: &Workload,
    read: Option<(u32, usize)>,
    session: &mut Session,
) -> (Option<Value>, Option<Vec<u8>>) {
    let (v_svole, p_svole) = rcot_stack(0);
    let mut prover = Prover::new(wl.module.clone(), p_svole)
        .unwrap()
        .with_chunk_cap(wl.chunk_cap)
        .with_segment_cost(wl.segment_cost);
    let mut verifier = Verifier::new(wl.module.clone(), v_svole)
        .unwrap()
        .with_chunk_cap(wl.chunk_cap)
        .with_segment_cost(wl.segment_cost);

    let Session { ctx_p, ctx_v, .. } = session;

    // If the workload has a private input, allocate space for it inside the
    // running VM via the guest's `cabi_realloc` export, then stage the bytes at
    // the returned pointer. Allocating in the measured instance — rather than
    // discovering an address out of band — lets `cabi_realloc` grow memory so
    // the staged region is always in bounds, and exercises the real allocator.
    let in_ptr = if let Some((bytes, size)) = &wl.input {
        let realloc = func_idx(&wl.module, "cabi_realloc");
        let alloc_args = || {
            vec![
                Param::Public(Value::I32(0)),
                Param::Public(Value::I32(0)),
                Param::Public(Value::I32(1)),
                Param::Public(Value::I32(*size as i32)),
            ]
        };
        let (rp, rv) = call_both(
            &mut prover,
            &mut verifier,
            ctx_p,
            ctx_v,
            realloc,
            alloc_args(),
            alloc_args(),
        );
        assert_eq!(
            rp, rv,
            "cabi_realloc must return the same pointer on both sides"
        );
        let ptr = match rp {
            Some(Value::I32(p)) => p as u32,
            other => panic!("cabi_realloc returned {other:?}"),
        };
        prover.write(ptr, Write::Private(bytes)).unwrap();
        verifier.write(ptr, Write::Blind(bytes.len())).unwrap();
        ptr
    } else {
        0
    };

    // Build params, prepending the input pointer when one was allocated.
    let mut p_params = Vec::new();
    let mut v_params = Vec::new();
    if wl.input.is_some() {
        p_params.push(Param::Public(Value::I32(in_ptr as i32)));
        v_params.push(Param::Public(Value::I32(in_ptr as i32)));
    }
    for a in &wl.args {
        match a {
            Arg::Secret(v) => {
                p_params.push(Param::Private(*v));
                v_params.push(Param::Blind(v.ty()));
            }
            Arg::Public(v) => {
                p_params.push(Param::Public(*v));
                v_params.push(Param::Public(*v));
            }
        }
    }

    let (rp, rv) = call_both(
        &mut prover,
        &mut verifier,
        ctx_p,
        ctx_v,
        wl.func,
        p_params,
        v_params,
    );

    assert_eq!(rp, rv, "prover and verifier results must agree");
    let bytes = read.map(|(off, len)| verifier.read(in_ptr + off, len).unwrap().to_vec());
    (rp, bytes)
}

fn run(wl: &Workload, session: &mut Session) -> Option<Value> {
    run_reading(wl, None, session).0
}

/// A minimal workload that squares a private input — enough committed work to
/// exercise the OT/VOLE path end to end.
fn bench_square(c: &mut Criterion) {
    let wat = r#"(module (func (export "f") (param i32) (result i32)
        (i32.mul (local.get 0) (local.get 0))))"#;
    let module = Module::parse(&wat::parse_str(wat).unwrap()).unwrap();
    let wl = Workload::new(module, "f").args(vec![Arg::Secret(Value::I32(7))]);
    let mut session = Session::new();
    assert_eq!(run(&wl, &mut session), Some(Value::I32(49)));

    let mut group = c.benchmark_group("zk-vm");
    group.sample_size(10);
    group.bench_function("square_i32", |b| b.iter(|| run(&wl, &mut session)));
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

    // Segment-cost variants: None proves each chunk sequentially; the others
    // split it into parallel segments of roughly that many gate bits.
    const SEGMENT_COSTS: &[(Option<usize>, &str)] = &[
        (None, "seq"),
        (Some(400_000), "seg400k"),
        (Some(100_000), "seg100k"),
        (Some(25_000), "seg25k"),
    ];

    let mut session = Session::new();
    let mut group = c.benchmark_group("zk-vm/sha256");
    group.sample_size(10);
    for &len in SHA256_SIZES {
        let msg: Vec<u8> = (0..len).map(|i| i as u8).collect();
        for &(cost, tag) in SEGMENT_COSTS {
            // Allocate a 4 KiB message region plus the 32-byte digest; the
            // harness prepends the buffer pointer, so `hash` receives
            // `(ptr, len)`.
            let wl = Workload::new(module.clone(), "hash")
                .input(msg.clone(), 4128)
                .args(vec![Arg::Public(Value::I32(len as i32))])
                .segment_cost(cost);

            // Validate: the revealed digest (4 KiB into the buffer) must match
            // a reference SHA-256.
            let (_, digest) = run_reading(&wl, Some((4096, 32)), &mut session);
            let expected = Sha256::digest(&msg);
            assert_eq!(
                digest.as_deref(),
                Some(expected.as_slice()),
                "revealed digest must match reference SHA-256 for {len} bytes"
            );

            group.throughput(Throughput::Bytes(len as u64));
            group.bench_with_input(BenchmarkId::new(tag, len), &wl, |b, wl| {
                b.iter(|| run(wl, &mut session))
            });
        }
    }
    group.finish();
}

criterion_group!(benches, bench_square, bench_sha256);
criterion_main!(benches);
