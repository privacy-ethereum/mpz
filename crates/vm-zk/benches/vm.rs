//! Benchmark harness for the zk-vm over a real OT stack.
//!
//! Each measured iteration proves SHA-256 of a private message end to end
//! through the [`Prover`]/[`Verifier`] pair, with correlated randomness drawn
//! from a real `CO15 -> SoftSpoken -> Ferret` RCOT stack (Chou-Orlandi base OT,
//! SoftSpoken extension, Ferret expansion) rather than an ideal functionality —
//! so the measurement reflects the cost of the actual protocol, including
//! OT/VOLE generation.

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use futures::executor::block_on;
use mpz_common::{Context, context::test_mt_context, executor::Executor};
use mpz_core::Block;
use mpz_ot::{chou_orlandi, ferret, softspoken};
use mpz_vm_core::{Param, Vm, Write, value::Value};
use mpz_vm_ir::{ExportKind, Module};
use mpz_vm_zk::{Prover, Verifier};
use rand::{Rng, SeedableRng, rngs::StdRng};
use sha2::{Digest, Sha256};

/// The prover's RCOT receiver: Ferret over SoftSpoken over a Chou-Orlandi base
/// OT.
type ProverSvole = ferret::Receiver<softspoken::Receiver<chou_orlandi::Sender>>;
/// The verifier's RCOT sender: Ferret over SoftSpoken over a Chou-Orlandi base
/// OT.
type VerifierSvole = ferret::Sender<softspoken::Sender<chou_orlandi::Receiver>>;

/// Builds the real RCOT stack for both parties from `seed`.
///
/// The verifier is the RCOT sender and holds the correlation `delta` (its lsb
/// forced to 1, as the zk-vm requires); the prover is the RCOT receiver. The
/// base-OT roles are swapped relative to the extension: the verifier's
/// SoftSpoken sender is bootstrapped by a Chou-Orlandi receiver, the prover's
/// SoftSpoken receiver by a Chou-Orlandi sender.
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
        softspoken::Receiver::new(
            softspoken::ReceiverConfig::default(),
            chou_orlandi::Sender::new(),
        ),
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

/// The long-lived transport between the parties: a multithreaded executor
/// pair and one context per side. Created once and reused across iterations
/// so worker-pool spawn/teardown stays out of the measurement; everything
/// cryptographic (base OT, SoftSpoken, Ferret, prover/verifier state) is
/// rebuilt inside each iteration so the measured time stays end-to-end.
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

/// SHA-256 digest length, in bytes.
const DIGEST_LEN: usize = 32;

/// Proves SHA-256 over the private `msg` end to end and returns the revealed
/// digest. Allocates the message buffer in-guest via `cabi_realloc`, stages the
/// message privately, calls the guest export `func` (either `hash`, which
/// compresses in wasm, or `hash_precompile`, which compresses through the host
/// `sha256_compress` precompile), and reads the digest back at the pointer the
/// call returns. Panics if the two sides disagree.
///
/// The whole crypto stack is rebuilt here — only `session`'s executors and
/// contexts are reused — so the measured time stays end-to-end.
fn prove_sha256(module: &Module, msg: &[u8], session: &mut Session, func: &str) -> Vec<u8> {
    let (v_svole, p_svole) = rcot_stack(0);
    let mut prover = Prover::new(module.clone(), p_svole).unwrap();
    let mut verifier = Verifier::new(module.clone(), v_svole).unwrap();
    let Session { ctx_p, ctx_v, .. } = session;

    // Allocate the message buffer inside the running VM via the guest's
    // `cabi_realloc` export, then stage the message privately at the returned
    // pointer. Allocating in the measured instance grows memory so the region is
    // always in bounds and exercises the real allocator.
    let realloc = func_idx(module, "cabi_realloc");
    let alloc_args = || {
        vec![
            Param::Public(Value::I32(0)),
            Param::Public(Value::I32(0)),
            Param::Public(Value::I32(1)),
            Param::Public(Value::I32(msg.len() as i32)),
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
    prover.write(ptr, Write::Private(msg)).unwrap();
    verifier.write(ptr, Write::Blind(msg.len())).unwrap();

    // `func(ptr, len)` returns the address of the revealed digest.
    let hash = func_idx(module, func);
    let hash_args = || {
        vec![
            Param::Public(Value::I32(ptr as i32)),
            Param::Public(Value::I32(msg.len() as i32)),
        ]
    };
    let (rp, rv) = call_both(
        &mut prover,
        &mut verifier,
        ctx_p,
        ctx_v,
        hash,
        hash_args(),
        hash_args(),
    );
    assert_eq!(rp, rv, "prover and verifier results must agree");
    let digest_ptr = match rp {
        Some(Value::I32(p)) => p as u32,
        other => panic!("hash returned {other:?}"),
    };
    verifier.read(digest_ptr, DIGEST_LEN).unwrap().to_vec()
}

/// Installs a tracing subscriber when `RUST_LOG` is set that prints, on each
/// span's close, its `time.busy`/`time.idle` wall-clock alongside the full
/// span scope (`chunk:allocate:ferret.flush`, etc.) and recorded fields — the
/// per-stage proving profile. A no-op (no subscriber, zero span cost) when
/// `RUST_LOG` is unset, so a plain `cargo bench` measures undisturbed
/// throughput.
///
/// For a profile run:
/// `RUST_LOG=mpz_vm_zk=debug,mpz_ot=debug cargo bench -p mpz-vm-zk --bench vm`.
/// The prover and verifier run on separate threads into one subscriber; their
/// close lines carry the `role`/target so the two sides stay distinguishable,
/// or narrow to one with a target filter (e.g. `mpz_vm_zk::prover=debug`).
/// Absolute throughput numbers should be read from a run with `RUST_LOG` unset.
fn init_tracing() {
    use tracing_subscriber::{EnvFilter, fmt::format::FmtSpan};

    let Ok(filter) = EnvFilter::try_from_default_env() else {
        return;
    };
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_span_events(FmtSpan::CLOSE)
        .with_target(true)
        .with_writer(std::io::stderr)
        .try_init();
}

/// Message sizes (bytes) to benchmark SHA-256 over. The headline is 4 KiB.
const SHA256_SIZES: &[usize] = &[4096, 16384];

/// SHA-256 proving variants: `wasm` compresses each block with guest
/// instructions, `precompile` compresses through the host `sha256_compress`
/// precompile (the per-block compression circuit, no guest gates).
const SHA256_VARIANTS: &[(&str, &str)] = &[("wasm", "hash"), ("precompile", "hash_precompile")];

/// Proves SHA-256 of a private message end to end, for both the wasm and
/// precompile variants. Each (variant, size) is validated once against a
/// reference SHA-256 (proving the guest + VM + reveal are correct) before being
/// timed.
fn bench_sha256(c: &mut Criterion) {
    init_tracing();
    let wasm = include_bytes!("guests/sha256.wasm");
    let module = Module::parse(wasm).unwrap();

    let mut session = Session::new();
    let mut group = c.benchmark_group("zk-vm/sha256");
    group.sample_size(10);
    for &len in SHA256_SIZES {
        let msg: Vec<u8> = (0..len).map(|i| i as u8).collect();
        for &(label, func) in SHA256_VARIANTS {
            // Validate the revealed digest against a reference before timing.
            let digest = prove_sha256(&module, &msg, &mut session, func);
            assert_eq!(
                digest,
                Sha256::digest(&msg).as_slice(),
                "{label} variant digest must match reference SHA-256 for {len} bytes"
            );

            group.throughput(Throughput::Bytes(len as u64));
            group.bench_with_input(BenchmarkId::new(label, len), &msg, |b, msg| {
                b.iter(|| prove_sha256(&module, msg, &mut session, func))
            });
        }
    }
    group.finish();
}

criterion_group!(benches, bench_sha256);
criterion_main!(benches);
