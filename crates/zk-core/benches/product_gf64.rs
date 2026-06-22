//! Accelerated permutation-product argument over `GF(2^64)`.
//!
//! Permutation/lookup arguments reduce to a grand product over the committed
//! memory tuples `eᵢ` and a public challenge `r`:
//!
//! ```text
//!   p(r) = ∏_{i=1}^{M} (eᵢ + r)
//! ```
//!
//! The gate-by-gate evaluation commits every running product, costing one
//! authenticated value per entry. The accelerated method (SpeakUp,
//! "Accelerating permutation products") splits the entries into chunks of
//! `d − 1` and verifies each chunk as a single **degree-`d` QuickSilver
//! constraint**
//!
//! ```text
//!   acc_k − acc_{k-1} · ∏_{i ∈ chunk k} (eᵢ + r) = 0
//! ```
//!
//! committing only the chunk-boundary partial products `acc_k`. Amortized cost
//! per entry drops from `κ` to `κ / (d − 1)` sVOLEs. This is exactly the
//! `GF(2^64)` polynomial-constraint path ([`PolyContext`]): `eᵢ` and `acc_k`
//! are committed wires, `r` is a public constant, and each chunk is one
//! degree-`d` `assert_zero`.
//!
//! The benchmark runs chunk sizes `c ∈ {1, 3, 7, 15, 31}` (degrees 2, 4, 8,
//! 16, 32) so the amortization is visible: larger chunks commit fewer partial
//! products but fold higher-degree constraints.
//!
//! Run with: `cargo bench -p mpz-zk-core --bench product_gf64`

use std::time::Duration;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use mpz_fields::{ExtensionField, gf2_64::Gf2_64, gf2_128::Gf2_128};
use mpz_zk_core::{
    DeltaPowers, PolyContext, Proof, ProverOutput, VerifierOutput,
    gf64::{Auth64, Commit, Prover, Verifier},
    poly::Expr,
};
use rand::{Rng, SeedableRng, rngs::StdRng};
use rand_chacha::ChaCha12Rng;
use typenum::U0;

/// Total number of entries. Chunks tile `⌊M / c⌋·c` entries; any short tail
/// (at most `c − 1` entries) is committed but unconstrained.
const M: usize = 32_768;

/// Subfield injection `GF(2^64) ↪ GF(2^128)`.
fn embed(v: Gf2_64) -> Gf2_128 {
    <Gf2_128 as ExtensionField<Gf2_64>>::embed(v)
}

// ===========================================================================
// Chunked product constraints
// ===========================================================================

/// One chunk size of the product argument: `C` entries per chunk, verified as
/// a degree-`D = C + 1` constraint.
trait Chunk {
    /// Entries per chunk.
    const C: usize;
    /// Constraint degree `C + 1` (the proof's `d_max`).
    const D: usize;

    /// Emits `acc_out − acc_in · ∏(eᵢ + r) = 0` for one chunk.
    fn constrain<Ctx>(
        ctx: &mut Ctx,
        acc_in: Ctx::Wire,
        entries: &[Ctx::Wire],
        r: Expr<Ctx::Coeffs, U0>,
        acc_out: Ctx::Wire,
    ) where
        Ctx: PolyContext<Field = Gf2_64>,
        Ctx::Error: std::fmt::Debug;
}

/// Gate-by-gate baseline: one factor per chunk, degree 2.
struct Chunk1;
impl Chunk for Chunk1 {
    const C: usize = 1;
    const D: usize = 2;
    fn constrain<Ctx>(
        ctx: &mut Ctx,
        acc_in: Ctx::Wire,
        e: &[Ctx::Wire],
        r: Expr<Ctx::Coeffs, U0>,
        acc_out: Ctx::Wire,
    ) where
        Ctx: PolyContext<Field = Gf2_64>,
        Ctx::Error: std::fmt::Debug,
    {
        let p = ctx.lift(e[0]) + r;
        let term = ctx.lift(acc_in) * p;
        ctx.assert_zero(term - ctx.lift(acc_out)).expect("chunk");
    }
}

/// Degree-4 chunk: three factors.
struct Chunk3;
impl Chunk for Chunk3 {
    const C: usize = 3;
    const D: usize = 4;
    fn constrain<Ctx>(
        ctx: &mut Ctx,
        acc_in: Ctx::Wire,
        e: &[Ctx::Wire],
        r: Expr<Ctx::Coeffs, U0>,
        acc_out: Ctx::Wire,
    ) where
        Ctx: PolyContext<Field = Gf2_64>,
        Ctx::Error: std::fmt::Debug,
    {
        let p = (ctx.lift(e[0]) + r) * (ctx.lift(e[1]) + r) * (ctx.lift(e[2]) + r);
        let term = ctx.lift(acc_in) * p;
        ctx.assert_zero(term - ctx.lift(acc_out)).expect("chunk");
    }
}

/// Degree-8 chunk: seven factors.
struct Chunk7;
impl Chunk for Chunk7 {
    const C: usize = 7;
    const D: usize = 8;
    fn constrain<Ctx>(
        ctx: &mut Ctx,
        acc_in: Ctx::Wire,
        e: &[Ctx::Wire],
        r: Expr<Ctx::Coeffs, U0>,
        acc_out: Ctx::Wire,
    ) where
        Ctx: PolyContext<Field = Gf2_64>,
        Ctx::Error: std::fmt::Debug,
    {
        let p = (ctx.lift(e[0]) + r)
            * (ctx.lift(e[1]) + r)
            * (ctx.lift(e[2]) + r)
            * (ctx.lift(e[3]) + r)
            * (ctx.lift(e[4]) + r)
            * (ctx.lift(e[5]) + r)
            * (ctx.lift(e[6]) + r);
        let term = ctx.lift(acc_in) * p;
        ctx.assert_zero(term - ctx.lift(acc_out)).expect("chunk");
    }
}

/// Degree-16 chunk: fifteen factors.
struct Chunk15;
impl Chunk for Chunk15 {
    const C: usize = 15;
    const D: usize = 16;
    fn constrain<Ctx>(
        ctx: &mut Ctx,
        acc_in: Ctx::Wire,
        e: &[Ctx::Wire],
        r: Expr<Ctx::Coeffs, U0>,
        acc_out: Ctx::Wire,
    ) where
        Ctx: PolyContext<Field = Gf2_64>,
        Ctx::Error: std::fmt::Debug,
    {
        let p = (ctx.lift(e[0]) + r)
            * (ctx.lift(e[1]) + r)
            * (ctx.lift(e[2]) + r)
            * (ctx.lift(e[3]) + r)
            * (ctx.lift(e[4]) + r)
            * (ctx.lift(e[5]) + r)
            * (ctx.lift(e[6]) + r)
            * (ctx.lift(e[7]) + r)
            * (ctx.lift(e[8]) + r)
            * (ctx.lift(e[9]) + r)
            * (ctx.lift(e[10]) + r)
            * (ctx.lift(e[11]) + r)
            * (ctx.lift(e[12]) + r)
            * (ctx.lift(e[13]) + r)
            * (ctx.lift(e[14]) + r);
        let term = ctx.lift(acc_in) * p;
        ctx.assert_zero(term - ctx.lift(acc_out)).expect("chunk");
    }
}

/// Degree-32 chunk: thirty-one factors.
struct Chunk31;
impl Chunk for Chunk31 {
    const C: usize = 31;
    const D: usize = 32;
    fn constrain<Ctx>(
        ctx: &mut Ctx,
        acc_in: Ctx::Wire,
        e: &[Ctx::Wire],
        r: Expr<Ctx::Coeffs, U0>,
        acc_out: Ctx::Wire,
    ) where
        Ctx: PolyContext<Field = Gf2_64>,
        Ctx::Error: std::fmt::Debug,
    {
        // ∏_{i=0}^{30} (e_i + r), degree 31, then × acc_in for degree 32.
        // Each `*` raises the degree by one, so the running type is
        // `Expr<_, U_{j+1}>`; the rebindings let the compile-time degrees flow.
        let p = ctx.lift(e[0]) + r;
        let p = p * (ctx.lift(e[1]) + r);
        let p = p * (ctx.lift(e[2]) + r);
        let p = p * (ctx.lift(e[3]) + r);
        let p = p * (ctx.lift(e[4]) + r);
        let p = p * (ctx.lift(e[5]) + r);
        let p = p * (ctx.lift(e[6]) + r);
        let p = p * (ctx.lift(e[7]) + r);
        let p = p * (ctx.lift(e[8]) + r);
        let p = p * (ctx.lift(e[9]) + r);
        let p = p * (ctx.lift(e[10]) + r);
        let p = p * (ctx.lift(e[11]) + r);
        let p = p * (ctx.lift(e[12]) + r);
        let p = p * (ctx.lift(e[13]) + r);
        let p = p * (ctx.lift(e[14]) + r);
        let p = p * (ctx.lift(e[15]) + r);
        let p = p * (ctx.lift(e[16]) + r);
        let p = p * (ctx.lift(e[17]) + r);
        let p = p * (ctx.lift(e[18]) + r);
        let p = p * (ctx.lift(e[19]) + r);
        let p = p * (ctx.lift(e[20]) + r);
        let p = p * (ctx.lift(e[21]) + r);
        let p = p * (ctx.lift(e[22]) + r);
        let p = p * (ctx.lift(e[23]) + r);
        let p = p * (ctx.lift(e[24]) + r);
        let p = p * (ctx.lift(e[25]) + r);
        let p = p * (ctx.lift(e[26]) + r);
        let p = p * (ctx.lift(e[27]) + r);
        let p = p * (ctx.lift(e[28]) + r);
        let p = p * (ctx.lift(e[29]) + r);
        let p = p * (ctx.lift(e[30]) + r);
        let term = ctx.lift(acc_in) * p;
        ctx.assert_zero(term - ctx.lift(acc_out)).expect("chunk");
    }
}

/// Walks the whole product: wires are `[e_0..e_{M-1}, acc_0..acc_{n_chunks}]`
/// with `acc_0 = 1`, and chunk `k` constrains `acc_{k+1}` against `acc_k`.
fn eval<Ch, Ctx>(ctx: &mut Ctx, wires: &[Ctx::Wire], r: Gf2_64)
where
    Ch: Chunk,
    Ctx: PolyContext<Field = Gf2_64>,
    Ctx::Error: std::fmt::Debug,
{
    let r_expr = ctx.lift_const(r);
    let n_chunks = M / Ch::C;
    for k in 0..n_chunks {
        let entries = &wires[k * Ch::C..k * Ch::C + Ch::C];
        Ch::constrain(ctx, wires[M + k], entries, r_expr, wires[M + k + 1]);
    }
}

// ===========================================================================
// Harness
// ===========================================================================

/// The satisfying witness: `M` random entries followed by the `n_chunks + 1`
/// partial products `acc_0 = 1, acc_k = acc_{k-1}·∏(eᵢ + r)`.
fn witness<Ch: Chunk>(rng: &mut StdRng) -> (Vec<Gf2_64>, Gf2_64) {
    let r = Gf2_64(rng.random());
    let entries: Vec<Gf2_64> = (0..M).map(|_| Gf2_64(rng.random())).collect();

    let n_chunks = M / Ch::C;
    let mut acc = vec![Gf2_64::ONE; n_chunks + 1];
    for k in 0..n_chunks {
        let mut prod = Gf2_64::ONE;
        for j in 0..Ch::C {
            prod = prod * (entries[k * Ch::C + j] + r);
        }
        acc[k + 1] = acc[k] * prod;
    }

    let mut values = entries;
    values.extend(acc);
    (values, r)
}

struct Inputs {
    delta: Gf2_128,
    d_max: usize,
    r: Gf2_64,
    /// Cleartext committed values (for the commit pass).
    values: Vec<Gf2_64>,
    /// Prover input wires (value + raw MAC).
    mac_wires: Vec<Auth64>,
    /// Verifier input wires (adjusted keys).
    key_wires: Vec<Gf2_128>,
    chi: [u8; 32],
    powers: DeltaPowers,
    poly_vope_sum: Gf2_128,
    coefficients: Vec<Gf2_128>,
}

fn setup<Ch: Chunk>() -> Inputs {
    let mut rng = StdRng::seed_from_u64(0x9_0d);
    let (values, r) = witness::<Ch>(&mut rng);
    let n = values.len();
    let delta = Gf2_128::new(rng.random());
    let d_max = Ch::D;

    // Subfield sVOLE: choice ∈ GF(2^64), key ∈ GF(2^128),
    // mac = key + embed(choice)·Δ.
    let choices: Vec<Gf2_64> = (0..n).map(|_| Gf2_64(rng.random())).collect();
    let keys: Vec<Gf2_128> = (0..n).map(|_| Gf2_128::new(rng.random())).collect();
    let mac_wires: Vec<Auth64> = (0..n)
        .map(|i| Auth64 {
            value: values[i],
            mac: keys[i] + embed(choices[i]) * delta,
        })
        .collect();
    let key_wires: Vec<Gf2_128> = (0..n)
        .map(|i| keys[i] + embed(values[i] + choices[i]) * delta)
        .collect();

    // Mock degree-`d_max` polynomial-check VOPE.
    let powers = DeltaPowers::new(delta);
    let poly_masks: Vec<Gf2_128> = (0..d_max).map(|_| Gf2_128::new(rng.random())).collect();
    let mut poly_vope_sum = Gf2_128::new(0);
    let mut pw = Gf2_128::new(1);
    for &m in &poly_masks {
        poly_vope_sum = poly_vope_sum + m * pw;
        pw = pw * delta;
    }

    // Fiat–Shamir challenge stream seed, shared by setup and the benched runs.
    let chi: [u8; 32] = rng.random();

    // One prover run to produce the masked coefficients.
    let mut commit = Commit::new(&mut []);
    eval::<Ch, _>(&mut commit, &values, r);
    commit.finish().expect("commit finish");
    let mut prover = Prover::committed(&[]).accumulate(ChaCha12Rng::from_seed(chi));
    eval::<Ch, _>(&mut prover, &mac_wires, r);
    let ProverOutput { poly, .. } = prover.finish().expect("accumulate finish");
    let coefficients: Vec<Gf2_128> = poly
        .coefficients(d_max)
        .expect("coefficients")
        .into_iter()
        .zip(&poly_masks)
        .map(|(c, &m)| c + m)
        .collect();

    Inputs {
        delta,
        d_max,
        r,
        values,
        mac_wires,
        key_wires,
        chi,
        powers,
        poly_vope_sum,
        coefficients,
    }
}

fn run_prover<Ch: Chunk>(inputs: &Inputs) {
    let mut commit = Commit::new(&mut []);
    eval::<Ch, _>(&mut commit, &inputs.values, inputs.r);
    commit.finish().expect("commit finish");

    let mut prover = Prover::committed(&[]).accumulate(ChaCha12Rng::from_seed(inputs.chi));
    eval::<Ch, _>(&mut prover, &inputs.mac_wires, inputs.r);
    let ProverOutput { u, v, poly, assertions } = prover.finish().expect("accumulate finish");

    let coefficients: Vec<Gf2_128> = poly.coefficients(inputs.d_max).expect("coefficients");
    let _proof = Proof {
        assertions,
        u,
        v,
        coefficients,
    };
}

fn run_verifier<Ch: Chunk>(inputs: &Inputs) {
    let verifier = Verifier::new(inputs.delta, &[], &[]).expect("new");
    let mut verifier = verifier.accumulate(ChaCha12Rng::from_seed(inputs.chi));
    eval::<Ch, _>(&mut verifier, &inputs.key_wires, inputs.r);
    let VerifierOutput { poly, .. } = verifier.finish().expect("finish");

    poly.check(&inputs.powers, &inputs.coefficients, inputs.poly_vope_sum)
        .expect("poly check");
}

fn bench_one<Ch: Chunk>(c: &mut Criterion, label: &str) {
    let inputs = setup::<Ch>();

    let mut pg = c.benchmark_group("product_prover");
    pg.sample_size(10);
    pg.measurement_time(Duration::from_secs(10));
    pg.throughput(Throughput::Elements(M as u64));
    pg.bench_function(BenchmarkId::new("chunk", label), |b| {
        b.iter(|| run_prover::<Ch>(&inputs))
    });
    pg.finish();

    let mut vg = c.benchmark_group("product_verifier");
    vg.sample_size(10);
    vg.measurement_time(Duration::from_secs(10));
    vg.throughput(Throughput::Elements(M as u64));
    vg.bench_function(BenchmarkId::new("chunk", label), |b| {
        b.iter(|| run_verifier::<Ch>(&inputs))
    });
    vg.finish();
}

fn bench_product(c: &mut Criterion) {
    bench_one::<Chunk1>(c, "1_deg2");
    bench_one::<Chunk3>(c, "3_deg4");
    bench_one::<Chunk7>(c, "7_deg8");
    bench_one::<Chunk15>(c, "15_deg16");
    bench_one::<Chunk31>(c, "31_deg32");
}

criterion_group!(benches, bench_product);
criterion_main!(benches);
