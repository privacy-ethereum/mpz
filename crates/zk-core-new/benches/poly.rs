//! Polynomial-constraint prover/verifier benchmarks.
//!
//! Measures the inline `PolyContext` path: building one degree-3 constraint per
//! evaluation (`mul`/`add`/`sub` on `Expr`) plus the final masked batch check.
//! Mirrors the QuickSilver poly-mode workload (many evaluations of a fixed
//! low-degree constraint).
//!
//! Run with: `cargo bench -p mpz-zk-core-new --bench poly`

use std::time::Duration;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use mpz_circuits_new::Context;
use mpz_core::Block;
use mpz_fields::gf2_128::Gf2_128;
use mpz_ot_core::ideal::rcot::IdealRCOT;
use mpz_zk_core_new::{PolyContext, Proof, Prover, ProverVope, Verifier, VerifierVope};
use rand::{Rng, SeedableRng, rngs::StdRng};

/// Constraint degree (`d_max`) and VOPE width.
const DEGREE: usize = 3;
/// VOPE(1) correlations for the triple check's mask.
const VOPE_COST: usize = 128;
/// Tape commits: inputs `a, b, c` plus the AND gate `p`.
const COMMITS: usize = 4;

const SIZES: &[usize] = &[262_144, 1_048_576, 4_194_304];

fn sample_rcot<R: Rng>(
    rng: &mut R,
    total: usize,
) -> (Gf2_128, Vec<Gf2_128>, Vec<bool>, Vec<Gf2_128>) {
    let mut delta_block: Block = rng.random();
    delta_block.set_lsb(true);
    let seed: Block = rng.random();

    let mut rcot = IdealRCOT::new(seed, delta_block);
    rcot.alloc(total);
    rcot.flush().expect("ideal rcot flush");
    let (sender_out, receiver_out) = rcot.transfer(total).expect("ideal rcot transfer");

    (
        delta_block.into(),
        sender_out.keys.into_iter().map(Into::into).collect(),
        receiver_out.choices,
        receiver_out.msgs.into_iter().map(Into::into).collect(),
    )
}

/// One satisfied degree-3 constraint over committed wires:
/// `(a·b − p)·c == 0` (zero since `p = a·b`).
fn constraint<C: PolyContext<Field = mpz_fields::gf2::Gf2>>(
    ctx: &mut C,
    a: C::Wire,
    b: C::Wire,
    c: C::Wire,
    p: C::Wire,
) {
    let (ae, be, ce, pe) = (ctx.lift(a), ctx.lift(b), ctx.lift(c), ctx.lift(p));
    ctx.assert_zero((ae * be - pe) * ce).ok().expect("satisfied");
}

/// A degree-`DEGREE` VOPE correlation mocked from `delta`.
fn mock_poly_vope(delta: Gf2_128, rng: &mut StdRng) -> (ProverVope, VerifierVope) {
    let coeffs: Vec<Gf2_128> = (0..DEGREE).map(|_| Gf2_128::new(rng.random())).collect();
    let mut sum = Gf2_128::ZERO;
    let mut pw = Gf2_128::ONE;
    for &c in &coeffs {
        sum = sum + c * pw;
        pw = pw * delta;
    }
    (ProverVope { coeffs }, VerifierVope { sum })
}

struct Inputs {
    delta: Gf2_128,
    macs: Vec<Gf2_128>,
    keys: Vec<Gf2_128>,
    /// Adjust bits the prover produced over the main tape (fed to the verifier).
    adjust: Vec<bool>,
    vope_choices: [bool; VOPE_COST],
    vope_ev: [Gf2_128; VOPE_COST],
    vope_keys: [Gf2_128; VOPE_COST],
    poly_pv: ProverVope,
    poly_vv: VerifierVope,
    chi: [u8; 32],
    proof: Proof,
}

fn setup(n: usize) -> Inputs {
    let mut rng = StdRng::seed_from_u64(0);
    let (delta, raw_keys, choices, macs_all) = sample_rcot(&mut rng, COMMITS + VOPE_COST);

    let macs: Vec<Gf2_128> = macs_all[..COMMITS].to_vec();
    let keys: Vec<Gf2_128> = raw_keys[..COMMITS].to_vec();
    let vope_choices: [bool; VOPE_COST] = core::array::from_fn(|i| choices[COMMITS + i]);
    let vope_ev: [Gf2_128; VOPE_COST] = core::array::from_fn(|i| macs_all[COMMITS + i]);
    let vope_keys: [Gf2_128; VOPE_COST] = core::array::from_fn(|i| raw_keys[COMMITS + i]);
    let (poly_pv, poly_vv) = mock_poly_vope(delta, &mut rng);
    let chi: [u8; 32] = rng.random();

    let mut adjust: Vec<bool> = choices[..COMMITS].to_vec();
    let mut prover = Prover::new();
    {
        let mut exec = prover.execute(&mut adjust, &macs).expect("execute");
        let a = exec.input(true);
        let b = exec.input(true);
        let c = exec.input(false);
        let p = Context::mul(&mut exec, a, b);
        for _ in 0..n {
            constraint(&mut exec, a, b, c, p);
        }
        exec.finish().expect("finish");
    }
    let proof = prover.prove(chi, &vope_choices, &vope_ev, &poly_pv);

    Inputs {
        delta,
        macs,
        keys,
        adjust,
        vope_choices,
        vope_ev,
        vope_keys,
        poly_pv,
        poly_vv,
        chi,
        proof,
    }
}

fn run_prover(i: &Inputs, n: usize) {
    let mut adjust = i.adjust.clone();
    let mut prover = Prover::new();
    {
        let mut exec = prover.execute(&mut adjust, &i.macs).expect("execute");
        let a = exec.input(true);
        let b = exec.input(true);
        let c = exec.input(false);
        let p = Context::mul(&mut exec, a, b);
        for _ in 0..n {
            constraint(&mut exec, a, b, c, p);
        }
        exec.finish().expect("finish");
    }
    let _ = prover.prove(i.chi, &i.vope_choices, &i.vope_ev, &i.poly_pv);
}

fn run_verifier(i: &Inputs, n: usize) {
    let mut verifier = Verifier::new(i.delta);
    {
        let mut exec = verifier.execute(&i.keys, &i.adjust).expect("execute");
        let a = exec.input();
        let b = exec.input();
        let c = exec.input();
        let p = Context::mul(&mut exec, a, b);
        for _ in 0..n {
            constraint(&mut exec, a, b, c, p);
        }
        exec.finish().expect("finish");
    }
    verifier
        .verify(i.chi, &i.vope_keys, &i.poly_vv, i.proof.clone())
        .expect("verify");
}

fn bench_poly(c: &mut Criterion) {
    for &n in SIZES {
        let inputs = setup(n);

        let mut pg = c.benchmark_group("poly_prover");
        pg.sample_size(10);
        pg.measurement_time(Duration::from_secs(8));
        pg.throughput(Throughput::Elements(n as u64));
        pg.bench_with_input(BenchmarkId::from_parameter(n), &n, |bch, &n| {
            bch.iter(|| run_prover(&inputs, n));
        });
        pg.finish();

        let mut vg = c.benchmark_group("poly_verifier");
        vg.sample_size(10);
        vg.measurement_time(Duration::from_secs(8));
        vg.throughput(Throughput::Elements(n as u64));
        vg.bench_with_input(BenchmarkId::from_parameter(n), &n, |bch, &n| {
            bch.iter(|| run_verifier(&inputs, n));
        });
        vg.finish();
    }
}

criterion_group!(benches, bench_poly);
criterion_main!(benches);
