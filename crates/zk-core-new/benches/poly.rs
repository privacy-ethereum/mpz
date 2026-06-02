//! Polynomial-constraint prover/verifier benchmark, on the **same circuit as
//! the PR** (`poly-proof-core`): the 12 CPU-step fixtures, weighted by the same
//! per-step instantiation counts (~232 evals/step), `num_evals = 100k × 232`.
//!
//! The fixtures are ported to the operator-based `PolyContext::Expr` API and run
//! over `Gf2_128` (our target MAC field; the PR benched `Gf2_64`). Witnesses are
//! satisfied (all-zero bits, except `mul_force`'s output) so the arithmetic and
//! `assert_zero` path are exercised exactly as in a real proof.
//!
//! Run with: `cargo bench -p mpz-zk-core-new --bench poly`

use std::ops::{Add, Mul};
use std::time::Duration;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use mpz_fields::{gf2::Gf2, gf2_128::Gf2_128};
use mpz_zk_core_new::{PolyContext, Proof, Prover, ProverVope, Verifier, VerifierVope};
use rand::{Rng, SeedableRng, rngs::StdRng};

/// `100_000` CPU steps × 232 constraint evaluations/step.
const NUM_STEPS: usize = 100_000;
/// Per-step instantiation counts (PR `add_step_constraints`).
const COUNTS: [usize; 12] = [32, 32, 31, 1, 20, 32, 1, 1, 32, 20, 12, 18];
/// Per-fixture variable counts.
const NUM_VARS: [usize; 12] = [5, 4, 13, 14, 6, 4, 38, 3, 6, 8, 6, 4];
/// Maximum constraint degree across the fixtures (`write_back`,
/// `write_back_bit0`, `mul_bit_extraction` are degree 6).
const D_MAX: usize = 6;

// --- fixtures, ported to operator-based `PolyContext::Expr` -----------------

fn add_all<E: Copy + Add<Output = E>>(items: &[E]) -> E {
    let mut acc = items[0];
    for &x in &items[1..] {
        acc = acc + x;
    }
    acc
}

/// 2-to-1 MUX: `a + sel·(a + b)`.
fn mux<E: Copy + Add<Output = E> + Mul<Output = E>>(sel: E, a: E, b: E) -> E {
    a + sel * (a + b)
}

fn carry_generate<C: PolyContext<Field = Gf2>>(c: &mut C, w: &[C::Wire]) -> Result<(), C::Error> {
    let (y, a, b, cc, f) = (
        c.lift(w[0]),
        c.lift(w[1]),
        c.lift(w[2]),
        c.lift(w[3]),
        c.lift(w[4]),
    );
    c.assert_zero(y + (a + cc) * (b * f + cc))
}

fn carry_chain<C: PolyContext<Field = Gf2>>(c: &mut C, w: &[C::Wire]) -> Result<(), C::Error> {
    let (y, g, cc, e) = (c.lift(w[0]), c.lift(w[1]), c.lift(w[2]), c.lift(w[3]));
    c.assert_zero(y + (g + cc) * e)
}

fn write_back<C: PolyContext<Field = Gf2>>(c: &mut C, w: &[C::Wire]) -> Result<(), C::Error> {
    let l: Vec<C::Expr> = w.iter().map(|&x| c.lift(x)).collect();
    let (y, o, ww, s, q, v, h, big_b, g, a, b, cc, f) = (
        l[0], l[1], l[2], l[3], l[4], l[5], l[6], l[7], l[8], l[9], l[10], l[11], l[12],
    );
    let q_inner = q * add_all(&[g, a, b * f, cc]);
    let chain = add_all(&[g, v, q_inner]);
    let alu = chain + h * (chain + big_b);
    let w_inner = ww * add_all(&[o, alu, s * alu]);
    c.assert_zero(add_all(&[y, o, w_inner]))
}

fn write_back_bit0<C: PolyContext<Field = Gf2>>(c: &mut C, w: &[C::Wire]) -> Result<(), C::Error> {
    let l: Vec<C::Expr> = w.iter().map(|&x| c.lift(x)).collect();
    let (y, o, ww, s, q, v, h, big_b, g, a, b, cc, f, k) = (
        l[0], l[1], l[2], l[3], l[4], l[5], l[6], l[7], l[8], l[9], l[10], l[11], l[12], l[13],
    );
    let q_inner = q * add_all(&[g, a, b * f, cc]);
    let chain = add_all(&[g, v, q_inner]);
    let alu = chain + h * (chain + big_b);
    let w_inner = ww * add_all(&[o, alu, s * (alu + k)]);
    c.assert_zero(add_all(&[y, o, w_inner]))
}

fn addr_base_mux<C: PolyContext<Field = Gf2>>(c: &mut C, w: &[C::Wire]) -> Result<(), C::Error> {
    let (y, big_a, big_b, big_c, m0, m1) = (
        c.lift(w[0]),
        c.lift(w[1]),
        c.lift(w[2]),
        c.lift(w[3]),
        c.lift(w[4]),
        c.lift(w[5]),
    );
    let p = big_a + m0 * (big_a + big_b);
    let q = big_c + m0 * big_c;
    let p_mux = p + m1 * (p + q);
    c.assert_zero(y + p_mux)
}

fn addr_index_mux<C: PolyContext<Field = Gf2>>(c: &mut C, w: &[C::Wire]) -> Result<(), C::Error> {
    let (y, a, b, d) = (c.lift(w[0]), c.lift(w[1]), c.lift(w[2]), c.lift(w[3]));
    c.assert_zero(add_all(&[y, b, d * (a + b)]))
}

fn mul_bit_extraction<C: PolyContext<Field = Gf2>>(
    c: &mut C,
    w: &[C::Wire],
) -> Result<(), C::Error> {
    let y = c.lift(w[0]);
    let s: Vec<C::Expr> = (1..=5).map(|i| c.lift(w[i])).collect();
    let x: Vec<C::Expr> = (6..38).map(|i| c.lift(w[i])).collect();
    let m0: Vec<C::Expr> = (0..16).map(|j| mux(s[0], x[2 * j], x[2 * j + 1])).collect();
    let m1: Vec<C::Expr> = (0..8).map(|j| mux(s[1], m0[2 * j], m0[2 * j + 1])).collect();
    let m2: Vec<C::Expr> = (0..4).map(|j| mux(s[2], m1[2 * j], m1[2 * j + 1])).collect();
    let m3: Vec<C::Expr> = (0..2).map(|j| mux(s[3], m2[2 * j], m2[2 * j + 1])).collect();
    let result = mux(s[4], m3[0], m3[1]);
    c.assert_zero(y + result)
}

fn mul_force<C: PolyContext<Field = Gf2>>(c: &mut C, w: &[C::Wire]) -> Result<(), C::Error> {
    let (y, big_m, m) = (c.lift(w[0]), c.lift(w[1]), c.lift(w[2]));
    let one = PolyContext::constant(c, Gf2::ONE);
    c.assert_zero(add_all(&[y, one, big_m * (one + m)]))
}

fn acc_mux<C: PolyContext<Field = Gf2>>(c: &mut C, w: &[C::Wire]) -> Result<(), C::Error> {
    let (y, a, ww, s, u0, u1) = (
        c.lift(w[0]),
        c.lift(w[1]),
        c.lift(w[2]),
        c.lift(w[3]),
        c.lift(w[4]),
        c.lift(w[5]),
    );
    let r = u0 * (ww + a);
    let u1_term = u1 * add_all(&[s, a, r]);
    c.assert_zero(add_all(&[y, a, r, u1_term]))
}

fn pc_mux<C: PolyContext<Field = Gf2>>(c: &mut C, w: &[C::Wire]) -> Result<(), C::Error> {
    let (y, pc, iota, s, r, p0, p1, k) = (
        c.lift(w[0]),
        c.lift(w[1]),
        c.lift(w[2]),
        c.lift(w[3]),
        c.lift(w[4]),
        c.lift(w[5]),
        c.lift(w[6]),
        c.lift(w[7]),
    );
    let p = pc + iota;
    let d = s + p;
    let e = r + p;
    let kd = k * d;
    let p0_d = p0 * d;
    let p0_inner = p0 * add_all(&[d, kd, e]);
    let p1_term = p1 * (kd + p0_inner);
    c.assert_zero(add_all(&[y, p, p0_d, p1_term]))
}

fn sp_mux<C: PolyContext<Field = Gf2>>(c: &mut C, w: &[C::Wire]) -> Result<(), C::Error> {
    let (y, sp, d_inc, d_dec, r0, r1) = (
        c.lift(w[0]),
        c.lift(w[1]),
        c.lift(w[2]),
        c.lift(w[3]),
        c.lift(w[4]),
        c.lift(w[5]),
    );
    let r = r0 * d_inc;
    let r1_term = r1 * (d_dec + r);
    c.assert_zero(add_all(&[y, sp, r, r1_term]))
}

fn fp_mux<C: PolyContext<Field = Gf2>>(c: &mut C, w: &[C::Wire]) -> Result<(), C::Error> {
    let (y, f, n, t) = (c.lift(w[0]), c.lift(w[1]), c.lift(w[2]), c.lift(w[3]));
    c.assert_zero(add_all(&[y, f, t * (n + f)]))
}

fn dispatch<C: PolyContext<Field = Gf2>>(
    c: &mut C,
    idx: usize,
    w: &[C::Wire],
) -> Result<(), C::Error> {
    match idx {
        0 => carry_generate(c, w),
        1 => carry_chain(c, w),
        2 => write_back(c, w),
        3 => write_back_bit0(c, w),
        4 => addr_base_mux(c, w),
        5 => addr_index_mux(c, w),
        6 => mul_bit_extraction(c, w),
        7 => mul_force(c, w),
        8 => acc_mux(c, w),
        9 => pc_mux(c, w),
        10 => sp_mux(c, w),
        11 => fp_mux(c, w),
        _ => unreachable!(),
    }
}

// --- setup ------------------------------------------------------------------

/// A `Gf2_128` MAC/key pair for a committed bit `value` under `delta`
/// (`key = mac + value·delta`, `lsb(mac) = value`).
fn wire(rng: &mut StdRng, delta: Gf2_128, value: bool) -> (Gf2_128, Gf2_128) {
    let raw: u128 = rng.random();
    let mac = Gf2_128::new((raw & !1) | u128::from(value));
    let key = if value { mac + delta } else { mac };
    (mac, key)
}

struct Inputs {
    delta: Gf2_128,
    /// Per-fixture prover wires (MACs) — a satisfying witness, reused per eval.
    p_wires: Vec<Vec<Gf2_128>>,
    /// Per-fixture verifier wires (keys).
    v_keys: Vec<Vec<Gf2_128>>,
    /// Eval schedule: fixture index per evaluation (length `NUM_STEPS × 232`).
    schedule: Vec<usize>,
    poly_pv: ProverVope,
    poly_vv: VerifierVope,
    chi: [u8; 32],
    /// Precomputed proof, cloned per verifier iteration.
    proof: Proof,
}

fn setup() -> Inputs {
    let mut rng = StdRng::seed_from_u64(0xbe0c4);
    let mut delta = Gf2_128::new(rng.random());
    delta = Gf2_128::new(delta.to_inner() | 1); // lsb = 1

    // Satisfying witness per fixture: all bits 0, except `mul_force` (idx 7)
    // needs Y = 1 so `Y + 1 + M·(1+m) = 0`.
    let mut p_wires = Vec::with_capacity(12);
    let mut v_keys = Vec::with_capacity(12);
    for idx in 0..12 {
        let n = NUM_VARS[idx];
        let (mut macs, mut keys) = (Vec::with_capacity(n), Vec::with_capacity(n));
        for var in 0..n {
            let bit = idx == 7 && var == 0;
            let (m, k) = wire(&mut rng, delta, bit);
            macs.push(m);
            keys.push(k);
        }
        p_wires.push(macs);
        v_keys.push(keys);
    }

    // Weighted template pool (232 entries), repeated across steps.
    let pool: Vec<usize> = (0..12).flat_map(|i| std::iter::repeat_n(i, COUNTS[i])).collect();
    let schedule: Vec<usize> = (0..NUM_STEPS).flat_map(|_| pool.iter().copied()).collect();

    // Mocked degree-`D_MAX` VOPE: sum = Σ_h coeffs[h]·Δ^h.
    let coeffs: Vec<Gf2_128> = (0..D_MAX).map(|_| Gf2_128::new(rng.random())).collect();
    let mut sum = Gf2_128::ZERO;
    let mut pw = Gf2_128::ONE;
    for &cf in &coeffs {
        sum = sum + cf * pw;
        pw = pw * delta;
    }
    let chi: [u8; 32] = rng.random();

    Inputs {
        delta,
        p_wires,
        v_keys,
        schedule,
        poly_pv: ProverVope { coeffs },
        poly_vv: VerifierVope { sum },
        chi,
    }
}

fn run_prover(i: &Inputs) {
    let mut prover = Prover::new();
    let mut masks: Vec<bool> = Vec::new();
    let macs: Vec<Gf2_128> = Vec::new();
    {
        let mut exec = prover.execute(&mut masks, &macs).expect("execute");
        for &idx in &i.schedule {
            dispatch(&mut exec, idx, &i.p_wires[idx]).expect("constraint");
        }
        exec.finish().expect("finish");
    }
    let _ = prover.prove(i.chi, &[false; 128], &[Gf2_128::ZERO; 128], &i.poly_pv);
}

fn run_verifier(i: &Inputs) {
    let mut verifier = Verifier::new(i.delta);
    let keys: Vec<Gf2_128> = Vec::new();
    let adjust: Vec<bool> = Vec::new();
    {
        let mut exec = verifier.execute(&keys, &adjust).expect("execute");
        for &idx in &i.schedule {
            dispatch(&mut exec, idx, &i.v_keys[idx]).expect("constraint");
        }
        exec.finish().expect("finish");
    }
    // Rebuild the proof so `verify` succeeds (constraints satisfied).
    let mut prover = Prover::new();
    let mut masks: Vec<bool> = Vec::new();
    let proof = {
        let mut exec = prover.execute(&mut masks, &[]).expect("execute");
        for &idx in &i.schedule {
            dispatch(&mut exec, idx, &i.p_wires[idx]).expect("constraint");
        }
        exec.finish().expect("finish");
        prover.prove(i.chi, &[false; 128], &[Gf2_128::ZERO; 128], &i.poly_pv)
    };
    verifier
        .verify(i.chi, &[Gf2_128::ZERO; 128], &i.poly_vv, proof)
        .expect("verify");
}

fn bench_poly(c: &mut Criterion) {
    let inputs = setup();
    let n = inputs.schedule.len() as u64;

    let mut pg = c.benchmark_group("poly_prover_steps");
    pg.sample_size(10);
    pg.measurement_time(Duration::from_secs(10));
    pg.throughput(Throughput::Elements(n));
    pg.bench_function("100k", |b| b.iter(|| run_prover(&inputs)));
    pg.finish();

    let mut vg = c.benchmark_group("poly_verifier_steps");
    vg.sample_size(10);
    vg.measurement_time(Duration::from_secs(10));
    vg.throughput(Throughput::Elements(n));
    vg.bench_function("100k", |b| b.iter(|| run_verifier(&inputs)));
    vg.finish();
}

criterion_group!(benches, bench_poly);
criterion_main!(benches);
