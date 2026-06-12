//! Polynomial-constraint prover/verifier benchmark.
//!
//! **`mux{2,4,8,16}`**: a 1-of-`w` multiplexer over 32-bit values. Each output
//! bit is a depth-`log2(w)` binary mux tree `a + sel·(a + b)` over the committed
//! inputs and `log2(w)` committed selector bits, giving 32 degree-`(log2(w)+1)`
//! constraints per multiplexer. The variants sweep the mux degree: 1-of-2
//! (degree 2) through 1-of-16 (degree 5).
//!
//! The workload uses only `lift` + `assert_zero` (no AND gates and no
//! `materialize`), so the triple check is trivial and the measured cost is the
//! polynomial path: building the degree-raising expressions and folding them
//! into [`ProverPoly`]/[`VerifierPoly`].
//!
//! Run with: `cargo bench -p mpz-zk-core --bench poly`

use std::time::Duration;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use mpz_core::Block;
use mpz_fields::{gf2::Gf2, gf2_128::Gf2_128};
use mpz_ot_core::ideal::rcot::IdealRCOT;
use mpz_zk_core::{
    Commit, DeltaPowers, Proof, Prover, ProverOutput, Verifier, VerifierOutput,
    poly::{Expr, PolyContext},
    vope_receiver, vope_sender,
};
use rand::{Rng, SeedableRng, rngs::StdRng};
use rand_chacha::ChaCha12Rng;
use typenum::U1;

const VOPE_COST: usize = 128;

// ===========================================================================
// Gadget
// ===========================================================================

// Each gadget builds 32 output-bit constraints for one 1-of-`w` multiplexer.
// The selectors (`sel`, `log2(w)` wires), inputs (`inputs`, `w·32` wires laid
// out as `input·32 + bit`) and output (`out`, 32 wires) are flat committed-wire
// slices. The mux level `a + sel·(a + b)` raises the expression degree by one
// per tree level, so the top constraint is degree `log2(w)+1`. The degree is
// part of the `Expr` *type*, so each width is spelled out statically rather than
// folded over a runtime-sized tree.

/// 1-of-2 mux, depth 1, degree-2 constraints.
fn mux2_u32<C>(ctx: &mut C, sel: &[Gf2_128], inputs: &[Gf2_128], out: &[Gf2_128])
where
    C: PolyContext<Field = Gf2, Wire = Gf2_128>,
    C::Error: std::fmt::Debug,
{
    let s0 = ctx.lift(sel[0]);
    for bit in 0..32 {
        let leaf: [Expr<C::Coeffs, U1>; 2] = core::array::from_fn(|n| ctx.lift(inputs[n * 32 + bit]));
        let top = leaf[0] + s0 * (leaf[0] + leaf[1]); // degree 2
        let o = ctx.lift(out[bit]);
        ctx.assert_zero(top - o).expect("mux output");
    }
}

/// 1-of-4 mux, depth 2, degree-3 constraints.
fn mux4_u32<C>(ctx: &mut C, sel: &[Gf2_128], inputs: &[Gf2_128], out: &[Gf2_128])
where
    C: PolyContext<Field = Gf2, Wire = Gf2_128>,
    C::Error: std::fmt::Debug,
{
    let s: [Expr<C::Coeffs, U1>; 2] = core::array::from_fn(|i| ctx.lift(sel[i]));
    for bit in 0..32 {
        let leaf: [Expr<C::Coeffs, U1>; 4] = core::array::from_fn(|n| ctx.lift(inputs[n * 32 + bit]));
        let l0: [Expr<C::Coeffs, _>; 2] =
            core::array::from_fn(|j| leaf[2 * j] + s[0] * (leaf[2 * j] + leaf[2 * j + 1]));
        let top = l0[0] + s[1] * (l0[0] + l0[1]); // degree 3
        let o = ctx.lift(out[bit]);
        ctx.assert_zero(top - o).expect("mux output");
    }
}

/// 1-of-8 mux, depth 3, degree-4 constraints.
fn mux8_u32<C>(ctx: &mut C, sel: &[Gf2_128], inputs: &[Gf2_128], out: &[Gf2_128])
where
    C: PolyContext<Field = Gf2, Wire = Gf2_128>,
    C::Error: std::fmt::Debug,
{
    let s: [Expr<C::Coeffs, U1>; 3] = core::array::from_fn(|i| ctx.lift(sel[i]));
    for bit in 0..32 {
        let leaf: [Expr<C::Coeffs, U1>; 8] = core::array::from_fn(|n| ctx.lift(inputs[n * 32 + bit]));
        let l0: [Expr<C::Coeffs, _>; 4] =
            core::array::from_fn(|j| leaf[2 * j] + s[0] * (leaf[2 * j] + leaf[2 * j + 1]));
        let l1: [Expr<C::Coeffs, _>; 2] =
            core::array::from_fn(|j| l0[2 * j] + s[1] * (l0[2 * j] + l0[2 * j + 1]));
        let top = l1[0] + s[2] * (l1[0] + l1[1]); // degree 4
        let o = ctx.lift(out[bit]);
        ctx.assert_zero(top - o).expect("mux output");
    }
}

/// 1-of-16 mux, depth 4, degree-5 constraints.
fn mux16_u32<C>(ctx: &mut C, sel: &[Gf2_128], inputs: &[Gf2_128], out: &[Gf2_128])
where
    C: PolyContext<Field = Gf2, Wire = Gf2_128>,
    C::Error: std::fmt::Debug,
{
    let s: [Expr<C::Coeffs, U1>; 4] = core::array::from_fn(|i| ctx.lift(sel[i]));
    for bit in 0..32 {
        let leaf: [Expr<C::Coeffs, U1>; 16] =
            core::array::from_fn(|n| ctx.lift(inputs[n * 32 + bit]));
        // Mux level: `a + sel·(a + b)`, raising the degree by one each time.
        let l0: [Expr<C::Coeffs, _>; 8] =
            core::array::from_fn(|j| leaf[2 * j] + s[0] * (leaf[2 * j] + leaf[2 * j + 1]));
        let l1: [Expr<C::Coeffs, _>; 4] =
            core::array::from_fn(|j| l0[2 * j] + s[1] * (l0[2 * j] + l0[2 * j + 1]));
        let l2: [Expr<C::Coeffs, _>; 2] =
            core::array::from_fn(|j| l1[2 * j] + s[2] * (l1[2 * j] + l1[2 * j + 1]));
        let top = l2[0] + s[3] * (l2[0] + l2[1]); // degree 5
        let o = ctx.lift(out[bit]);
        ctx.assert_zero(top - o).expect("mux output");
    }
}

// ===========================================================================
// Circuit: a satisfying witness plus a carrier-generic evaluation.
// ===========================================================================

/// A benchmark circuit: a fixed satisfying witness (committed bits) and a
/// degree, evaluated by reading the flat committed-wire slice.
trait PolyCircuit {
    /// The satisfying witness, one bit per committed wire.
    fn witness(&self) -> Vec<bool>;
    /// The proof degree `d_max` (number of coefficients sent).
    fn d_max(&self) -> usize;
    /// Evaluates the circuit over the committed wires (same order as the
    /// witness), emitting its constraints.
    fn eval<C>(&self, ctx: &mut C, wires: &[Gf2_128])
    where
        C: PolyContext<Field = Gf2, Wire = Gf2_128>,
        C::Error: std::fmt::Debug;
}

/// `n` independent 1-of-`width` multiplexers over 32-bit values. Each mux
/// commits `log2(width)` selector + `width·32` input + 32 output bits.
struct MuxCircuit {
    /// Number of mux inputs (a power of two: 2, 4, 8 or 16).
    width: usize,
    n: usize,
}

impl MuxCircuit {
    /// Number of selector bits / mux-tree depth.
    fn depth(&self) -> usize {
        self.width.trailing_zeros() as usize
    }

    /// Committed bits per multiplexer.
    fn mux_bits(&self) -> usize {
        self.depth() + self.width * 32 + 32
    }
}

impl PolyCircuit for MuxCircuit {
    fn witness(&self) -> Vec<bool> {
        let depth = self.depth();
        let mut rng = StdRng::seed_from_u64(0x111);
        let mut bits = Vec::with_capacity(self.n * self.mux_bits());
        for _ in 0..self.n {
            let sel: Vec<bool> = (0..depth).map(|_| rng.random()).collect();
            let idx = (0..depth).fold(0usize, |a, i| a | ((sel[i] as usize) << i));
            let inputs: Vec<[bool; 32]> = (0..self.width)
                .map(|_| core::array::from_fn(|_| rng.random()))
                .collect();
            let out = inputs[idx];

            bits.extend(sel);
            for value in &inputs {
                bits.extend(value);
            }
            bits.extend(out);
        }
        bits
    }

    fn d_max(&self) -> usize {
        self.depth() + 1
    }

    fn eval<C>(&self, ctx: &mut C, wires: &[Gf2_128])
    where
        C: PolyContext<Field = Gf2, Wire = Gf2_128>,
        C::Error: std::fmt::Debug,
    {
        let depth = self.depth();
        let mux_bits = self.mux_bits();
        for m in 0..self.n {
            let base = m * mux_bits;
            let sel = &wires[base..base + depth];
            let inputs = &wires[base + depth..base + depth + self.width * 32];
            let out = &wires[base + mux_bits - 32..base + mux_bits];
            match self.width {
                2 => mux2_u32(ctx, sel, inputs, out),
                4 => mux4_u32(ctx, sel, inputs, out),
                8 => mux8_u32(ctx, sel, inputs, out),
                16 => mux16_u32(ctx, sel, inputs, out),
                w => unreachable!("unsupported mux width {w}"),
            }
        }
    }
}

// ===========================================================================
// Poly proof harness
// ===========================================================================

/// Samples `total` RCOT correlations as `(delta, raw_keys, choices, macs)`
/// with `delta.lsb = 1`.
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

/// Sets the LSB of `g` to `bit`.
fn set_lsb(g: Gf2_128, bit: bool) -> Gf2_128 {
    Gf2_128::new((g.to_inner() & !1) | u128::from(bit))
}

/// Everything needed to run the prover and verifier benchmarks for one
/// circuit: pre-committed input wires and a precomputed (valid) proof.
struct PolyInputs {
    delta: Gf2_128,
    d_max: usize,
    /// Prover input wires (MACs, LSB = committed bit).
    mac_wires: Vec<Gf2_128>,
    /// Verifier input wires (keys, pre-adjusted off-band).
    key_wires: Vec<Gf2_128>,
    chi: [u8; 32],
    vope_choices: [bool; VOPE_COST],
    vope_ev: [Gf2_128; VOPE_COST],
    vope_keys: [Gf2_128; VOPE_COST],
    /// Powers of `delta` for the polynomial check.
    powers: DeltaPowers,
    /// Verifier's side of the polynomial-check VOPE correlation.
    poly_vope_sum: Gf2_128,
    /// The prover's masked polynomial coefficients (degrees `0 ..= d_max-1`).
    coefficients: Vec<Gf2_128>,
    /// The triple-check proof (trivial here — no AND gates).
    proof: Proof,
}

fn setup<Circ: PolyCircuit>(circ: &Circ) -> PolyInputs {
    let mut rng = StdRng::seed_from_u64(7);
    let witness = circ.witness();
    let input_count = witness.len();
    let d_max = circ.d_max();

    let total = input_count + VOPE_COST;
    let (delta, raw_keys, choices, macs) = sample_rcot(&mut rng, total);

    // Commit the input bits: adjust = bit ^ choice, MAC LSB = bit, key
    // pre-adjusted.
    let mac_wires: Vec<Gf2_128> = (0..input_count)
        .map(|i| set_lsb(macs[i], witness[i]))
        .collect();
    let key_wires: Vec<Gf2_128> = (0..input_count)
        .map(|i| {
            let adjust = witness[i] ^ choices[i];
            let k = raw_keys[i];
            set_lsb(if adjust { k + delta } else { k }, false)
        })
        .collect();

    let vope_choices: [bool; VOPE_COST] = core::array::from_fn(|i| choices[input_count + i]);
    let vope_ev: [Gf2_128; VOPE_COST] = core::array::from_fn(|i| macs[input_count + i]);
    let vope_keys: [Gf2_128; VOPE_COST] = core::array::from_fn(|i| raw_keys[input_count + i]);
    let chi: [u8; 32] = rng.random();

    // Mock degree-`d_max` polynomial-check VOPE: random mask coefficients on
    // the prover side, their Δ-weighted sum on the verifier side.
    let powers = DeltaPowers::new(delta);
    let poly_masks: Vec<Gf2_128> = (0..d_max).map(|_| Gf2_128::new(rng.random())).collect();
    let mut poly_vope_sum = Gf2_128::new(0);
    let mut pw = Gf2_128::new(1);
    for &m in &poly_masks {
        poly_vope_sum = poly_vope_sum + m * pw;
        pw = pw * delta;
    }

    // Run the prover once to produce the proof and the masked coefficients.
    let mut commit = Commit::new(&mut []);
    circ.eval(&mut commit, &ptr_wires(&witness));
    commit.finish().expect("commit finish");

    let mut prover = Prover::committed(&[]).accumulate(ChaCha12Rng::from_seed(chi));
    circ.eval(&mut prover, &mac_wires);
    let ProverOutput { u, v, poly, assertions } = prover.finish().expect("accumulate finish");

    let coefficients: Vec<Gf2_128> = poly
        .coefficients(d_max)
        .expect("coefficients")
        .into_iter()
        .zip(&poly_masks)
        .map(|(c, &m)| c + m)
        .collect();

    let (a_0, a_1) = vope_receiver(&vope_choices, &vope_ev);
    let proof = Proof {
        assertions,
        u: u + a_0,
        v: v + a_1,
        coefficients: coefficients.clone(),
    };

    PolyInputs {
        delta,
        d_max,
        mac_wires,
        key_wires,
        chi,
        vope_choices,
        vope_ev,
        vope_keys,
        powers,
        poly_vope_sum,
        coefficients,
        proof,
    }
}

/// Pointer-bit wires for the commit pass: each wire's LSB carries the bit.
fn ptr_wires(witness: &[bool]) -> Vec<Gf2_128> {
    witness.iter().map(|&b| Gf2_128::new(b as u128)).collect()
}

fn run_prover<Circ: PolyCircuit>(circ: &Circ, inputs: &PolyInputs) {
    let mut commit = Commit::new(&mut []);
    circ.eval(&mut commit, &ptr_wires(&circ.witness()));
    commit.finish().expect("commit finish");

    let mut prover = Prover::committed(&[]).accumulate(ChaCha12Rng::from_seed(inputs.chi));
    circ.eval(&mut prover, &inputs.mac_wires);
    let ProverOutput { u, v, poly, assertions } = prover.finish().expect("accumulate finish");

    let coefficients: Vec<Gf2_128> = poly.coefficients(inputs.d_max).expect("coefficients");
    let (a_0, a_1) = vope_receiver(&inputs.vope_choices, &inputs.vope_ev);
    let _proof = Proof {
        assertions,
        u: u + a_0,
        v: v + a_1,
        coefficients,
    };
}

fn run_verifier<Circ: PolyCircuit>(circ: &Circ, inputs: &PolyInputs) {
    let verifier = Verifier::new(inputs.delta, &[], &[]).expect("new");
    let mut verifier = verifier.accumulate(ChaCha12Rng::from_seed(inputs.chi));
    circ.eval(&mut verifier, &inputs.key_wires);
    let VerifierOutput { w, poly, assertions } = verifier.finish().expect("finish");

    poly.check(&inputs.powers, &inputs.coefficients, inputs.poly_vope_sum)
        .expect("poly check");

    let b = vope_sender(&inputs.vope_keys);
    assert_eq!(assertions, inputs.proof.assertions);
    assert_eq!(
        w + b,
        inputs.proof.u + inputs.delta * inputs.proof.v,
        "triple check failed"
    );
}

fn bench_circuit<Circ: PolyCircuit>(c: &mut Criterion, name: &str, circ: Circ, units: u64) {
    let inputs = setup(&circ);

    let mut pg = c.benchmark_group(format!("poly_prover_{name}"));
    pg.sample_size(10);
    pg.measurement_time(Duration::from_secs(10));
    pg.throughput(Throughput::Elements(units));
    pg.bench_function("run", |b| b.iter(|| run_prover(&circ, &inputs)));
    pg.finish();

    let mut vg = c.benchmark_group(format!("poly_verifier_{name}"));
    vg.sample_size(10);
    vg.measurement_time(Duration::from_secs(10));
    vg.throughput(Throughput::Elements(units));
    vg.bench_function("run", |b| b.iter(|| run_verifier(&circ, &inputs)));
    vg.finish();
}

fn bench_poly(c: &mut Criterion) {
    // 2k multiplexers of 32-bit values each, swept over 1-of-{2,4,8,16}
    // (mux degrees 2..=5).
    const N_MUX: usize = 2_000;
    for width in [2usize, 4, 8, 16] {
        bench_circuit(
            c,
            &format!("mux{width}"),
            MuxCircuit { width, n: N_MUX },
            N_MUX as u64,
        );
    }
}

criterion_group!(benches, bench_poly);
criterion_main!(benches);
