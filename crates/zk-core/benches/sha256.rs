//! SHA-256 prover/verifier benchmarks over message sizes from one
//! block (64 B) up to 128 KiB.
//!
//! Run with: `cargo bench -p mpz-zk-core --bench sha256`

use std::time::Duration;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use itybity::ToBits;
use mpz_circuits::{
    Context,
    sha256::{AND_PER_BLOCK, H0, compress as sha256_compress},
};
use mpz_core::Block;
use mpz_fields::gf2_128::Gf2_128;
use mpz_ot_core::ideal::rcot::IdealRCOT;
use mpz_zk_core::{Commit, Proof, Prover, ProverOutput, Verifier, VerifierOutput, vope_receiver, vope_sender};
use rand::{Rng, SeedableRng, rngs::StdRng};
use rand_chacha::ChaCha12Rng;

const VOPE_COST: usize = 128;

/// Samples `total` RCOT correlations as `(delta, keys, choices, macs)`
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

/// Iterated SHA-256 compression over a sequence of message blocks.
fn sha256_chain<C: Context<Field = mpz_fields::gf2::Gf2, Wire = Gf2_128>>(
    ctx: &mut C,
    initial_state: [Gf2_128; 256],
    msg_blocks: &[[Gf2_128; 512]],
) -> [Gf2_128; 256] {
    let mut state = initial_state;
    for block in msg_blocks {
        state = sha256_compress(ctx, *block, state);
    }
    state
}

const SIZES: &[(usize, &str)] = &[
    (64, "64B"),
    (1024, "1KiB"),
    (16 * 1024, "16KiB"),
    (64 * 1024, "64KiB"),
    (128 * 1024, "128KiB"),
];

struct BenchInputs {
    delta: Gf2_128,
    input_mac_wires: Vec<Gf2_128>,
    input_key_wires: Vec<Gf2_128>,
    /// Gate masks as committed (cloned per prover iteration, since
    /// the commit pass overwrites them with the adjust bits in place).
    gate_masks: Vec<bool>,
    gate_macs: Vec<Gf2_128>,
    gate_keys: Vec<Gf2_128>,
    /// Gate adjust bits the prover produced, fed to the verifier.
    gate_adjust: Vec<bool>,
    vope_choices: [bool; VOPE_COST],
    vope_ev: [Gf2_128; VOPE_COST],
    vope_keys: [Gf2_128; VOPE_COST],
    /// Seed of the consistency-check challenge stream.
    chi: [u8; 32],
    /// Proof produced by the prover, consumed in the verifier benchmark.
    proof: Proof,
}

fn setup_inputs(num_blocks: usize) -> BenchInputs {
    let mut rng = StdRng::seed_from_u64(0);

    // Initial state + N message blocks, each 512 bits.
    let mut input_bits: Vec<bool> = H0.iter_lsb0().collect();
    for _ in 0..num_blocks {
        let block: [u32; 16] = core::array::from_fn(|_| rng.random());
        input_bits.extend(block.iter_lsb0());
    }
    let input_count = input_bits.len();
    let gate_count = num_blocks * AND_PER_BLOCK;
    let total = input_count + gate_count + VOPE_COST;

    let (delta, raw_keys, choices, macs) = sample_rcot(&mut rng, total);

    let input_adjust: Vec<bool> = (0..input_count)
        .map(|i| input_bits[i] ^ choices[i])
        .collect();
    let input_mac_wires: Vec<Gf2_128> = (0..input_count)
        .map(|i| set_lsb(macs[i], input_bits[i]))
        .collect();
    let input_key_wires: Vec<Gf2_128> = (0..input_count)
        .map(|i| {
            let k = raw_keys[i];
            let key = if input_adjust[i] { k + delta } else { k };
            set_lsb(key, false)
        })
        .collect();

    let main_cost = input_count + gate_count;
    let gate_masks: Vec<bool> = choices[input_count..main_cost].to_vec();
    let gate_macs: Vec<Gf2_128> = macs[input_count..main_cost].to_vec();
    let gate_keys: Vec<Gf2_128> = raw_keys[input_count..main_cost].to_vec();

    let vope_choices: [bool; VOPE_COST] = core::array::from_fn(|i| choices[main_cost + i]);
    let vope_ev: [Gf2_128; VOPE_COST] = core::array::from_fn(|i| macs[main_cost + i]);
    let vope_keys: [Gf2_128; VOPE_COST] = core::array::from_fn(|i| raw_keys[main_cost + i]);
    let chi: [u8; 32] = rng.random();

    // Run the prover once to produce a valid proof and the gate adjust
    // bits for the verifier benchmark.
    let state_p: [Gf2_128; 256] = core::array::from_fn(|i| input_mac_wires[i]);
    let msg_p: Vec<[Gf2_128; 512]> = (0..num_blocks)
        .map(|b| core::array::from_fn(|i| input_mac_wires[256 + b * 512 + i]))
        .collect();

    let mut gate_adjust = gate_masks.clone();
    let mut commit = Commit::new(&mut gate_adjust);
    let _ = sha256_chain(&mut commit, state_p, &msg_p);
    commit.finish().expect("commit finish");
    let mut prover = Prover::committed(&gate_macs).accumulate(ChaCha12Rng::from_seed(chi));
    let _ = sha256_chain(&mut prover, state_p, &msg_p);
    let ProverOutput { u, v, assertions, .. } = prover.finish().expect("accumulate finish");

    let (a_0, a_1) = vope_receiver(&vope_choices, &vope_ev);
    let proof = Proof {
        assertions,
        u: u + a_0,
        v: v + a_1,
        coefficients: Vec::new(),
    };

    BenchInputs {
        delta,
        input_mac_wires,
        input_key_wires,
        gate_masks,
        gate_macs,
        gate_keys,
        gate_adjust,
        vope_choices,
        vope_ev,
        vope_keys,
        chi,
        proof,
    }
}

fn run_prover(inputs: &BenchInputs, num_blocks: usize) {
    let state: [Gf2_128; 256] = core::array::from_fn(|i| inputs.input_mac_wires[i]);
    let msg_blocks: Vec<[Gf2_128; 512]> = (0..num_blocks)
        .map(|b| core::array::from_fn(|i| inputs.input_mac_wires[256 + b * 512 + i]))
        .collect();

    let mut masks = inputs.gate_masks.clone();
    let mut commit = Commit::new(&mut masks);
    let _ = sha256_chain(&mut commit, state, &msg_blocks);
    commit.finish().expect("commit finish");
    let mut prover =
        Prover::committed(&inputs.gate_macs).accumulate(ChaCha12Rng::from_seed(inputs.chi));
    let _ = sha256_chain(&mut prover, state, &msg_blocks);
    let ProverOutput { u, v, assertions, .. } = prover.finish().expect("accumulate finish");

    let (a_0, a_1) = vope_receiver(&inputs.vope_choices, &inputs.vope_ev);
    let _proof = Proof {
        assertions,
        u: u + a_0,
        v: v + a_1,
        coefficients: Vec::new(),
    };
}

fn run_verifier(inputs: &BenchInputs, num_blocks: usize) {
    let state: [Gf2_128; 256] = core::array::from_fn(|i| inputs.input_key_wires[i]);
    let msg_blocks: Vec<[Gf2_128; 512]> = (0..num_blocks)
        .map(|b| core::array::from_fn(|i| inputs.input_key_wires[256 + b * 512 + i]))
        .collect();

    let verifier =
        Verifier::new(inputs.delta, &inputs.gate_keys, &inputs.gate_adjust).expect("new");
    let mut verifier = verifier.accumulate(ChaCha12Rng::from_seed(inputs.chi));
    let _ = sha256_chain(&mut verifier, state, &msg_blocks);
    let VerifierOutput { w, assertions, .. } = verifier.finish().expect("finish");

    let b = vope_sender(&inputs.vope_keys);
    assert_eq!(assertions, inputs.proof.assertions);
    assert_eq!(
        w + b,
        inputs.proof.u + inputs.delta * inputs.proof.v,
        "consistency check failed"
    );
}

fn bench_sha256(c: &mut Criterion) {
    // Build, bench, and drop one `BenchInputs` per size before
    // constructing the next: the gate tapes for the largest size are
    // hundreds of MiB, so keeping every size resident at once strains
    // 32-bit targets.
    for &(bytes, name) in SIZES {
        let num_blocks = bytes / 64;
        let inputs = setup_inputs(num_blocks);

        let mut prover_group = c.benchmark_group("sha256_prover");
        prover_group.sample_size(10);
        prover_group.measurement_time(Duration::from_secs(10));
        prover_group.throughput(Throughput::Bytes(bytes as u64));
        prover_group.bench_function(BenchmarkId::new("message", name), |b| {
            b.iter(|| run_prover(&inputs, num_blocks));
        });
        prover_group.finish();

        let mut verifier_group = c.benchmark_group("sha256_verifier");
        verifier_group.sample_size(10);
        verifier_group.measurement_time(Duration::from_secs(10));
        verifier_group.throughput(Throughput::Bytes(bytes as u64));
        verifier_group.bench_function(BenchmarkId::new("message", name), |b| {
            b.iter(|| run_verifier(&inputs, num_blocks));
        });
        verifier_group.finish();
    }
}

criterion_group!(benches, bench_sha256);
criterion_main!(benches);
