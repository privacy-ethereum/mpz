//! SHA-256 prover/verifier benchmarks over message sizes from one
//! block (64 B) up to 128 KiB, distinguishing witness generation from
//! the batch check, with the check measured single- and multi-threaded.
//!
//! Witness generation is the wire walk: the prover's commit pass and
//! the verifier's key derivation. The batch check is the accumulate
//! pass folding every multiplication under the challenge stream. The
//! multi-threaded check partitions the blocks across rayon workers,
//! starting each from its block's input hash state (captured during
//! setup) with the challenge stream seeked to the block's gate offset.
//!
//! Run with: `cargo bench -p mpz-zk-core-new --bench sha256`

use std::{convert::Infallible, hint::black_box, time::Duration};

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use itybity::ToBits;
use mpz_circuits_new::{
    Context,
    sha256::{AND_PER_BLOCK, H0, compress as sha256_compress},
};
use mpz_core::Block;
use mpz_fields::{gf2::Gf2, gf2_64::Gf2_64};
use mpz_ot_core::ideal::rcot::IdealRCOT;
use mpz_zk_core_new::{MAC_ONE, MAC_ZERO, Proof, Prover, Verifier, vope_receiver, vope_sender};
use rand::{Rng, SeedableRng, rngs::StdRng};
use rand_chacha::ChaCha12Rng;
use rayon::prelude::*;

const VOPE_COST: usize = 64;

/// Samples `total` RCOT correlations as `(delta, keys, choices, macs)`
/// with `delta.lsb = 1`.
fn sample_rcot<R: Rng>(
    rng: &mut R,
    total: usize,
) -> (Gf2_64, Vec<Gf2_64>, Vec<bool>, Vec<Gf2_64>) {
    let mut delta_block: Block = rng.random();
    delta_block.set_lsb(true);
    let seed: Block = rng.random();

    let mut rcot = IdealRCOT::new(seed, delta_block);
    rcot.alloc(total);
    rcot.flush().expect("ideal rcot flush");
    let (sender_out, receiver_out) = rcot.transfer(total).expect("ideal rcot transfer");

    (
        gf2_64(delta_block),
        sender_out.keys.into_iter().map(gf2_64).collect(),
        receiver_out.choices,
        receiver_out.msgs.into_iter().map(gf2_64).collect(),
    )
}

/// Truncates a 128-bit RCOT block to a `Gf2_64` element (its low 64 bits).
///
/// XOR correlations are bitwise, so `mac = key ^ choice·delta` survives the
/// truncation, as does delta's forced LSB.
fn gf2_64(b: Block) -> Gf2_64 {
    Gf2_64::new(u128::from_le_bytes(b.to_bytes()) as u64)
}

/// Sets the LSB of `g` to `bit`.
fn set_lsb(g: Gf2_64, bit: bool) -> Gf2_64 {
    Gf2_64::new((g.to_inner() & !1) | u64::from(bit))
}

/// Challenge-stream rng positioned at gate offset `gate` (one 8-byte
/// challenge — two ChaCha words — per gate).
fn chi_rng(chi: [u8; 32], gate: usize) -> ChaCha12Rng {
    let mut rng = ChaCha12Rng::from_seed(chi);
    rng.set_word_pos(gate as u128 * 2);
    rng
}

/// Splits the flat input-wire tape into the initial hash state and the
/// per-block message wires.
fn split_inputs(wires: &[Gf2_64], num_blocks: usize) -> ([Gf2_64; 256], Vec<[Gf2_64; 512]>) {
    let state = core::array::from_fn(|i| wires[i]);
    let msg = (0..num_blocks)
        .map(|b| core::array::from_fn(|i| wires[256 + b * 512 + i]))
        .collect();
    (state, msg)
}

/// Iterated SHA-256 compression over a sequence of message blocks.
fn sha256_chain<C: Context<Field = Gf2, Wire = Gf2_64>>(
    ctx: &mut C,
    initial_state: [Gf2_64; 256],
    msg_blocks: &[[Gf2_64; 512]],
) -> [Gf2_64; 256] {
    let mut state = initial_state;
    for block in msg_blocks {
        state = sha256_compress(ctx, *block, state);
    }
    state
}

/// Wire-only verifier walk: derives key wires from the tapes without
/// folding.
struct KeyWalk<'a> {
    keys: &'a [Gf2_64],
    adjust: &'a [bool],
    delta: Gf2_64,
    key_one: Gf2_64,
    cursor: usize,
}

impl<'a> KeyWalk<'a> {
    fn new(keys: &'a [Gf2_64], adjust: &'a [bool], delta: Gf2_64) -> Self {
        Self {
            keys,
            adjust,
            delta,
            key_one: MAC_ONE + delta,
            cursor: 0,
        }
    }
}

impl Context for KeyWalk<'_> {
    type Error = Infallible;
    type Wire = Gf2_64;
    type Field = Gf2;

    fn add(&mut self, a: Gf2_64, b: Gf2_64) -> Gf2_64 {
        a + b
    }

    fn sub(&mut self, a: Gf2_64, b: Gf2_64) -> Gf2_64 {
        a - b
    }

    fn mul(&mut self, _a: Gf2_64, _b: Gf2_64) -> Gf2_64 {
        let i = self.cursor;
        let mut key = self.keys[i];
        if self.adjust[i] {
            key = key + self.delta;
        }
        self.cursor = i + 1;
        set_lsb(key, false)
    }

    fn constant(&mut self, v: Gf2) -> Gf2_64 {
        if v.0 { self.key_one } else { MAC_ZERO }
    }

    fn assert_const(&mut self, _v: Gf2_64, _expected: Gf2) -> Result<(), Infallible> {
        Ok(())
    }
}

const SIZES: &[(usize, &str)] = &[
    (64, "64B"),
    (1024, "1KiB"),
    (16 * 1024, "16KiB"),
    (64 * 1024, "64KiB"),
    (128 * 1024, "128KiB"),
];

struct BenchInputs {
    delta: Gf2_64,
    input_mac_wires: Vec<Gf2_64>,
    input_key_wires: Vec<Gf2_64>,
    /// Gate masks as committed (cloned per prover iteration, since
    /// the commit pass overwrites them with the adjust bits in place).
    gate_masks: Vec<bool>,
    gate_macs: Vec<Gf2_64>,
    gate_keys: Vec<Gf2_64>,
    /// Gate adjust bits the prover produced, fed to the verifier.
    gate_adjust: Vec<bool>,
    /// Each block's input hash state as MAC wires, for partitioning
    /// the prover's check.
    mac_states: Vec<[Gf2_64; 256]>,
    /// Each block's input hash state as key wires, for partitioning
    /// the verifier's check.
    key_states: Vec<[Gf2_64; 256]>,
    vope_choices: [bool; VOPE_COST],
    vope_ev: [Gf2_64; VOPE_COST],
    vope_keys: [Gf2_64; VOPE_COST],
    /// Verifier's consistency-check challenge.
    chi: [u8; 32],
    /// Proof produced by the prover, validated against in every run.
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

    let input_adjust: Vec<bool> = (0..input_count).map(|i| input_bits[i] ^ choices[i]).collect();
    let input_mac_wires: Vec<Gf2_64> = (0..input_count)
        .map(|i| set_lsb(macs[i], input_bits[i]))
        .collect();
    let input_key_wires: Vec<Gf2_64> = (0..input_count)
        .map(|i| {
            let k = raw_keys[i];
            let key = if input_adjust[i] { k + delta } else { k };
            set_lsb(key, false)
        })
        .collect();

    let main_cost = input_count + gate_count;
    let gate_masks: Vec<bool> = choices[input_count..main_cost].to_vec();
    let gate_macs: Vec<Gf2_64> = macs[input_count..main_cost].to_vec();
    let gate_keys: Vec<Gf2_64> = raw_keys[input_count..main_cost].to_vec();

    let vope_choices: [bool; VOPE_COST] = core::array::from_fn(|i| choices[main_cost + i]);
    let vope_ev: [Gf2_64; VOPE_COST] = core::array::from_fn(|i| macs[main_cost + i]);
    let vope_keys: [Gf2_64; VOPE_COST] = core::array::from_fn(|i| raw_keys[main_cost + i]);
    let chi: [u8; 32] = rng.random();

    // Run the prover once to produce a valid proof, the gate adjust
    // bits for the verifier, and each block's input hash state for
    // the partitioned checks.
    let (state_p, msg_p) = split_inputs(&input_mac_wires, num_blocks);

    let mut gate_adjust = gate_masks.clone();
    let mut prover =
        Prover::new(&mut gate_adjust, &gate_macs).expect("tape lengths should match");
    let mut mac_states = Vec::with_capacity(num_blocks);
    let mut state = state_p;
    for msg in &msg_p {
        mac_states.push(state);
        state = sha256_compress(&mut prover, *msg, state);
    }
    let prover = prover.finish().expect("commit pass should consume the tape");
    let mut prover = prover.accumulate(ChaCha12Rng::from_seed(chi));
    let _ = sha256_chain(&mut prover, state_p, &msg_p);
    let (u, v, assertions) = prover
        .finish()
        .expect("accumulate pass should consume the tape");

    let (a_0, a_1) = vope_receiver(&vope_choices, &vope_ev);
    let proof = Proof {
        assertions,
        u: u + a_0,
        v: v + a_1,
    };

    // Walk the key wires to capture the verifier-side block states.
    let (state_v, msg_v) = split_inputs(&input_key_wires, num_blocks);

    let mut walk = KeyWalk::new(&gate_keys, &gate_adjust, delta);
    let mut key_states = Vec::with_capacity(num_blocks);
    let mut state = state_v;
    for msg in &msg_v {
        key_states.push(state);
        state = sha256_compress(&mut walk, *msg, state);
    }

    BenchInputs {
        delta,
        input_mac_wires,
        input_key_wires,
        gate_masks,
        gate_macs,
        gate_keys,
        gate_adjust,
        mac_states,
        key_states,
        vope_choices,
        vope_ev,
        vope_keys,
        chi,
        proof,
    }
}

/// Witness generation: the prover's commit pass.
fn run_prover_witness(inputs: &BenchInputs, num_blocks: usize) {
    let (state, msg_blocks) = split_inputs(&inputs.input_mac_wires, num_blocks);

    let mut masks = inputs.gate_masks.clone();
    let mut prover =
        Prover::new(&mut masks, &inputs.gate_macs).expect("tape lengths should match");
    let out = sha256_chain(&mut prover, state, &msg_blocks);
    let _ = prover.finish().expect("commit pass should consume the tape");
    black_box(out);
}

/// Batch check: the prover's accumulate pass, single-threaded.
fn run_prover_check_single(inputs: &BenchInputs, num_blocks: usize) {
    let (state, msg_blocks) = split_inputs(&inputs.input_mac_wires, num_blocks);

    let mut prover =
        Prover::committed(&inputs.gate_macs).accumulate(ChaCha12Rng::from_seed(inputs.chi));
    let _ = sha256_chain(&mut prover, state, &msg_blocks);
    let (u, v, _) = prover
        .finish()
        .expect("accumulate pass should consume the tape");

    let (a_0, a_1) = vope_receiver(&inputs.vope_choices, &inputs.vope_ev);
    assert_eq!(u + a_0, inputs.proof.u);
    assert_eq!(v + a_1, inputs.proof.v);
}

/// Batch check: the prover's accumulate pass, one partition per block.
fn run_prover_check_multi(inputs: &BenchInputs, num_blocks: usize) {
    let (_, msg_blocks) = split_inputs(&inputs.input_mac_wires, num_blocks);

    let (u, v) = (0..num_blocks)
        .into_par_iter()
        .map(|b| {
            let gate = b * AND_PER_BLOCK;
            let macs = &inputs.gate_macs[gate..gate + AND_PER_BLOCK];
            let mut prover = Prover::committed(macs).accumulate(chi_rng(inputs.chi, gate));
            let _ = sha256_compress(&mut prover, msg_blocks[b], inputs.mac_states[b]);
            let (u, v, _) = prover
                .finish()
                .expect("accumulate pass should consume the tape");
            (u, v)
        })
        .reduce(
            || (Gf2_64::new(0), Gf2_64::new(0)),
            |(u1, v1), (u2, v2)| (u1 + u2, v1 + v2),
        );

    let (a_0, a_1) = vope_receiver(&inputs.vope_choices, &inputs.vope_ev);
    assert_eq!(u + a_0, inputs.proof.u);
    assert_eq!(v + a_1, inputs.proof.v);
}

/// Key derivation: the verifier's wire-only walk.
fn run_verifier_keys(inputs: &BenchInputs, num_blocks: usize) {
    let (state, msg_blocks) = split_inputs(&inputs.input_key_wires, num_blocks);

    let mut walk = KeyWalk::new(&inputs.gate_keys, &inputs.gate_adjust, inputs.delta);
    let out = sha256_chain(&mut walk, state, &msg_blocks);
    black_box(out);
}

/// Batch check: the verifier's accumulate pass, single-threaded.
fn run_verifier_check_single(inputs: &BenchInputs, num_blocks: usize) {
    let (state, msg_blocks) = split_inputs(&inputs.input_key_wires, num_blocks);

    let verifier = Verifier::new(inputs.delta, &inputs.gate_keys, &inputs.gate_adjust)
        .expect("tape lengths should match");
    let mut verifier = verifier.accumulate(ChaCha12Rng::from_seed(inputs.chi));
    let _ = sha256_chain(&mut verifier, state, &msg_blocks);
    let (w, assertions) = verifier
        .finish()
        .expect("accumulate pass should consume the tape");

    let b = vope_sender(&inputs.vope_keys);
    assert_eq!(assertions, inputs.proof.assertions);
    assert_eq!(w + b, inputs.proof.u + inputs.delta * inputs.proof.v);
}

/// Batch check: the verifier's accumulate pass, one partition per block.
fn run_verifier_check_multi(inputs: &BenchInputs, num_blocks: usize) {
    let (_, msg_blocks) = split_inputs(&inputs.input_key_wires, num_blocks);

    let w = (0..num_blocks)
        .into_par_iter()
        .map(|b| {
            let gate = b * AND_PER_BLOCK;
            let keys = &inputs.gate_keys[gate..gate + AND_PER_BLOCK];
            let adjust = &inputs.gate_adjust[gate..gate + AND_PER_BLOCK];
            let verifier =
                Verifier::new(inputs.delta, keys, adjust).expect("tape lengths should match");
            let mut verifier = verifier.accumulate(chi_rng(inputs.chi, gate));
            let _ = sha256_compress(&mut verifier, msg_blocks[b], inputs.key_states[b]);
            let (w, _) = verifier
                .finish()
                .expect("accumulate pass should consume the tape");
            w
        })
        .reduce(|| Gf2_64::new(0), |w1, w2| w1 + w2);

    let b = vope_sender(&inputs.vope_keys);
    assert_eq!(w + b, inputs.proof.u + inputs.delta * inputs.proof.v);
}

fn bench_sha256(c: &mut Criterion) {
    // Build, bench, and drop one `BenchInputs` per size before
    // constructing the next: the input and gate tapes for the largest
    // size are multiple GiB, so keeping every size resident at once
    // OOMs on 32-bit targets.
    for &(bytes, name) in SIZES {
        let num_blocks = bytes / 64;
        let inputs = setup_inputs(num_blocks);

        let mut prover_group = c.benchmark_group("sha256_prover");
        prover_group.sample_size(10);
        prover_group.measurement_time(Duration::from_secs(10));
        prover_group.throughput(Throughput::Bytes(bytes as u64));
        prover_group.bench_function(BenchmarkId::new("witness", name), |b| {
            b.iter(|| run_prover_witness(&inputs, num_blocks));
        });
        prover_group.bench_function(BenchmarkId::new("check-single", name), |b| {
            b.iter(|| run_prover_check_single(&inputs, num_blocks));
        });
        prover_group.bench_function(BenchmarkId::new("check-multi", name), |b| {
            b.iter(|| run_prover_check_multi(&inputs, num_blocks));
        });
        prover_group.finish();

        let mut verifier_group = c.benchmark_group("sha256_verifier");
        verifier_group.sample_size(10);
        verifier_group.measurement_time(Duration::from_secs(10));
        verifier_group.throughput(Throughput::Bytes(bytes as u64));
        verifier_group.bench_function(BenchmarkId::new("keys", name), |b| {
            b.iter(|| run_verifier_keys(&inputs, num_blocks));
        });
        verifier_group.bench_function(BenchmarkId::new("check-single", name), |b| {
            b.iter(|| run_verifier_check_single(&inputs, num_blocks));
        });
        verifier_group.bench_function(BenchmarkId::new("check-multi", name), |b| {
            b.iter(|| run_verifier_check_multi(&inputs, num_blocks));
        });
        verifier_group.finish();
    }
}

criterion_group!(benches, bench_sha256);
criterion_main!(benches);
