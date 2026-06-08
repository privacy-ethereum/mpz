//! End-to-end integration: build the SHA-256 compression function as
//! a boolean circuit written against `zk_core::circuit::Context`,
//! then drive it through the witness-mode evaluator (sanity vs the
//! `sha2` crate) and through the [`Prover`] / [`Verifier`] pair
//! against a simulated sVOLE tape, verifying that the batch
//! consistency check accepts.

use itybity::{FromBitIterator, ToBits};
use mpz_circuits::{
    WitnessCtx,
    sha256::{H0, compress as sha256_compress},
};
use mpz_core::{Block, bitvec::BitVec};
use mpz_fields::{gf2::Gf2, gf2_128::Gf2_128};
use mpz_ot_core::ideal::rcot::IdealRCOT;
use rand::{Rng, SeedableRng, rngs::StdRng};

use mpz_zk_core::{Prover, Verifier};

const VOPE_COST: usize = 128;

/// Pack 64 message bytes into 16 u32 words using big-endian byte
/// order (the SHA-256 message-schedule convention).
fn msg_bytes_to_words(msg: &[u8; 64]) -> [u32; 16] {
    core::array::from_fn(|i| {
        u32::from_be_bytes([msg[i * 4], msg[i * 4 + 1], msg[i * 4 + 2], msg[i * 4 + 3]])
    })
}

fn sha2_crate_compress(msg: &[u8; 64], state: [u32; 8]) -> [u32; 8] {
    let mut state = state;
    sha2::compress256(&mut state, &[(*msg).into()]);
    state
}

// -------- sVOLE simulation helpers --------

fn set_lsb(g: Gf2_128, bit: bool) -> Gf2_128 {
    Gf2_128::new((g.to_inner() & !1) | u128::from(bit))
}

/// Draws `total` RCOT correlations from `IdealRCOT` and returns
/// `(delta, raw_keys, choices, macs)` as `Gf2_128` / `bool`. Delta's
/// LSB is forced to 1 (pointer-bit convention).
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

// -------- tests --------

#[test]
fn sha256_witness_matches_sha2_crate() {
    let mut rng = StdRng::seed_from_u64(0);
    let msg_bytes: [u8; 64] = rng.random();
    let msg_words = msg_bytes_to_words(&msg_bytes);
    let expected = sha2_crate_compress(&msg_bytes, H0);

    let msg_wires: [Gf2; 512] = <[Gf2; 512]>::from_lsb0_iter(msg_words.iter_lsb0());
    let state_wires: [Gf2; 256] = <[Gf2; 256]>::from_lsb0_iter(H0.iter_lsb0());

    let mut witness = Vec::new();
    let mut ctx = WitnessCtx {
        witness: &mut witness,
    };
    let out = sha256_compress(&mut ctx, msg_wires, state_wires);

    let got: [u32; 8] = <[u32; 8]>::from_lsb0_iter(out.iter().map(|g| g.0));
    assert_eq!(got, expected);

    // Every AND gate appends one bit to the witness tape.
    assert!(!witness.is_empty());
}

#[test]
fn sha256_quicksilver_batch_check_accepts() {
    let mut rng = StdRng::seed_from_u64(1);
    let msg: [u32; 16] = core::array::from_fn(|_| rng.random());

    let input_bits: Vec<bool> = msg.iter_lsb0().chain(H0.iter_lsb0()).collect();

    // Count AND gates by running the circuit once on plain bits
    // (`WitnessCtx`). Only used to size the sVOLE tape.
    let gate_count = {
        let mut witness = Vec::new();
        let mut ctx = WitnessCtx {
            witness: &mut witness,
        };
        let msg_wires: [Gf2; 512] = <[Gf2; 512]>::from_lsb0_iter(msg.iter_lsb0());
        let state_wires: [Gf2; 256] = <[Gf2; 256]>::from_lsb0_iter(H0.iter_lsb0());
        let _ = sha256_compress(&mut ctx, msg_wires, state_wires);
        witness.len()
    };

    let input_count = input_bits.len();
    let main_cost = input_count + gate_count;
    let total_svole = main_cost + VOPE_COST;
    println!(
        "sVOLE used: {total_svole} (inputs: {input_count}, gates: {gate_count}, vope: {VOPE_COST})",
    );
    let (delta, raw_keys, choices, macs) = sample_rcot(&mut rng, total_svole);
    let vope_choices: [bool; VOPE_COST] = core::array::from_fn(|i| choices[main_cost + i]);
    let vope_ev: [Gf2_128; VOPE_COST] = core::array::from_fn(|i| macs[main_cost + i]);
    let vope_keys: [Gf2_128; VOPE_COST] = core::array::from_fn(|i| raw_keys[main_cost + i]);

    // Verifier samples the consistency-check challenge after the prover
    // commits (here both sides simply share the same value).
    let chi: [u8; 32] = rng.random();

    // Caller builds input commits: input_adjust[i] = bit ^ choice,
    // input MAC has LSB set to the bit.
    let input_adjust: BitVec = (0..input_count)
        .map(|i| input_bits[i] ^ choices[i])
        .collect();
    let input_mac_wires: Vec<Gf2_128> = (0..input_count)
        .map(|i| set_lsb(macs[i], input_bits[i]))
        .collect();

    // Gate tape slices (caller-owned). `gate_masks` is mutated in
    // place by `prover.execute`: after `finish` it holds the masked
    // witness adjust bits.
    let mut gate_masks: Vec<bool> = choices[input_count..main_cost].to_vec();
    let gate_macs: Vec<Gf2_128> = macs[input_count..main_cost].to_vec();

    // ---- PROVER side ----
    let mut prover = Prover::new();
    let prover_out = {
        let mut exec = prover
            .execute(&mut gate_masks, &gate_macs)
            .expect("execute");
        let msg_p: [Gf2_128; 512] = core::array::from_fn(|i| input_mac_wires[i]);
        let state_p: [Gf2_128; 256] = core::array::from_fn(|i| input_mac_wires[512 + i]);
        let out = sha256_compress(&mut exec, msg_p, state_p);
        exec.finish().expect("finish");
        out
    };
    let proof = prover.prove(chi, &vope_choices, &vope_ev);

    // ---- VERIFIER side ----
    // Caller pre-adjusts input keys off-band.
    let input_key_wires: Vec<Gf2_128> = (0..input_count)
        .map(|i| {
            let k = raw_keys[i];
            let key = if input_adjust[i] { k + delta } else { k };
            set_lsb(key, false)
        })
        .collect();

    let gate_keys: Vec<Gf2_128> = raw_keys[input_count..main_cost].to_vec();

    let mut verifier = Verifier::new(delta);
    let verifier_out = {
        let mut exec = verifier
            .execute(&gate_keys, &gate_masks)
            .expect("execute");
        let msg_v: [Gf2_128; 512] = core::array::from_fn(|i| input_key_wires[i]);
        let state_v: [Gf2_128; 256] = core::array::from_fn(|i| input_key_wires[512 + i]);
        let out = sha256_compress(&mut exec, msg_v, state_v);
        exec.finish().expect("finish");
        out
    };

    // Output IT-MAC sanity: MAC == key + b·delta for each output bit.
    let expected_bits = sha2_compress_out_bits(msg, H0);
    for i in 0..prover_out.len() {
        let expected = if expected_bits[i] {
            verifier_out[i] + delta
        } else {
            verifier_out[i]
        };
        assert_eq!(prover_out[i], expected, "output bit {i}");
    }

    verifier
        .verify(chi, &vope_keys, proof)
        .expect("batch check should accept a consistent execution");
}

/// SHA-256 compression output as a flat bit array (LSB-first within
/// each u32), computed by the `sha2` crate.
fn sha2_compress_out_bits(msg_words: [u32; 16], state: [u32; 8]) -> [bool; 256] {
    let mut bytes = [0u8; 64];
    for (i, w) in msg_words.iter().enumerate() {
        bytes[i * 4..(i + 1) * 4].copy_from_slice(&w.to_be_bytes());
    }
    let out = sha2_crate_compress(&bytes, state);
    <[bool; 256]>::from_lsb0_iter(out.iter_lsb0())
}
