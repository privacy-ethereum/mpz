//! Core building blocks for the designated-verifier zero-knowledge proof system.
//!
//! The protocol runs a boolean circuit between a [`Prover`] and a [`Verifier`].
//!
//! The prover walks the circuits twice. The commit pass ([`prover::Commit`])
//! adjusts the mask tape in place; the adjustment bits are sent to the
//! verifier (see [`Commitment`]). Once committed ([`prover::Committed`]), the
//! caller installs the challenge stream and the accumulate pass
//! ([`prover::Accumulate`]) folds every multiplication and assertion into the
//! proof, yielding `(u, v, assertions)`, which the caller masks with the VOPE
//! correlation ([`vope_receiver`]) to form a [`Proof`].
//!
//! The verifier starts from the received commitment
//! ([`verifier::Committed`]), installs the challenge stream it sampled, and
//! performs a single accumulate pass ([`verifier::Accumulate`]) over the same
//! circuits, yielding `(w, assertions)`. The caller masks `w` with the VOPE
//! correlation ([`vope_sender`]) and accepts iff `w == u + delta * v` and the
//! assertion hashes match.
//!
//! Errors surfaced by these operations are reported via [`Error`] and the
//! crate-wide [`Result`] alias.

pub mod prover;
mod util;
pub mod verifier;
mod vope;

pub use prover::Prover;
pub use verifier::Verifier;
pub use vope::{vope_receiver, vope_sender};

use mpz_core::bitvec::BitVec;
use mpz_fields::gf2_64::Gf2_64;

/// A specialized [`Result`](core::result::Result) type for this crate's operations.
///
/// Defaults the error type to [`Error`].
pub type Result<T, E = Error> = core::result::Result<T, E>;

/// The authenticated wire carrying a public `false` bit.
///
/// A fixed protocol constant: both the prover's MAC and the verifier's key
/// for a public zero wire.
pub const MAC_ZERO: Gf2_64 = Gf2_64::new(u64::from_le_bytes([
    146, 239, 91, 41, 80, 62, 197, 196,
]));

/// The authenticated wire carrying a public `true` bit on the prover side.
///
/// A fixed protocol constant; the verifier's key for a public one wire is
/// `MAC_ONE + delta`.
pub const MAC_ONE: Gf2_64 = Gf2_64::new(u64::from_le_bytes([
    219, 104, 26, 50, 91, 130, 201, 178,
]));

/// The prover's commitment to the values consumed during circuit evaluation.
///
/// Sent from the prover to the verifier so both sides agree on the adjustments
/// applied during evaluation.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Commitment {
    /// The adjustment bits, one per entry consumed in evaluation order.
    pub adjust: BitVec,
}

/// A zero-knowledge proof produced by the prover over an evaluated circuit.
///
/// Assembled from the output of the prover's accumulate pass, masked with the
/// VOPE correlation ([`vope_receiver`]), and consumed by [`Verifier::verify`].
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Proof {
    /// Hash of the wires asserted during evaluation.
    pub assertions: [u8; 32],
    /// The masked `u` proof accumulator.
    pub u: Gf2_64,
    /// The masked `v` proof accumulator.
    pub v: Gf2_64,
}

/// An error returned by the prover or verifier.
///
/// Returned within the crate-wide [`Result`] alias. The underlying cause is
/// kept opaque; use the [`Display`](std::fmt::Display) representation for
/// diagnostics.
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct Error(#[from] ErrorRepr);

impl Error {
    pub(crate) fn assert() -> Self {
        Self(ErrorRepr::Assert)
    }

    pub(crate) fn tape_len(name: &'static str, expected: usize, actual: usize) -> Self {
        Self(ErrorRepr::TapeLength {
            name,
            expected,
            actual,
        })
    }

    pub(crate) fn tape_unconsumed(consumed: usize, total: usize) -> Self {
        Self(ErrorRepr::TapeUnconsumed { consumed, total })
    }
}

#[derive(Debug, thiserror::Error)]
enum ErrorRepr {
    #[error("witness assertion failed")]
    Assert,
    #[error("tape `{name}` length mismatch: expected {expected}, got {actual}")]
    TapeLength {
        name: &'static str,
        expected: usize,
        actual: usize,
    },
    #[error("circuit consumed {consumed} of {total} tape entries")]
    TapeUnconsumed { consumed: usize, total: usize },
}

#[cfg(test)]
mod tests {
    use itybity::ToBits;
    use mpz_circuits_new::{
        Context,
        sha256::{AND_PER_BLOCK, H0, compress},
    };
    use mpz_fields::gf2_64::Gf2_64;
    use rand::{Rng, SeedableRng, rngs::StdRng};

    use rand_chacha::ChaCha12Rng;

    use super::{
        Error, ErrorRepr, Proof, Prover, Verifier, util::set_lsb, vope_receiver, vope_sender,
    };

    fn random_delta(rng: &mut StdRng) -> Gf2_64 {
        let mut d = Gf2_64::new(rng.random());
        set_lsb(&mut d, true);
        d
    }

    fn corr(rng: &mut StdRng, delta: Gf2_64) -> (bool, Gf2_64, Gf2_64) {
        let choice: bool = rng.random();
        let key = Gf2_64::new(rng.random());
        let mac = if choice { key + delta } else { key };
        (choice, mac, key)
    }

    fn input(rng: &mut StdRng, b: bool, delta: Gf2_64) -> (Gf2_64, Gf2_64) {
        let mut key = Gf2_64::new(rng.random());
        set_lsb(&mut key, false);
        let mac = if b { key + delta } else { key };
        (mac, key)
    }

    struct Inputs {
        delta: Gf2_64,
        msg_macs: [Gf2_64; 512],
        msg_keys: [Gf2_64; 512],
        state_macs: [Gf2_64; 256],
        state_keys: [Gf2_64; 256],
        gate_masks: Vec<bool>,
        gate_macs: Vec<Gf2_64>,
        gate_keys: Vec<Gf2_64>,
        vope_choices: [bool; 64],
        vope_ev: [Gf2_64; 64],
        vope_keys: [Gf2_64; 64],
        chi: [u8; 32],
    }

    fn inputs(seed: u64) -> Inputs {
        let mut rng = StdRng::seed_from_u64(seed);
        let delta = random_delta(&mut rng);
        let chi: [u8; 32] = rng.random();

        let msg_words: [u32; 16] = core::array::from_fn(|_| rng.random());
        let msg_bits: Vec<bool> = msg_words.iter_lsb0().collect();
        let state_bits: Vec<bool> = H0.iter_lsb0().collect();

        let msg_pairs: Vec<(Gf2_64, Gf2_64)> = msg_bits
            .iter()
            .map(|&b| input(&mut rng, b, delta))
            .collect();
        let state_pairs: Vec<(Gf2_64, Gf2_64)> = state_bits
            .iter()
            .map(|&b| input(&mut rng, b, delta))
            .collect();
        let msg_macs: [Gf2_64; 512] = core::array::from_fn(|i| msg_pairs[i].0);
        let msg_keys: [Gf2_64; 512] = core::array::from_fn(|i| msg_pairs[i].1);
        let state_macs: [Gf2_64; 256] = core::array::from_fn(|i| state_pairs[i].0);
        let state_keys: [Gf2_64; 256] = core::array::from_fn(|i| state_pairs[i].1);

        let gates: Vec<_> = (0..AND_PER_BLOCK).map(|_| corr(&mut rng, delta)).collect();
        let gate_masks: Vec<bool> = gates.iter().map(|(c, _, _)| *c).collect();
        let gate_macs: Vec<Gf2_64> = gates.iter().map(|(_, m, _)| *m).collect();
        let gate_keys: Vec<Gf2_64> = gates.iter().map(|(_, _, k)| *k).collect();

        let vope: [(bool, Gf2_64, Gf2_64); 64] = core::array::from_fn(|_| corr(&mut rng, delta));
        let vope_choices: [bool; 64] = core::array::from_fn(|i| vope[i].0);
        let vope_ev: [Gf2_64; 64] = core::array::from_fn(|i| vope[i].1);
        let vope_keys: [Gf2_64; 64] = core::array::from_fn(|i| vope[i].2);

        Inputs {
            delta,
            msg_macs,
            msg_keys,
            state_macs,
            state_keys,
            gate_masks,
            gate_macs,
            gate_keys,
            vope_choices,
            vope_ev,
            vope_keys,
            chi,
        }
    }

    /// Runs the prover's two passes over a single sha256 compression and
    /// returns the masked proof.
    fn prove_compress(i: &Inputs, masks: &mut [bool]) -> Proof {
        let mut prover = Prover::new(masks, &i.gate_macs).unwrap();
        let _ = compress(&mut prover, i.msg_macs, i.state_macs);
        let prover = prover.finish().unwrap();
        let mut prover = prover.accumulate(ChaCha12Rng::from_seed(i.chi));
        let _ = compress(&mut prover, i.msg_macs, i.state_macs);
        let (u, v, assertions) = prover.finish().unwrap();

        let (a_0, a_1) = vope_receiver(&i.vope_choices, &i.vope_ev);
        Proof {
            assertions,
            u: u + a_0,
            v: v + a_1,
        }
    }

    /// Runs the verifier's accumulate pass over a single sha256 compression
    /// and returns `(w, assertions)`.
    fn verify_compress(i: &Inputs, masks: &[bool], gate_keys: &[Gf2_64]) -> (Gf2_64, [u8; 32]) {
        let verifier = Verifier::new(i.delta, gate_keys, masks).unwrap();
        let mut verifier = verifier.accumulate(ChaCha12Rng::from_seed(i.chi));
        let _ = compress(&mut verifier, i.msg_keys, i.state_keys);
        verifier.finish().unwrap()
    }

    #[test]
    fn happy_path() {
        let i = inputs(1);

        let mut masks = i.gate_masks.clone();
        let proof = prove_compress(&i, &mut masks);

        let (w, assertions) = verify_compress(&i, &masks, &i.gate_keys);
        let b = vope_sender(&i.vope_keys);

        assert_eq!(assertions, proof.assertions);
        assert_eq!(w + b, proof.u + i.delta * proof.v);
    }

    #[test]
    fn corrupted_triple_rejected() {
        // Run an honest prover; corrupt a verifier gate key before
        // its accumulate pass so its triple's z doesn't match.
        let mut i = inputs(2);

        let mut masks = i.gate_masks.clone();
        let proof = prove_compress(&i, &mut masks);

        i.gate_keys[0] = i.gate_keys[0] + Gf2_64::new(0xdead_beef_dead_beef);

        let (w, assertions) = verify_compress(&i, &masks, &i.gate_keys);
        let b = vope_sender(&i.vope_keys);

        assert_eq!(assertions, proof.assertions);
        assert_ne!(w + b, proof.u + i.delta * proof.v);
    }

    #[test]
    fn corrupted_assertion_rejected() {
        // sha256-compress doesn't call `assert`, so flipping a bit
        // in the proof's assertions hash makes it differ from the
        // verifier's expected (empty) hash.
        let i = inputs(3);

        let mut masks = i.gate_masks.clone();
        let mut proof = prove_compress(&i, &mut masks);
        proof.assertions[0] ^= 1;

        let (w, assertions) = verify_compress(&i, &masks, &i.gate_keys);
        let b = vope_sender(&i.vope_keys);

        assert_ne!(assertions, proof.assertions);
        assert_eq!(w + b, proof.u + i.delta * proof.v);
    }

    #[test]
    fn verifier_tape_length_mismatch_rejected() {
        let i = inputs(4);

        // Adjust slice one bit shorter than the key tape.
        let bad_adjust = vec![false; i.gate_keys.len() - 1];

        let Error(repr) = Verifier::new(i.delta, &i.gate_keys, &bad_adjust).unwrap_err();
        assert!(matches!(repr, ErrorRepr::TapeLength { .. }));
    }

    #[test]
    fn wrong_vope_keys_rejected() {
        let mut i = inputs(5);

        let mut masks = i.gate_masks.clone();
        let proof = prove_compress(&i, &mut masks);

        let (w, assertions) = verify_compress(&i, &masks, &i.gate_keys);

        i.vope_keys[0] = i.vope_keys[0] + Gf2_64::new(0xfeed_face_feed_face);
        let b = vope_sender(&i.vope_keys);

        assert_eq!(assertions, proof.assertions);
        assert_ne!(w + b, proof.u + i.delta * proof.v);
    }

    #[test]
    fn prover_tape_length_mismatch_rejected() {
        let mut masks: Vec<bool> = Vec::new();
        let macs = [Gf2_64::new(0)];
        let Error(repr) = Prover::new(&mut masks, &macs).unwrap_err();
        assert!(matches!(repr, ErrorRepr::TapeLength { .. }));
    }

    #[test]
    fn check_depends_on_chi() {
        // Two runs that differ only in the challenge produce different
        // (u, v) — confirms the check actually consumes χ.
        let i = inputs(7);

        let run = |chi: [u8; 32]| {
            let mut masks = i.gate_masks.clone();
            let mut prover = Prover::new(&mut masks, &i.gate_macs).unwrap();
            let _ = compress(&mut prover, i.msg_macs, i.state_macs);
            let prover = prover.finish().unwrap();
            let mut prover = prover.accumulate(ChaCha12Rng::from_seed(chi));
            let _ = compress(&mut prover, i.msg_macs, i.state_macs);
            let (u, v, _) = prover.finish().unwrap();
            (u, v)
        };

        let a = run([1u8; 32]);
        let b = run([2u8; 32]);
        assert_ne!(a, b);
    }

    #[test]
    fn assert_eq_round_trip() {
        // Two input wires committed to the same bit; assert_eq must
        // pass on both sides and the proof must verify.
        let mut rng = StdRng::seed_from_u64(8);
        let delta = random_delta(&mut rng);
        let (mac_a, key_a) = input(&mut rng, true, delta);
        let (mac_b, key_b) = input(&mut rng, true, delta);

        let mut gate_masks: Vec<bool> = Vec::new();
        let gate_macs: Vec<Gf2_64> = Vec::new();
        let gate_keys: Vec<Gf2_64> = Vec::new();
        let vope: [(bool, Gf2_64, Gf2_64); 64] = core::array::from_fn(|_| corr(&mut rng, delta));
        let vope_choices: [bool; 64] = core::array::from_fn(|i| vope[i].0);
        let vope_ev: [Gf2_64; 64] = core::array::from_fn(|i| vope[i].1);
        let vope_keys: [Gf2_64; 64] = core::array::from_fn(|i| vope[i].2);
        let chi: [u8; 32] = rng.random();

        let mut prover = Prover::new(&mut gate_masks, &gate_macs).unwrap();
        prover.assert_eq(mac_a, mac_b).unwrap();
        let prover = prover.finish().unwrap();
        let mut prover = prover.accumulate(ChaCha12Rng::from_seed(chi));
        prover.assert_eq(mac_a, mac_b).unwrap();
        let (u, v, assertions) = prover.finish().unwrap();

        let (a_0, a_1) = vope_receiver(&vope_choices, &vope_ev);
        let proof = Proof {
            assertions,
            u: u + a_0,
            v: v + a_1,
        };

        let verifier = Verifier::new(delta, &gate_keys, &gate_masks).unwrap();
        let mut verifier = verifier.accumulate(ChaCha12Rng::from_seed(chi));
        verifier.assert_eq(key_a, key_b).unwrap();
        let (w, v_assertions) = verifier.finish().unwrap();
        let b = vope_sender(&vope_keys);

        assert_eq!(v_assertions, proof.assertions);
        assert_eq!(w + b, proof.u + delta * proof.v);
    }

    #[test]
    fn assert_eq_unequal_returns_err_on_prover() {
        // Prover-side `assert_eq` on two wires committed to different
        // bits short-circuits with `Error::Assert` during the
        // accumulate pass (the `got != expected` check inside
        // `assert_const`).
        let mut rng = StdRng::seed_from_u64(9);
        let delta = random_delta(&mut rng);
        let (mac_a, _) = input(&mut rng, true, delta);
        let (mac_b, _) = input(&mut rng, false, delta);

        let mut gate_masks: Vec<bool> = Vec::new();
        let gate_macs: Vec<Gf2_64> = Vec::new();

        let prover = Prover::new(&mut gate_masks, &gate_macs).unwrap();
        let prover = prover.finish().unwrap();
        let mut prover = prover.accumulate(ChaCha12Rng::from_seed([0u8; 32]));
        let Error(repr) = prover.assert_eq(mac_a, mac_b).unwrap_err();
        assert!(matches!(repr, ErrorRepr::Assert));
    }

    #[test]
    fn assert_eq_dishonest_prover_rejected() {
        // Dishonest prover tries to assert equality between two
        // unequal wires by skipping the local `assert_eq` call (so
        // its `assertions` hash differs from the verifier's
        // expectation, since the verifier still calls `assert_eq`).
        let mut rng = StdRng::seed_from_u64(10);
        let delta = random_delta(&mut rng);
        let (_mac_a, key_a) = input(&mut rng, true, delta);
        let (_mac_b, key_b) = input(&mut rng, false, delta);

        let mut gate_masks: Vec<bool> = Vec::new();
        let gate_macs: Vec<Gf2_64> = Vec::new();
        let gate_keys: Vec<Gf2_64> = Vec::new();
        let vope: [(bool, Gf2_64, Gf2_64); 64] = core::array::from_fn(|_| corr(&mut rng, delta));
        let vope_choices: [bool; 64] = core::array::from_fn(|i| vope[i].0);
        let vope_ev: [Gf2_64; 64] = core::array::from_fn(|i| vope[i].1);
        let vope_keys: [Gf2_64; 64] = core::array::from_fn(|i| vope[i].2);
        let chi: [u8; 32] = rng.random();

        // Prover skips the assertion (simulating a malicious party).
        let prover = Prover::new(&mut gate_masks, &gate_macs).unwrap();
        // No assert_eq call here.
        let prover = prover.finish().unwrap();
        let mut prover = prover.accumulate(ChaCha12Rng::from_seed(chi));
        // No assert_eq call here either.
        let (u, v, assertions) = prover.finish().unwrap();

        let (a_0, a_1) = vope_receiver(&vope_choices, &vope_ev);
        let proof = Proof {
            assertions,
            u: u + a_0,
            v: v + a_1,
        };

        // Verifier honestly performs the assertion.
        let verifier = Verifier::new(delta, &gate_keys, &gate_masks).unwrap();
        let mut verifier = verifier.accumulate(ChaCha12Rng::from_seed(chi));
        verifier.assert_eq(key_a, key_b).unwrap();
        let (w, v_assertions) = verifier.finish().unwrap();
        let b = vope_sender(&vope_keys);

        assert_ne!(v_assertions, proof.assertions);
        assert_eq!(w + b, proof.u + delta * proof.v);
    }
}
