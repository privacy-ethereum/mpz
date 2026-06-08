//! Core building blocks for the designated-verifier zero-knowledge proof system.
//!
//! The protocol runs a boolean circuit between a [`Prover`] and a [`Verifier`].
//! Evaluating the circuit on each side records the information needed to prove
//! and check the computation. The prover then produces a [`Proof`] with
//! [`Prover::prove`], which the verifier checks with [`Verifier::verify`].
//!
//! The two parties drive circuit evaluation through the [`ProverExecute`] and
//! [`VerifierExecute`] handles obtained from [`Prover::execute`] and
//! [`Verifier::execute`]. A [`Commit`] carries the adjustment bits the prover
//! sends to the verifier so both sides agree on the values consumed during
//! evaluation.
//!
//! Errors surfaced by these operations are reported via [`Error`] and the
//! crate-wide [`Result`] alias.

mod check;
mod prover;
mod util;
mod verifier;
mod vope;

pub use prover::{Prover, ProverExecute};
pub use verifier::{Verifier, VerifierExecute};

use mpz_core::bitvec::BitVec;
use mpz_fields::gf2_128::Gf2_128;

/// A specialized [`Result`](core::result::Result) type for this crate's operations.
///
/// Defaults the error type to [`Error`].
pub type Result<T, E = Error> = core::result::Result<T, E>;

pub(crate) const MAC_ZERO: Gf2_128 = Gf2_128::new(u128::from_le_bytes([
    146, 239, 91, 41, 80, 62, 197, 196, 204, 121, 176, 38, 171, 216, 63, 120,
]));

pub(crate) const MAC_ONE: Gf2_128 = Gf2_128::new(u128::from_le_bytes([
    219, 104, 26, 50, 91, 130, 201, 178, 144, 31, 95, 155, 206, 113, 5, 103,
]));

/// The prover's commitment to the values consumed during circuit evaluation.
///
/// Sent from the prover to the verifier so both sides agree on the adjustments
/// applied during evaluation.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Commit {
    /// The adjustment bits, one per entry consumed in evaluation order.
    pub adjust: BitVec,
}

/// A zero-knowledge proof produced by the prover over an evaluated circuit.
///
/// Produced by [`Prover::prove`] and consumed by [`Verifier::verify`].
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Proof {
    pub(crate) assertions: [u8; 32],
    pub(crate) u: Gf2_128,
    pub(crate) v: Gf2_128,
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

    pub(crate) fn check() -> Self {
        Self(ErrorRepr::Check)
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
    #[error("consistency check failed")]
    Check,
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
    use mpz_circuits::{
        Context,
        sha256::{AND_PER_BLOCK, H0, compress},
    };
    use mpz_fields::gf2_128::Gf2_128;
    use rand::{Rng, SeedableRng, rngs::StdRng};

    use super::{Error, ErrorRepr, Prover, Verifier, util::set_lsb};

    fn random_delta(rng: &mut StdRng) -> Gf2_128 {
        let mut d = Gf2_128::new(rng.random());
        set_lsb(&mut d, true);
        d
    }

    fn corr(rng: &mut StdRng, delta: Gf2_128) -> (bool, Gf2_128, Gf2_128) {
        let choice: bool = rng.random();
        let key = Gf2_128::new(rng.random());
        let mac = if choice { key + delta } else { key };
        (choice, mac, key)
    }

    fn input(rng: &mut StdRng, b: bool, delta: Gf2_128) -> (Gf2_128, Gf2_128) {
        let mut key = Gf2_128::new(rng.random());
        set_lsb(&mut key, false);
        let mac = if b { key + delta } else { key };
        (mac, key)
    }

    struct Inputs {
        delta: Gf2_128,
        msg_macs: [Gf2_128; 512],
        msg_keys: [Gf2_128; 512],
        state_macs: [Gf2_128; 256],
        state_keys: [Gf2_128; 256],
        gate_masks: Vec<bool>,
        gate_macs: Vec<Gf2_128>,
        gate_keys: Vec<Gf2_128>,
        vope_choices: [bool; 128],
        vope_ev: [Gf2_128; 128],
        vope_keys: [Gf2_128; 128],
        chi: [u8; 32],
    }

    fn inputs(seed: u64) -> Inputs {
        let mut rng = StdRng::seed_from_u64(seed);
        let delta = random_delta(&mut rng);
        let chi: [u8; 32] = rng.random();

        let msg_words: [u32; 16] = core::array::from_fn(|_| rng.random());
        let msg_bits: Vec<bool> = msg_words.iter_lsb0().collect();
        let state_bits: Vec<bool> = H0.iter_lsb0().collect();

        let msg_pairs: Vec<(Gf2_128, Gf2_128)> = msg_bits
            .iter()
            .map(|&b| input(&mut rng, b, delta))
            .collect();
        let state_pairs: Vec<(Gf2_128, Gf2_128)> = state_bits
            .iter()
            .map(|&b| input(&mut rng, b, delta))
            .collect();
        let msg_macs: [Gf2_128; 512] = core::array::from_fn(|i| msg_pairs[i].0);
        let msg_keys: [Gf2_128; 512] = core::array::from_fn(|i| msg_pairs[i].1);
        let state_macs: [Gf2_128; 256] = core::array::from_fn(|i| state_pairs[i].0);
        let state_keys: [Gf2_128; 256] = core::array::from_fn(|i| state_pairs[i].1);

        let gates: Vec<_> = (0..AND_PER_BLOCK).map(|_| corr(&mut rng, delta)).collect();
        let gate_masks: Vec<bool> = gates.iter().map(|(c, _, _)| *c).collect();
        let gate_macs: Vec<Gf2_128> = gates.iter().map(|(_, m, _)| *m).collect();
        let gate_keys: Vec<Gf2_128> = gates.iter().map(|(_, _, k)| *k).collect();

        let vope: [(bool, Gf2_128, Gf2_128); 128] = core::array::from_fn(|_| corr(&mut rng, delta));
        let vope_choices: [bool; 128] = core::array::from_fn(|i| vope[i].0);
        let vope_ev: [Gf2_128; 128] = core::array::from_fn(|i| vope[i].1);
        let vope_keys: [Gf2_128; 128] = core::array::from_fn(|i| vope[i].2);

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

    #[test]
    fn happy_path() {
        let i = inputs(1);

        let mut prover = Prover::new();
        let mut masks = i.gate_masks.clone();
        {
            let mut exec = prover.execute(&mut masks, &i.gate_macs).unwrap();
            let _ = compress(&mut exec, i.msg_macs, i.state_macs);
            exec.finish().unwrap();
        }
        let proof = prover.prove(i.chi, &i.vope_choices, &i.vope_ev);

        let mut verifier = Verifier::new(i.delta);
        {
            let mut exec = verifier.execute(&i.gate_keys, &masks).unwrap();
            let _ = compress(&mut exec, i.msg_keys, i.state_keys);
            exec.finish().unwrap();
        }
        verifier.verify(i.chi, &i.vope_keys, proof).unwrap();
    }

    #[test]
    fn corrupted_triple_rejected() {
        // Run an honest prover; corrupt a verifier gate key before
        // its execute pass so its triple's z doesn't match.
        let mut i = inputs(2);

        let mut prover = Prover::new();
        let mut masks = i.gate_masks.clone();
        {
            let mut exec = prover.execute(&mut masks, &i.gate_macs).unwrap();
            let _ = compress(&mut exec, i.msg_macs, i.state_macs);
            exec.finish().unwrap();
        }
        let proof = prover.prove(i.chi, &i.vope_choices, &i.vope_ev);

        i.gate_keys[0] = i.gate_keys[0] + Gf2_128::new(0xdead_beef_dead_beef_dead_beef_dead_beef);

        let mut verifier = Verifier::new(i.delta);
        {
            let mut exec = verifier.execute(&i.gate_keys, &masks).unwrap();
            let _ = compress(&mut exec, i.msg_keys, i.state_keys);
            exec.finish().unwrap();
        }
        let Error(repr) = verifier.verify(i.chi, &i.vope_keys, proof).unwrap_err();
        assert!(matches!(repr, ErrorRepr::Check));
    }

    #[test]
    fn corrupted_assertion_rejected() {
        // sha256-compress doesn't call `assert`, so flipping a bit
        // in the proof's assertions hash makes it differ from the
        // verifier's expected (empty) hash.
        let i = inputs(3);

        let mut prover = Prover::new();
        let mut masks = i.gate_masks.clone();
        {
            let mut exec = prover.execute(&mut masks, &i.gate_macs).unwrap();
            let _ = compress(&mut exec, i.msg_macs, i.state_macs);
            exec.finish().unwrap();
        }
        let mut proof = prover.prove(i.chi, &i.vope_choices, &i.vope_ev);
        proof.assertions[0] ^= 1;

        let mut verifier = Verifier::new(i.delta);
        {
            let mut exec = verifier.execute(&i.gate_keys, &masks).unwrap();
            let _ = compress(&mut exec, i.msg_keys, i.state_keys);
            exec.finish().unwrap();
        }
        let Error(repr) = verifier.verify(i.chi, &i.vope_keys, proof).unwrap_err();
        assert!(matches!(repr, ErrorRepr::Assert));
    }

    #[test]
    fn verifier_tape_length_mismatch_rejected() {
        let i = inputs(4);

        // Adjust slice one bit shorter than the key tape.
        let bad_adjust = vec![false; i.gate_keys.len() - 1];

        let mut verifier = Verifier::new(i.delta);
        let Error(repr) = verifier
            .execute(&i.gate_keys, &bad_adjust)
            .unwrap_err();
        assert!(matches!(repr, ErrorRepr::TapeLength { .. }));
    }

    #[test]
    fn wrong_vope_keys_rejected() {
        let mut i = inputs(5);

        let mut prover = Prover::new();
        let mut masks = i.gate_masks.clone();
        {
            let mut exec = prover.execute(&mut masks, &i.gate_macs).unwrap();
            let _ = compress(&mut exec, i.msg_macs, i.state_macs);
            exec.finish().unwrap();
        }
        let proof = prover.prove(i.chi, &i.vope_choices, &i.vope_ev);

        let mut verifier = Verifier::new(i.delta);
        {
            let mut exec = verifier.execute(&i.gate_keys, &masks).unwrap();
            let _ = compress(&mut exec, i.msg_keys, i.state_keys);
            exec.finish().unwrap();
        }
        i.vope_keys[0] = i.vope_keys[0] + Gf2_128::new(0xfeed_face_feed_face_feed_face_feed_face);
        let Error(repr) = verifier.verify(i.chi, &i.vope_keys, proof).unwrap_err();
        assert!(matches!(repr, ErrorRepr::Check));
    }

    #[test]
    fn prover_tape_length_mismatch_rejected() {
        let mut prover = Prover::new();
        let mut masks: Vec<bool> = Vec::new();
        let macs = [Gf2_128::new(0)];
        let Error(repr) = prover.execute(&mut masks, &macs).unwrap_err();
        assert!(matches!(repr, ErrorRepr::TapeLength { .. }));
    }

    #[test]
    fn check_depends_on_chi() {
        // Two runs that differ only in the challenge produce different
        // (u, v) — confirms the check actually consumes χ.
        let i = inputs(7);

        let run = |chi: [u8; 32]| {
            let mut prover = Prover::new();
            let mut masks = i.gate_masks.clone();
            {
                let mut exec = prover.execute(&mut masks, &i.gate_macs).unwrap();
                let _ = compress(&mut exec, i.msg_macs, i.state_macs);
                exec.finish().unwrap();
            }
            prover.prove(chi, &i.vope_choices, &i.vope_ev)
        };

        let a = run([1u8; 32]);
        let b = run([2u8; 32]);
        assert_ne!((a.u, a.v), (b.u, b.v));
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
        let gate_macs: Vec<Gf2_128> = Vec::new();
        let gate_keys: Vec<Gf2_128> = Vec::new();
        let vope: [(bool, Gf2_128, Gf2_128); 128] = core::array::from_fn(|_| corr(&mut rng, delta));
        let vope_choices: [bool; 128] = core::array::from_fn(|i| vope[i].0);
        let vope_ev: [Gf2_128; 128] = core::array::from_fn(|i| vope[i].1);
        let vope_keys: [Gf2_128; 128] = core::array::from_fn(|i| vope[i].2);
        let chi: [u8; 32] = rng.random();

        let mut prover = Prover::new();
        {
            let mut exec = prover.execute(&mut gate_masks, &gate_macs).unwrap();
            exec.assert_eq(mac_a, mac_b).unwrap();
            exec.finish().unwrap();
        }
        let proof = prover.prove(chi, &vope_choices, &vope_ev);

        let mut verifier = Verifier::new(delta);
        {
            let mut exec = verifier.execute(&gate_keys, &gate_masks).unwrap();
            exec.assert_eq(key_a, key_b).unwrap();
            exec.finish().unwrap();
        }
        verifier.verify(chi, &vope_keys, proof).unwrap();
    }

    #[test]
    fn assert_eq_unequal_returns_err_on_prover() {
        // Prover-side `assert_eq` on two wires committed to
        // different bits short-circuits with `Error::Assert` (the
        // `got != expected` check inside `assert_const`).
        let mut rng = StdRng::seed_from_u64(9);
        let delta = random_delta(&mut rng);
        let (mac_a, _) = input(&mut rng, true, delta);
        let (mac_b, _) = input(&mut rng, false, delta);

        let mut gate_masks: Vec<bool> = Vec::new();
        let gate_macs: Vec<Gf2_128> = Vec::new();

        let mut prover = Prover::new();
        let mut exec = prover.execute(&mut gate_masks, &gate_macs).unwrap();
        let Error(repr) = exec.assert_eq(mac_a, mac_b).unwrap_err();
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
        let gate_macs: Vec<Gf2_128> = Vec::new();
        let gate_keys: Vec<Gf2_128> = Vec::new();
        let vope: [(bool, Gf2_128, Gf2_128); 128] = core::array::from_fn(|_| corr(&mut rng, delta));
        let vope_choices: [bool; 128] = core::array::from_fn(|i| vope[i].0);
        let vope_ev: [Gf2_128; 128] = core::array::from_fn(|i| vope[i].1);
        let vope_keys: [Gf2_128; 128] = core::array::from_fn(|i| vope[i].2);
        let chi: [u8; 32] = rng.random();

        // Prover skips the assertion (simulating a malicious party).
        let mut prover = Prover::new();
        {
            let exec = prover.execute(&mut gate_masks, &gate_macs).unwrap();
            // No assert_eq call here.
            exec.finish().unwrap();
        }
        let proof = prover.prove(chi, &vope_choices, &vope_ev);

        // Verifier honestly performs the assertion.
        let mut verifier = Verifier::new(delta);
        {
            let mut exec = verifier.execute(&gate_keys, &gate_masks).unwrap();
            exec.assert_eq(key_a, key_b).unwrap();
            exec.finish().unwrap();
        }
        let Error(repr) = verifier.verify(chi, &vope_keys, proof).unwrap_err();
        assert!(matches!(repr, ErrorRepr::Assert));
    }
}
