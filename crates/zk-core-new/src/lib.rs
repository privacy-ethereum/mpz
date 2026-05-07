//! QuickSilver zk protocol https://eprint.iacr.org/2021/076

pub(crate) mod check;
mod prover;
pub(crate) mod util;
mod verifier;
pub(crate) mod vope;

pub use prover::{Prover, ProverExecute};
pub use verifier::{Verifier, VerifierExecute};

use mpz_core::bitvec::BitVec;
use mpz_fields::gf2_128::Gf2_128;

/// Result type.
pub type Result<T, E = Error> = core::result::Result<T, E>;

/// Public-0 MAC.
pub(crate) const MAC_ZERO: Gf2_128 = Gf2_128::new(u128::from_le_bytes([
    146, 239, 91, 41, 80, 62, 197, 196, 204, 121, 176, 38, 171, 216, 63, 120,
]));

/// Public-1 MAC.
pub(crate) const MAC_ONE: Gf2_128 = Gf2_128::new(u128::from_le_bytes([
    219, 104, 26, 50, 91, 130, 201, 178, 144, 31, 95, 155, 206, 113, 5, 103,
]));

/// Masked witness sent from the Prover to the Verifier.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MaskedWitness {
    pub(crate) bits: BitVec,
}

impl MaskedWitness {
    /// Returns the length (in bits) of the witness.
    pub fn len(&self) -> usize {
        self.bits.len()
    }

    /// Returns `true` if the witness is empty.
    pub fn is_empty(&self) -> bool {
        self.bits.is_empty()
    }
}

/// Proof message sent from Prover to the Verifier.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Proof {
    pub(crate) assertions: [u8; 32],
    pub(crate) u: Gf2_128,
    pub(crate) v: Gf2_128,
}

/// Error type.
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

    pub(crate) fn witness_len(expected: usize, actual: usize) -> Self {
        Self(ErrorRepr::WitnessLength { expected, actual })
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
    #[error("prover sent incorrect witness length, expected {expected} got {actual}")]
    WitnessLength { expected: usize, actual: usize },
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
    use blake3::Hasher;
    use itybity::ToBits;
    use mpz_circuits_new::{
        Context,
        sha256::{AND_PER_BLOCK, H0, compress},
    };
    use mpz_core::bitvec::BitVec;
    use mpz_fields::gf2_128::Gf2_128;
    use rand::{Rng, SeedableRng, rngs::StdRng};

    use super::{Error, ErrorRepr, MaskedWitness, Prover, Verifier, util::set_lsb};

    /// Random `delta` with `lsb = 1`.
    fn random_delta(rng: &mut StdRng) -> Gf2_128 {
        let mut d = Gf2_128::new(rng.random());
        set_lsb(&mut d, true);
        d
    }

    /// One sVOLE correlation. Returns `(choice, mac, key)` with
    /// `mac = key + choice·delta`.
    fn corr(rng: &mut StdRng, delta: Gf2_128) -> (bool, Gf2_128, Gf2_128) {
        let choice: bool = rng.random();
        let key = Gf2_128::new(rng.random());
        let mac = if choice { key + delta } else { key };
        (choice, mac, key)
    }

    /// IT-MAC pair for a committed input bit `b`. Verifier's key has
    /// LSB cleared and prover's MAC has LSB set to `b`.
    fn input(rng: &mut StdRng, b: bool, delta: Gf2_128) -> (Gf2_128, Gf2_128) {
        let mut key = Gf2_128::new(rng.random());
        set_lsb(&mut key, false);
        let mac = if b { key + delta } else { key };
        (mac, key)
    }

    /// One full sha256-compress round of correlations: msg + state
    /// input wires, AND-gate tape, and VOPE tape. Returned as a flat
    /// data record so tests can mutate fields directly.
    struct Inputs {
        delta: Gf2_128,
        msg_macs: [Gf2_128; 512],
        msg_keys: [Gf2_128; 512],
        state_macs: [Gf2_128; 256],
        state_keys: [Gf2_128; 256],
        gate_masks: BitVec,
        gate_macs: Vec<Gf2_128>,
        gate_keys: Vec<Gf2_128>,
        vope_choices: [bool; 128],
        vope_ev: [Gf2_128; 128],
        vope_keys: [Gf2_128; 128],
    }

    fn inputs(seed: u64) -> Inputs {
        let mut rng = StdRng::seed_from_u64(seed);
        let delta = random_delta(&mut rng);

        let msg_words: [u32; 16] = core::array::from_fn(|_| rng.random());
        let msg_bits: Vec<bool> = msg_words.iter_lsb0().collect();
        let state_bits: Vec<bool> = H0.iter_lsb0().collect();

        let msg_pairs: Vec<(Gf2_128, Gf2_128)> =
            msg_bits.iter().map(|&b| input(&mut rng, b, delta)).collect();
        let state_pairs: Vec<(Gf2_128, Gf2_128)> = state_bits
            .iter()
            .map(|&b| input(&mut rng, b, delta))
            .collect();
        let msg_macs: [Gf2_128; 512] = core::array::from_fn(|i| msg_pairs[i].0);
        let msg_keys: [Gf2_128; 512] = core::array::from_fn(|i| msg_pairs[i].1);
        let state_macs: [Gf2_128; 256] = core::array::from_fn(|i| state_pairs[i].0);
        let state_keys: [Gf2_128; 256] = core::array::from_fn(|i| state_pairs[i].1);

        let gates: Vec<_> = (0..AND_PER_BLOCK).map(|_| corr(&mut rng, delta)).collect();
        let gate_masks: BitVec = gates.iter().map(|(c, _, _)| *c).collect();
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
        }
    }

    #[test]
    fn happy_path() {
        let i = inputs(1);

        let mut prover = Prover::new();
        let mut pt = Hasher::default();
        let masked = {
            let mut exec = prover.execute(&i.gate_masks, &i.gate_macs).unwrap();
            let _ = compress(&mut exec, i.msg_macs, i.state_macs);
            exec.finish(&mut pt).unwrap()
        };
        let proof = prover.prove(&mut pt, &i.vope_choices, &i.vope_ev);

        let mut verifier = Verifier::new(i.delta);
        let mut vt = Hasher::default();
        {
            let mut exec = verifier.execute(&i.gate_keys, masked).unwrap();
            let _ = compress(&mut exec, i.msg_keys, i.state_keys);
            exec.finish(&mut vt).unwrap();
        }
        verifier.verify(&mut vt, &i.vope_keys, proof).unwrap();
    }

    #[test]
    fn corrupted_triple_rejected() {
        // Run an honest prover; corrupt a verifier gate key before
        // its execute pass so its triple's z doesn't match.
        let mut i = inputs(2);

        let mut prover = Prover::new();
        let mut pt = Hasher::default();
        let masked = {
            let mut exec = prover.execute(&i.gate_masks, &i.gate_macs).unwrap();
            let _ = compress(&mut exec, i.msg_macs, i.state_macs);
            exec.finish(&mut pt).unwrap()
        };
        let proof = prover.prove(&mut pt, &i.vope_choices, &i.vope_ev);

        i.gate_keys[0] =
            i.gate_keys[0] + Gf2_128::new(0xdead_beef_dead_beef_dead_beef_dead_beef);

        let mut verifier = Verifier::new(i.delta);
        let mut vt = Hasher::default();
        {
            let mut exec = verifier.execute(&i.gate_keys, masked).unwrap();
            let _ = compress(&mut exec, i.msg_keys, i.state_keys);
            exec.finish(&mut vt).unwrap();
        }
        let Error(repr) = verifier.verify(&mut vt, &i.vope_keys, proof).unwrap_err();
        assert!(matches!(repr, ErrorRepr::Check));
    }

    #[test]
    fn corrupted_assertion_rejected() {
        // sha256-compress doesn't call `assert`, so flipping a bit
        // in the proof's assertions hash makes it differ from the
        // verifier's expected (empty) hash.
        let i = inputs(3);

        let mut prover = Prover::new();
        let mut pt = Hasher::default();
        let masked = {
            let mut exec = prover.execute(&i.gate_masks, &i.gate_macs).unwrap();
            let _ = compress(&mut exec, i.msg_macs, i.state_macs);
            exec.finish(&mut pt).unwrap()
        };
        let mut proof = prover.prove(&mut pt, &i.vope_choices, &i.vope_ev);
        proof.assertions[0] ^= 1;

        let mut verifier = Verifier::new(i.delta);
        let mut vt = Hasher::default();
        {
            let mut exec = verifier.execute(&i.gate_keys, masked).unwrap();
            let _ = compress(&mut exec, i.msg_keys, i.state_keys);
            exec.finish(&mut vt).unwrap();
        }
        let Error(repr) = verifier.verify(&mut vt, &i.vope_keys, proof).unwrap_err();
        assert!(matches!(repr, ErrorRepr::Assert));
    }

    #[test]
    fn masked_witness_length_mismatch_rejected() {
        let i = inputs(4);

        // Witness one bit shorter than the gate tape.
        let mut bits = BitVec::new();
        bits.resize(i.gate_keys.len() - 1, false);
        let bad = MaskedWitness { bits };

        let mut verifier = Verifier::new(i.delta);
        let Error(repr) = verifier.execute(&i.gate_keys, bad).unwrap_err();
        assert!(matches!(repr, ErrorRepr::WitnessLength { .. }));
    }

    #[test]
    fn wrong_vope_keys_rejected() {
        let mut i = inputs(5);

        let mut prover = Prover::new();
        let mut pt = Hasher::default();
        let masked = {
            let mut exec = prover.execute(&i.gate_masks, &i.gate_macs).unwrap();
            let _ = compress(&mut exec, i.msg_macs, i.state_macs);
            exec.finish(&mut pt).unwrap()
        };
        let proof = prover.prove(&mut pt, &i.vope_choices, &i.vope_ev);

        let mut verifier = Verifier::new(i.delta);
        let mut vt = Hasher::default();
        {
            let mut exec = verifier.execute(&i.gate_keys, masked).unwrap();
            let _ = compress(&mut exec, i.msg_keys, i.state_keys);
            exec.finish(&mut vt).unwrap();
        }
        i.vope_keys[0] =
            i.vope_keys[0] + Gf2_128::new(0xfeed_face_feed_face_feed_face_feed_face);
        let Error(repr) = verifier.verify(&mut vt, &i.vope_keys, proof).unwrap_err();
        assert!(matches!(repr, ErrorRepr::Check));
    }

    #[test]
    fn prover_tape_length_mismatch_rejected() {
        let mut prover = Prover::new();
        let masks: BitVec = BitVec::new();
        let macs = [Gf2_128::new(0)];
        let Error(repr) = prover.execute(&masks, &macs).unwrap_err();
        assert!(matches!(repr, ErrorRepr::TapeLength { .. }));
    }

    #[test]
    fn check_depends_on_chi() {
        // Two transcripts differing only in a prefix produce
        // different (u, v) — confirms the check actually consumes
        // the transcript-derived χ.
        let i = inputs(7);

        let run = |prefix: Option<&[u8]>| {
            let mut prover = Prover::new();
            let mut t = Hasher::default();
            if let Some(p) = prefix {
                t.update(p);
            }
            {
                let mut exec = prover.execute(&i.gate_masks, &i.gate_macs).unwrap();
                let _ = compress(&mut exec, i.msg_macs, i.state_macs);
                let _ = exec.finish(&mut t).unwrap();
            }
            prover.prove(&mut t, &i.vope_choices, &i.vope_ev)
        };

        let a = run(None);
        let b = run(Some(b"different transcript prefix"));
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

        let gate_masks: BitVec = BitVec::new();
        let gate_macs: Vec<Gf2_128> = Vec::new();
        let gate_keys: Vec<Gf2_128> = Vec::new();
        let vope: [(bool, Gf2_128, Gf2_128); 128] = core::array::from_fn(|_| corr(&mut rng, delta));
        let vope_choices: [bool; 128] = core::array::from_fn(|i| vope[i].0);
        let vope_ev: [Gf2_128; 128] = core::array::from_fn(|i| vope[i].1);
        let vope_keys: [Gf2_128; 128] = core::array::from_fn(|i| vope[i].2);

        let mut prover = Prover::new();
        let mut pt = Hasher::default();
        let masked = {
            let mut exec = prover.execute(&gate_masks, &gate_macs).unwrap();
            exec.assert_eq(mac_a, mac_b).unwrap();
            exec.finish(&mut pt).unwrap()
        };
        let proof = prover.prove(&mut pt, &vope_choices, &vope_ev);

        let mut verifier = Verifier::new(delta);
        let mut vt = Hasher::default();
        {
            let mut exec = verifier.execute(&gate_keys, masked).unwrap();
            exec.assert_eq(key_a, key_b).unwrap();
            exec.finish(&mut vt).unwrap();
        }
        verifier.verify(&mut vt, &vope_keys, proof).unwrap();
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

        let gate_masks: BitVec = BitVec::new();
        let gate_macs: Vec<Gf2_128> = Vec::new();

        let mut prover = Prover::new();
        let mut exec = prover.execute(&gate_masks, &gate_macs).unwrap();
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
        let (mac_a, key_a) = input(&mut rng, true, delta);
        let (mac_b, key_b) = input(&mut rng, false, delta);

        let gate_masks: BitVec = BitVec::new();
        let gate_macs: Vec<Gf2_128> = Vec::new();
        let gate_keys: Vec<Gf2_128> = Vec::new();
        let vope: [(bool, Gf2_128, Gf2_128); 128] = core::array::from_fn(|_| corr(&mut rng, delta));
        let vope_choices: [bool; 128] = core::array::from_fn(|i| vope[i].0);
        let vope_ev: [Gf2_128; 128] = core::array::from_fn(|i| vope[i].1);
        let vope_keys: [Gf2_128; 128] = core::array::from_fn(|i| vope[i].2);

        // Prover skips the assertion (simulating a malicious party).
        let mut prover = Prover::new();
        let mut pt = Hasher::default();
        let masked = {
            let exec = prover.execute(&gate_masks, &gate_macs).unwrap();
            // No assert_eq call here.
            exec.finish(&mut pt).unwrap()
        };
        let proof = prover.prove(&mut pt, &vope_choices, &vope_ev);

        // Verifier honestly performs the assertion.
        let mut verifier = Verifier::new(delta);
        let mut vt = Hasher::default();
        {
            let mut exec = verifier.execute(&gate_keys, masked).unwrap();
            exec.assert_eq(key_a, key_b).unwrap();
            exec.finish(&mut vt).unwrap();
        }
        let Error(repr) = verifier.verify(&mut vt, &vope_keys, proof).unwrap_err();
        assert!(matches!(repr, ErrorRepr::Assert));
    }
}
