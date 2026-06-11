//! Core building blocks for the designated-verifier zero-knowledge proof
//! system.
//!
//! The protocol runs a boolean circuit between a [`Prover`] and a [`Verifier`].
//!
//! The prover walks the circuits twice. The commit pass ([`Commit`]) is
//! mask-only plaintext evaluation: it XORs each witness bit into the mask
//! tape in place, never touching the MAC tape, and the adjustment bits are
//! sent to the verifier (see [`Commitment`]). For the second pass the caller
//! starts from [`prover::Prover::committed`], installs the challenge stream,
//! and the accumulate pass
//! ([`prover::Accumulate`]) folds every multiplication and assertion into the
//! proof, yielding a [`ProverOutput`], which the caller masks with the VOPE
//! correlation ([`vope_receiver`]) to form a [`Proof`].
//!
//! The verifier starts from the received commitment
//! ([`verifier::Committed`]), installs the challenge stream it sampled, and
//! performs a single accumulate pass ([`verifier::Accumulate`]) over the same
//! circuits, yielding a [`VerifierOutput`]. The caller masks `w` with the VOPE
//! correlation ([`vope_sender`]) and accepts iff `w == u + delta * v` and the
//! assertion hashes match.
//!
//! Both accumulate passes are linear in the challenge weights, so a trace may
//! be folded in disjoint sub-ranges — each over its slice of the tapes with
//! the challenge stream seeked to its gate offset — and the partial results
//! combined by field addition. See [`prover::Prover::committed`].
//!
//! Two extensions reuse the same machinery:
//!
//! - [`PolyContext`] (composite QuickSilver) verifies higher-degree polynomial
//!   constraints `f(w) = 0` directly, rather than committing every intermediate
//!   product — the prover sends `d_max` masked coefficients per proof and the
//!   verifier batches all constraints into one check.
//! - [`gf64`] runs the whole protocol over `GF(2^64)` instead of bits, keeping
//!   the `GF(2^128)` MACs (a subfield IT-MAC). The boolean path's pointer-bit
//!   packing does not generalize, so the prover carries the value explicitly;
//!   both the triple check and [`PolyContext`] are available there too.
//!
//! Errors surfaced by these operations are reported via [`Error`] and the
//! crate-wide [`Result`] alias.

pub mod gf64;
pub mod poly;
pub mod prover;
mod util;
pub mod verifier;
mod vope;

pub use poly::{DeltaPowers, MAX_DEGREE, PolyContext, ProverPoly, VerifierPoly};
pub use prover::{Commit, Prover};
pub use verifier::Verifier;
pub use vope::{vope_receiver, vope_sender};

use mpz_core::bitvec::BitVec;
use mpz_fields::gf2_128::Gf2_128;

/// The output of a prover accumulate pass ([`Prover::finish`] and its
/// [`gf64`] counterpart).
///
/// The caller masks `(u, v)` with the VOPE correlation
/// ([`vope_receiver`]) and the polynomial-check `poly` coefficients
/// ([`ProverPoly::coefficients`]) with the degree-`d_max` VOPE coefficients
/// before assembling a [`Proof`].
#[derive(Debug)]
pub struct ProverOutput {
    /// The `u` proof accumulator (the `Σ χᵢ·MₓMᵧ` body), reduced.
    pub u: Gf2_128,
    /// The `v` proof accumulator (the subfield-scaled body), reduced.
    pub v: Gf2_128,
    /// The polynomial-check coefficients; empty unless [`PolyContext`]
    /// constraints were recorded.
    pub poly: ProverPoly,
    /// Hash of the wires asserted during evaluation.
    pub assertions: [u8; 32],
}

/// The output of a verifier accumulate pass ([`Verifier::finish`] and its
/// [`gf64`] counterpart).
///
/// The caller masks `w` with the VOPE correlation ([`vope_sender`]) and
/// accepts iff `w == u + delta·v`, the assertion hashes match, and the
/// polynomial check passes ([`VerifierPoly::check`]).
#[derive(Debug)]
pub struct VerifierOutput {
    /// The reduced check value `Σ χᵢ·xᵢyᵢ + Δ·Σ χᵢ·zᵢ`.
    pub w: Gf2_128,
    /// The polynomial-check state; empty unless [`PolyContext`] constraints
    /// were recorded.
    pub poly: VerifierPoly,
    /// Hash of the wires asserted during evaluation.
    pub assertions: [u8; 32],
}

/// Materializes the prover's authenticated wire for the tape entry `mac`
/// committed to `bit`.
///
/// This is the stateless core of the prover-side `input`: callers folding a
/// trace in sub-ranges use it to reconstruct wires for tape entries consumed
/// outside their own context (e.g. stitch-boundary commitments).
pub fn prover_wire(mac: Gf2_128, bit: bool) -> Gf2_128 {
    let mut mac = mac;
    util::set_lsb(&mut mac, bit);
    mac
}

/// Materializes the verifier's key wire for the tape entry `key` whose
/// adjustment bit is `adjust`.
///
/// The stateless core of the verifier-side `input`; see [`prover_wire`].
pub fn verifier_wire(key: Gf2_128, adjust: bool, delta: Gf2_128) -> Gf2_128 {
    let mut key = if adjust { key + delta } else { key };
    util::set_lsb(&mut key, false);
    key
}

/// A specialized [`Result`](core::result::Result) type for this crate's
/// operations.
///
/// Defaults the error type to [`Error`].
pub type Result<T, E = Error> = core::result::Result<T, E>;

/// The authenticated wire carrying a public `false` bit.
///
/// A fixed protocol constant: both the prover's MAC and the verifier's key
/// for a public zero wire.
pub const MAC_ZERO: Gf2_128 = Gf2_128::new(u128::from_le_bytes([
    146, 239, 91, 41, 80, 62, 197, 196, 204, 121, 176, 38, 171, 216, 63, 120,
]));

/// The authenticated wire carrying a public `true` bit on the prover side.
///
/// A fixed protocol constant; the verifier's key for a public one wire is
/// `MAC_ONE + delta`.
pub const MAC_ONE: Gf2_128 = Gf2_128::new(u128::from_le_bytes([
    219, 104, 26, 50, 91, 130, 201, 178, 144, 31, 95, 155, 206, 113, 5, 103,
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
/// VOPE correlation ([`vope_receiver`]), and consumed by the verifier.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Proof {
    /// Hash of the wires asserted during evaluation.
    pub assertions: [u8; 32],
    /// The masked `u` proof accumulator.
    pub u: Gf2_128,
    /// The masked `v` proof accumulator.
    pub v: Gf2_128,
    /// Masked coefficients of the polynomial check, degrees
    /// `0 ..= d_max - 1` ([`ProverPoly::coefficients`] plus the degree-`d_max`
    /// VOPE mask coefficients). Empty when no polynomial constraints were
    /// recorded.
    pub coefficients: Vec<Gf2_128>,
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

    pub(crate) fn degree(max_seen: usize, d_max: usize) -> Self {
        Self(ErrorRepr::Degree { max_seen, d_max })
    }

    pub(crate) fn check() -> Self {
        Self(ErrorRepr::Check)
    }
}

#[derive(Debug, thiserror::Error)]
enum ErrorRepr {
    #[error("witness assertion failed")]
    Assert,
    #[error("polynomial check failed")]
    Check,
    #[error("constraint degree {max_seen} exceeds d_max {d_max}")]
    Degree { max_seen: usize, d_max: usize },
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
    use rand_chacha::ChaCha12Rng;

    use super::{
        Commit, DeltaPowers, Error, ErrorRepr, PolyContext, Proof, Prover, ProverOutput, Verifier,
        VerifierOutput, util::set_lsb, vope_receiver, vope_sender,
    };
    use mpz_fields::gf2::Gf2;

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

    /// Runs the prover's two passes over a single sha256 compression and
    /// returns the masked proof.
    fn prove_compress(i: &Inputs, masks: &mut [bool]) -> Proof {
        let mut commit = Commit::new(masks);
        let _ = compress(&mut commit, i.msg_macs, i.state_macs);
        commit.finish().unwrap();
        let mut prover = Prover::committed(&i.gate_macs).accumulate(ChaCha12Rng::from_seed(i.chi));
        let _ = compress(&mut prover, i.msg_macs, i.state_macs);
        let ProverOutput { u, v, assertions, .. } = prover.finish().unwrap();

        let (a_0, a_1) = vope_receiver(&i.vope_choices, &i.vope_ev);
        Proof {
            assertions,
            u: u + a_0,
            v: v + a_1,
            coefficients: Vec::new(),
        }
    }

    /// Runs the verifier's accumulate pass over a single sha256 compression
    /// and returns `(w, assertions)`.
    fn verify_compress(i: &Inputs, masks: &[bool], gate_keys: &[Gf2_128]) -> (Gf2_128, [u8; 32]) {
        let verifier = Verifier::new(i.delta, gate_keys, masks).unwrap();
        let mut verifier = verifier.accumulate(ChaCha12Rng::from_seed(i.chi));
        let _ = compress(&mut verifier, i.msg_keys, i.state_keys);
        let VerifierOutput { w, assertions, .. } = verifier.finish().unwrap();
        (w, assertions)
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

        i.gate_keys[0] = i.gate_keys[0] + Gf2_128::new(0xdead_beef_dead_beef_dead_beef_dead_beef);

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

        i.vope_keys[0] = i.vope_keys[0] + Gf2_128::new(0xfeed_face_feed_face_feed_face_feed_face);
        let b = vope_sender(&i.vope_keys);

        assert_eq!(assertions, proof.assertions);
        assert_ne!(w + b, proof.u + i.delta * proof.v);
    }

    #[test]
    fn prover_tape_mismatch_rejected() {
        // A commit pass that consumes fewer entries than the tape provides.
        let mut masks = vec![false];
        let Error(repr) = Commit::new(&mut masks).finish().unwrap_err();
        assert!(matches!(repr, ErrorRepr::TapeUnconsumed { .. }));

        // An accumulate pass that consumes fewer entries than the tape.
        let macs = [Gf2_128::new(0)];
        let prover = Prover::committed(&macs).accumulate(ChaCha12Rng::from_seed([0; 32]));
        let Error(repr) = prover.finish().unwrap_err();
        assert!(matches!(repr, ErrorRepr::TapeUnconsumed { .. }));
    }

    #[test]
    fn check_depends_on_chi() {
        // Two runs that differ only in the challenge produce different
        // (u, v) — confirms the check actually consumes χ.
        let i = inputs(7);

        let run = |chi: [u8; 32]| {
            let mut masks = i.gate_masks.clone();
            let mut commit = Commit::new(&mut masks);
            let _ = compress(&mut commit, i.msg_macs, i.state_macs);
            commit.finish().unwrap();
            let mut prover =
                Prover::committed(&i.gate_macs).accumulate(ChaCha12Rng::from_seed(chi));
            let _ = compress(&mut prover, i.msg_macs, i.state_macs);
            let ProverOutput { u, v, .. } = prover.finish().unwrap();
            (u, v)
        };

        let a = run([1u8; 32]);
        let b = run([2u8; 32]);
        assert_ne!(a, b);
    }

    #[test]
    fn subrange_folding_matches_full() {
        // Folding a trace as two sub-ranges — each over its tape slice
        // with the challenge stream seeked to its gate offset — must
        // produce partials that sum to the full-trace results on both
        // sides. Each multiplication consumes 16 bytes (4 ChaCha words)
        // of the stream.
        let mut rng = StdRng::seed_from_u64(11);
        let delta = random_delta(&mut rng);
        let chi: [u8; 32] = rng.random();

        const N: usize = 100;
        const MID: usize = 37;

        let gates: Vec<_> = (0..N).map(|_| corr(&mut rng, delta)).collect();
        let mut adjust: Vec<bool> = gates.iter().map(|(c, _, _)| *c).collect();
        let macs: Vec<Gf2_128> = gates.iter().map(|(_, m, _)| *m).collect();
        let keys: Vec<Gf2_128> = gates.iter().map(|(_, _, k)| *k).collect();
        let wires: Vec<(Gf2_128, Gf2_128, Gf2_128, Gf2_128)> = (0..N)
            .map(|_| {
                let (x, y): (bool, bool) = (rng.random(), rng.random());
                let (mac_a, key_a) = input(&mut rng, x, delta);
                let (mac_b, key_b) = input(&mut rng, y, delta);
                (mac_a, mac_b, key_a, key_b)
            })
            .collect();

        // Commit pass over the full trace produces the adjust bits.
        let mut commit = Commit::new(&mut adjust);
        for (a, b, _, _) in &wires {
            let _ = commit.mul(*a, *b);
        }
        commit.finish().unwrap();

        let prover_fold = |macs: &[Gf2_128],
                           wires: &[(Gf2_128, Gf2_128, Gf2_128, Gf2_128)],
                           gate_offset: usize| {
            let mut rng = ChaCha12Rng::from_seed(chi);
            rng.set_word_pos((gate_offset * 4) as u128);
            let mut p = Prover::committed(macs).accumulate(rng);
            for (a, b, _, _) in wires {
                let _ = p.mul(*a, *b);
            }
            let ProverOutput { u, v, .. } = p.finish().unwrap();
            (u, v)
        };

        let verifier_fold = |keys: &[Gf2_128],
                             adjust: &[bool],
                             wires: &[(Gf2_128, Gf2_128, Gf2_128, Gf2_128)],
                             gate_offset: usize| {
            let mut rng = ChaCha12Rng::from_seed(chi);
            rng.set_word_pos((gate_offset * 4) as u128);
            let mut v = Verifier::new(delta, keys, adjust)
                .unwrap()
                .accumulate(rng);
            for (_, _, a, b) in wires {
                let _ = v.mul(*a, *b);
            }
            let VerifierOutput { w, .. } = v.finish().unwrap();
            w
        };

        let (u_full, v_full) = prover_fold(&macs, &wires, 0);
        let (u_lo, v_lo) = prover_fold(&macs[..MID], &wires[..MID], 0);
        let (u_hi, v_hi) = prover_fold(&macs[MID..], &wires[MID..], MID);
        assert_eq!(u_full, u_lo + u_hi);
        assert_eq!(v_full, v_lo + v_hi);

        let w_full = verifier_fold(&keys, &adjust, &wires, 0);
        let w_lo = verifier_fold(&keys[..MID], &adjust[..MID], &wires[..MID], 0);
        let w_hi = verifier_fold(&keys[MID..], &adjust[MID..], &wires[MID..], MID);
        assert_eq!(w_full, w_lo + w_hi);

        // The sub-range partials still satisfy the check equation.
        assert_eq!(w_full, u_full + delta * v_full);
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

        let mut commit = Commit::new(&mut gate_masks);
        commit.assert_eq(mac_a, mac_b).unwrap();
        commit.finish().unwrap();
        let mut prover = Prover::committed(&gate_macs).accumulate(ChaCha12Rng::from_seed(chi));
        prover.assert_eq(mac_a, mac_b).unwrap();
        let ProverOutput { u, v, assertions, .. } = prover.finish().unwrap();

        let (a_0, a_1) = vope_receiver(&vope_choices, &vope_ev);
        let proof = Proof {
            assertions,
            u: u + a_0,
            v: v + a_1,
            coefficients: Vec::new(),
        };

        let verifier = Verifier::new(delta, &gate_keys, &gate_masks).unwrap();
        let mut verifier = verifier.accumulate(ChaCha12Rng::from_seed(chi));
        verifier.assert_eq(key_a, key_b).unwrap();
        let VerifierOutput { w, assertions: v_assertions, .. } = verifier.finish().unwrap();
        let b = vope_sender(&vope_keys);

        assert_eq!(v_assertions, proof.assertions);
        assert_eq!(w + b, proof.u + delta * proof.v);
    }

    #[test]
    fn assert_eq_unequal_returns_err_on_prover() {
        // Prover-side `assert_eq` on two wires committed to different
        // bits short-circuits with `Error::Assert` (the `got != expected`
        // check inside `assert_const`), in both passes.
        let mut rng = StdRng::seed_from_u64(9);
        let delta = random_delta(&mut rng);
        let (mac_a, _) = input(&mut rng, true, delta);
        let (mac_b, _) = input(&mut rng, false, delta);

        let gate_macs: Vec<Gf2_128> = Vec::new();
        let chi: [u8; 32] = rng.random();

        let mut commit = Commit::new(&mut []);
        let Error(repr) = commit.assert_eq(mac_a, mac_b).unwrap_err();
        assert!(matches!(repr, ErrorRepr::Assert));

        let mut prover = Prover::committed(&gate_macs).accumulate(ChaCha12Rng::from_seed(chi));
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
        let gate_macs: Vec<Gf2_128> = Vec::new();
        let gate_keys: Vec<Gf2_128> = Vec::new();
        let vope: [(bool, Gf2_128, Gf2_128); 128] = core::array::from_fn(|_| corr(&mut rng, delta));
        let vope_choices: [bool; 128] = core::array::from_fn(|i| vope[i].0);
        let vope_ev: [Gf2_128; 128] = core::array::from_fn(|i| vope[i].1);
        let vope_keys: [Gf2_128; 128] = core::array::from_fn(|i| vope[i].2);
        let chi: [u8; 32] = rng.random();

        // Prover skips the assertion (simulating a malicious party).
        Commit::new(&mut gate_masks).finish().unwrap();
        let prover = Prover::committed(&gate_macs).accumulate(ChaCha12Rng::from_seed(chi));
        let ProverOutput { u, v, assertions, .. } = prover.finish().unwrap();

        let (a_0, a_1) = vope_receiver(&vope_choices, &vope_ev);
        let proof = Proof {
            assertions,
            u: u + a_0,
            v: v + a_1,
            coefficients: Vec::new(),
        };

        // Verifier honestly performs the assertion.
        let verifier = Verifier::new(delta, &gate_keys, &gate_masks).unwrap();
        let mut verifier = verifier.accumulate(ChaCha12Rng::from_seed(chi));
        verifier.assert_eq(key_a, key_b).unwrap();
        let VerifierOutput { w, assertions: v_assertions, .. } = verifier.finish().unwrap();
        let b = vope_sender(&vope_keys);

        assert_ne!(v_assertions, proof.assertions);
        // The check equation itself still holds — rejection comes from
        // the assertion hash mismatch.
        assert_eq!(w + b, proof.u + delta * proof.v);
    }

    /// A trace mixing the triple check and the polynomial check: a committed
    /// multiplication, a degree-3 `acc_mux`-shaped constraint, a materialized
    /// degree-2 mux whose output feeds another committed multiplication.
    ///
    /// Consumes 3 tape entries and 4 challenge weights.
    fn poly_trace<C>(ctx: &mut C, w: [C::Wire; 6]) -> Result<C::Wire, C::Error>
    where
        C: PolyContext<Field = Gf2>,
    {
        let m = ctx.mul(w[0], w[1]);

        let [y, a, ww, s, u0, u1] = w.map(|x| ctx.lift(x));
        let r = u0 * (ww + a);
        let t = u1 * (s + a + r);
        ctx.assert_zero(y + a + r + t)?;

        let mux = a + u0 * (a + s);
        let out = ctx.materialize(mux);

        Ok(ctx.mul(out, m))
    }

    /// Satisfying witness for [`poly_trace`]: bits `[y, a, w, s, u0, u1]`
    /// with `y` solved so the degree-3 constraint holds.
    fn poly_witness(rng: &mut StdRng) -> [bool; 6] {
        let mut b: [bool; 6] = core::array::from_fn(|_| rng.random());
        let r = b[4] & (b[2] ^ b[1]);
        b[0] = b[1] ^ r ^ (b[5] & (b[3] ^ b[1] ^ r));
        b
    }

    /// Mocked degree-`d_max` VOPE correlation: random mask coefficients on
    /// the prover side, their `Δ`-weighted sum on the verifier side.
    fn mock_poly_vope(
        rng: &mut StdRng,
        powers: &DeltaPowers,
        d_max: usize,
    ) -> (Vec<Gf2_128>, Gf2_128) {
        let coeffs: Vec<Gf2_128> = (0..d_max).map(|_| Gf2_128::new(rng.random())).collect();
        let mut sum = Gf2_128::new(0);
        let mut pw = Gf2_128::new(1);
        for &c in &coeffs {
            sum = sum + c * pw;
            pw = pw * powers.delta();
        }
        (coeffs, sum)
    }

    #[test]
    fn poly_round_trip() {
        let mut rng = StdRng::seed_from_u64(20);
        let delta = random_delta(&mut rng);
        let powers = DeltaPowers::new(delta);
        let chi: [u8; 32] = rng.random();
        const D_MAX: usize = 3;

        let bits = poly_witness(&mut rng);
        let pairs: Vec<(Gf2_128, Gf2_128)> =
            bits.iter().map(|&b| input(&mut rng, b, delta)).collect();
        let macs_in: [Gf2_128; 6] = core::array::from_fn(|i| pairs[i].0);
        let keys_in: [Gf2_128; 6] = core::array::from_fn(|i| pairs[i].1);

        let gates: Vec<_> = (0..3).map(|_| corr(&mut rng, delta)).collect();
        let mut masks: Vec<bool> = gates.iter().map(|(c, _, _)| *c).collect();
        let gate_macs: Vec<Gf2_128> = gates.iter().map(|(_, m, _)| *m).collect();
        let gate_keys: Vec<Gf2_128> = gates.iter().map(|(_, _, k)| *k).collect();

        let vope: [(bool, Gf2_128, Gf2_128); 128] = core::array::from_fn(|_| corr(&mut rng, delta));
        let vope_choices: [bool; 128] = core::array::from_fn(|i| vope[i].0);
        let vope_ev: [Gf2_128; 128] = core::array::from_fn(|i| vope[i].1);
        let vope_keys: [Gf2_128; 128] = core::array::from_fn(|i| vope[i].2);
        let (poly_masks, poly_vope_sum) = mock_poly_vope(&mut rng, &powers, D_MAX);

        // Prover: commit pass, then accumulate pass.
        let mut commit = Commit::new(&mut masks);
        poly_trace(&mut commit, macs_in).unwrap();
        commit.finish().unwrap();

        let mut prover = Prover::committed(&gate_macs).accumulate(ChaCha12Rng::from_seed(chi));
        poly_trace(&mut prover, macs_in).unwrap();
        let ProverOutput { u, v, poly, assertions } = prover.finish().unwrap();

        let (a_0, a_1) = vope_receiver(&vope_choices, &vope_ev);
        let coefficients: Vec<Gf2_128> = poly
            .coefficients(D_MAX)
            .unwrap()
            .iter()
            .zip(&poly_masks)
            .map(|(&c, &m)| c + m)
            .collect();
        let proof = Proof {
            assertions,
            u: u + a_0,
            v: v + a_1,
            coefficients,
        };

        // Verifier: single accumulate pass over the same trace.
        let verifier = Verifier::new(delta, &gate_keys, &masks).unwrap();
        let mut verifier = verifier.accumulate(ChaCha12Rng::from_seed(chi));
        poly_trace(&mut verifier, keys_in).unwrap();
        let VerifierOutput { w, poly: v_poly, assertions: v_assertions } = verifier.finish().unwrap();
        let b = vope_sender(&vope_keys);

        assert_eq!(v_assertions, proof.assertions);
        assert_eq!(w + b, proof.u + delta * proof.v);
        v_poly
            .check(&powers, &proof.coefficients, poly_vope_sum)
            .unwrap();
    }

    #[test]
    fn poly_dishonest_adjust_rejected() {
        // An honest run, then the verifier consumes a flipped adjust bit for
        // the materialized wire: the triple or poly check must reject.
        let mut rng = StdRng::seed_from_u64(21);
        let delta = random_delta(&mut rng);
        let powers = DeltaPowers::new(delta);
        let chi: [u8; 32] = rng.random();
        const D_MAX: usize = 3;

        let bits = poly_witness(&mut rng);
        let pairs: Vec<(Gf2_128, Gf2_128)> =
            bits.iter().map(|&b| input(&mut rng, b, delta)).collect();
        let macs_in: [Gf2_128; 6] = core::array::from_fn(|i| pairs[i].0);
        let keys_in: [Gf2_128; 6] = core::array::from_fn(|i| pairs[i].1);

        let gates: Vec<_> = (0..3).map(|_| corr(&mut rng, delta)).collect();
        let mut masks: Vec<bool> = gates.iter().map(|(c, _, _)| *c).collect();
        let gate_macs: Vec<Gf2_128> = gates.iter().map(|(_, m, _)| *m).collect();
        let gate_keys: Vec<Gf2_128> = gates.iter().map(|(_, _, k)| *k).collect();
        let (poly_masks, poly_vope_sum) = mock_poly_vope(&mut rng, &powers, D_MAX);

        let mut commit = Commit::new(&mut masks);
        poly_trace(&mut commit, macs_in).unwrap();
        commit.finish().unwrap();

        let mut prover = Prover::committed(&gate_macs).accumulate(ChaCha12Rng::from_seed(chi));
        poly_trace(&mut prover, macs_in).unwrap();
        let ProverOutput { poly, .. } = prover.finish().unwrap();
        let coefficients: Vec<Gf2_128> = poly
            .coefficients(D_MAX)
            .unwrap()
            .iter()
            .zip(&poly_masks)
            .map(|(&c, &m)| c + m)
            .collect();

        // Flip the adjust bit of the materialized wire (tape entry 1).
        masks[1] = !masks[1];

        let verifier = Verifier::new(delta, &gate_keys, &masks).unwrap();
        let mut verifier = verifier.accumulate(ChaCha12Rng::from_seed(chi));
        poly_trace(&mut verifier, keys_in).unwrap();
        let VerifierOutput { poly: v_poly, .. } = verifier.finish().unwrap();

        assert!(
            v_poly
                .check(&powers, &coefficients, poly_vope_sum)
                .is_err(),
            "flipped materialize commitment must break the poly check"
        );
    }

    #[test]
    fn poly_subrange_folding_matches_full() {
        // Two disjoint batches of poly constraints folded with seeked
        // challenge streams and merged must match the full fold. Each
        // constraint consumes one 16-byte challenge (4 ChaCha words).
        let mut rng = StdRng::seed_from_u64(22);
        let delta = random_delta(&mut rng);
        let powers = DeltaPowers::new(delta);
        let chi: [u8; 32] = rng.random();
        const N: usize = 10;
        const MID: usize = 4;
        const D_MAX: usize = 3;

        let wires: Vec<[(Gf2_128, Gf2_128); 6]> = (0..N)
            .map(|_| {
                let bits = poly_witness(&mut rng);
                core::array::from_fn(|i| input(&mut rng, bits[i], delta))
            })
            .collect();

        let fold_prover = |range: core::ops::Range<usize>, offset: usize| {
            let mut rng = ChaCha12Rng::from_seed(chi);
            rng.set_word_pos((offset * 4) as u128);
            let mut p = Prover::committed(&[]).accumulate(rng);
            for w in &wires[range] {
                let [y, a, ww, s, u0, u1] =
                    core::array::from_fn(|i| p.lift(w[i].0));
                let r = u0 * (ww + a);
                let t = u1 * (s + a + r);
                p.assert_zero(y + a + r + t).unwrap();
            }
            let ProverOutput { poly, .. } = p.finish().unwrap();
            poly
        };

        let full = fold_prover(0..N, 0);
        let mut lo = fold_prover(0..MID, 0);
        let hi = fold_prover(MID..N, MID);
        lo.merge(&hi);
        assert_eq!(
            full.coefficients(D_MAX).unwrap(),
            lo.coefficients(D_MAX).unwrap()
        );

        // Verifier partials must satisfy the check against the full prover
        // coefficients.
        let fold_verifier = |range: core::ops::Range<usize>, offset: usize| {
            let mut rng = ChaCha12Rng::from_seed(chi);
            rng.set_word_pos((offset * 4) as u128);
            let v = Verifier::new(delta, &[], &[]).unwrap();
            let mut v = v.accumulate(rng);
            for w in &wires[range] {
                let [y, a, ww, s, u0, u1] =
                    core::array::from_fn(|i| v.lift(w[i].1));
                let r = u0 * (ww + a);
                let t = u1 * (s + a + r);
                v.assert_zero(y + a + r + t).unwrap();
            }
            let VerifierOutput { poly, .. } = v.finish().unwrap();
            poly
        };

        let mut v_lo = fold_verifier(0..MID, 0);
        let v_hi = fold_verifier(MID..N, MID);
        v_lo.merge(&v_hi);
        v_lo.check(
            &powers,
            &full.coefficients(D_MAX).unwrap(),
            Gf2_128::new(0),
        )
        .unwrap();
    }
}
