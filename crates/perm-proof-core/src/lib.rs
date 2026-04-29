//! Permutation proof protocol.
//!
//! Given two vectors `x, y ∈ Eⁿ` of authenticated wires, this crate
//! proves `x ~ y` (i.e. that one is a permutation of the other) using
//! the standard polynomial identity test over a random challenge drawn
//! from the verifier.

#![deny(missing_docs)]

use blake3::Hasher;
use hybrid_array::Array;
use mpz_fields::Field;
use serde::{Deserialize, Serialize};

pub mod backend;
pub mod prover;
pub mod verifier;

/// Test-support utilities.
#[cfg(any(test, feature = "test-utils"))]
pub mod test_utils;

pub use backend::{
    ProverBackend, VerifierBackend,
    vole_zk::{VoleZkProverBackend, VoleZkProverError, VoleZkVerifierBackend, VoleZkVerifierError},
};
pub use prover::{ProveError, Prover};
pub use verifier::{Verifier, VerifyError};

/// One position's worth of cleartext values: an `L`-element tuple.
///
/// The permutation proof operates on vectors of `L`-tuples of field
/// elements. `L = 1` is a degenerate scalar case — callers with a
/// plain vector of single values wrap each in a one-element array
/// (`[value]`) and proceed.
pub type ValueTuple<W, const L: usize> = [W; L];

/// One position's worth of prover-side MACs — an `L`-element tuple
/// matching the shape of [`ValueTuple`].
pub type MacTuple<E, const L: usize> = [E; L];

/// One position's worth of verifier-side keys — an `L`-element tuple
/// matching the shape of [`ValueTuple`].
pub type KeyTuple<E, const L: usize> = [E; L];

/// Bundle of proof data the prover ships to the verifier.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proof<E: Field, BackendProof> {
    /// MAC opening for the (single) zero-check the protocol runs over
    /// the difference of the two authenticated product wires.
    pub zero_proof: E,
    /// Backend-specific supplementary proof.
    pub backend_proof: BackendProof,
}

pub use mpz_vole_core::{
    DerandVOLEReceiver, DerandVOLEReceiverError, RVOLEReceiver, RVOLEReceiverOutput, RVOLESender,
    RVOLESenderOutput, RVOPEReceiver, RVOPEReceiverOutput, RVOPESender, RVOPESenderOutput,
    VOLEReceiver, VOLEReceiverOutput, VoleAdjustment,
};

/// Draw a uniform extension-field element from the transcript under a
/// domain-separation label.
pub(crate) fn draw_field<E: Field>(transcript: &mut Hasher, label: &[u8]) -> E {
    transcript.update(label);
    let mut buf: Array<u8, E::ByteSize> = Array::default();
    transcript.finalize_xof().fill(buf.as_mut_slice());
    E::try_from(buf).expect("uniform bytes are a field element")
}

/// Inner product of two E-valued `L`-tuples:
/// `Σ_j coeffs[j] · terms[j]`.
pub(crate) fn inner_product<E: Field, const L: usize>(coeffs: &[E; L], terms: &[E; L]) -> E {
    (0..L).fold(E::zero(), |acc, j| acc + coeffs[j] * terms[j])
}

#[cfg(test)]
mod tests {
    use super::*;

    use mpz_fields::gf2_128::Gf2_128;

    /// Determinism: two hashers in identical state, drawn with the
    /// same label, must produce the same field element.
    #[test]
    fn draw_field_is_deterministic_on_identical_transcripts() {
        let mut a = Hasher::new();
        let mut b = Hasher::new();
        a.update(b"shared-prefix");
        b.update(b"shared-prefix");

        let x: Gf2_128 = draw_field(&mut a, b"label");
        let y: Gf2_128 = draw_field(&mut b, b"label");
        assert_eq!(
            x, y,
            "same transcript state + same label must yield same draw"
        );
    }

    /// Domain separation: two draws from identical starting state but
    /// under different labels must produce different field elements
    /// with overwhelming probability.
    #[test]
    fn draw_field_separates_domains_by_label() {
        let mut a = Hasher::new();
        let mut b = Hasher::new();
        a.update(b"shared-prefix");
        b.update(b"shared-prefix");

        let x: Gf2_128 = draw_field(&mut a, b"label-one");
        let y: Gf2_128 = draw_field(&mut b, b"label-two");
        assert_ne!(
            x, y,
            "different labels on same state must yield different draws"
        );
    }

    /// Sequential uniqueness: two consecutive draws with the *same*
    /// label on the same transcript must produce different field
    /// elements.
    #[test]
    fn draw_field_is_sequentially_unique_under_same_label() {
        let mut transcript = Hasher::new();
        transcript.update(b"shared-prefix");

        let x: Gf2_128 = draw_field(&mut transcript, b"label");
        let y: Gf2_128 = draw_field(&mut transcript, b"label");
        assert_ne!(
            x, y,
            "consecutive draws under same label must still diverge"
        );
    }

    /// `inner_product` must compute `Σ_j coeffs[j] · terms[j]` for
    /// hand-traceable cases.
    #[test]
    fn inner_product_matches_hand_traced_cases() {
        use rand::{Rng, SeedableRng};
        use rand_chacha::ChaCha8Rng;

        let mut rng = ChaCha8Rng::seed_from_u64(0x1234);
        let one = Gf2_128::one();
        let zero = Gf2_128::zero();

        // L = 1: `<[c], [t]> = c · t`.
        let t: Gf2_128 = rng.random();
        assert_eq!(inner_product::<Gf2_128, 1>(&[one], &[t]), t);
        assert_eq!(inner_product::<Gf2_128, 1>(&[zero], &[t]), zero);

        // L = 3 with coefficients [1, 0, 1]: zeros in `coeffs` project
        // out the corresponding terms, leaving `a + c`.
        let a: Gf2_128 = rng.random();
        let b: Gf2_128 = rng.random();
        let c: Gf2_128 = rng.random();
        assert_eq!(inner_product(&[one, zero, one], &[a, b, c]), a + c);

        // L = 3 general case: compare against the explicit sum.
        let s: [Gf2_128; 3] = std::array::from_fn(|_| rng.random());
        let ts: [Gf2_128; 3] = std::array::from_fn(|_| rng.random());
        let expected = s[0] * ts[0] + s[1] * ts[1] + s[2] * ts[2];
        assert_eq!(inner_product(&s, &ts), expected);
    }

    /// IT-MAC preservation under `inner_product` with public coefficients.
    #[test]
    fn inner_product_preserves_it_mac_invariant() {
        use rand::{Rng, SeedableRng};
        use rand_chacha::ChaCha8Rng;

        let mut rng = ChaCha8Rng::seed_from_u64(0xCAFE);
        let delta: Gf2_128 = rng.random();

        const L: usize = 3;
        let s: [Gf2_128; L] = std::array::from_fn(|_| rng.random());
        let values: [Gf2_128; L] = std::array::from_fn(|_| rng.random());
        let keys: [Gf2_128; L] = std::array::from_fn(|_| rng.random());
        let macs: [Gf2_128; L] = std::array::from_fn(|j| keys[j] + delta * values[j]);

        let value_z = inner_product(&s, &values);
        let key_z = inner_product(&s, &keys);
        let mac_z = inner_product(&s, &macs);

        assert_eq!(
            mac_z,
            key_z + delta * value_z,
            "inner_product must preserve mac = key + Δ·value under public s"
        );
    }
}
