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
pub use mpz_vole_core::{
    DerandVOLEReceiver, DerandVOLEReceiverError, RVOLEReceiver, RVOLEReceiverOutput, RVOLESender,
    RVOLESenderOutput, RVOPEReceiver, RVOPEReceiverOutput, RVOPESender, RVOPESenderOutput,
    VOLEReceiver, VOLEReceiverOutput, VoleAdjustment,
};
pub use prover::{ProveError, Prover};
pub use verifier::{Verifier, VerifyError};

/// Bundle of proof data the prover ships to the verifier.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proof<E: Field, BackendProof> {
    /// MAC opening for the (single) zero-check the protocol runs over
    /// the difference of the two authenticated product wires.
    pub zero_proof: E,
    /// Backend-specific supplementary proof.
    pub backend_proof: BackendProof,
}

/// Draw a uniform extension-field element from the transcript under a
/// domain-separation label.
pub(crate) fn draw_field<E: Field>(transcript: &mut Hasher, label: &[u8]) -> E {
    transcript.update(label);
    let mut buf: Array<u8, E::ByteSize> = Array::default();
    transcript.finalize_xof().fill(buf.as_mut_slice());
    E::try_from(buf).expect("uniform bytes are a field element")
}

/// Draw a 32-byte PRG seed from the transcript under a
/// domain-separation label.
pub(crate) fn draw_seed(transcript: &mut Hasher, label: &[u8]) -> [u8; 32] {
    transcript.update(label);
    let mut buf = [0u8; 32];
    transcript.finalize_xof().fill(&mut buf);
    buf
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
}
