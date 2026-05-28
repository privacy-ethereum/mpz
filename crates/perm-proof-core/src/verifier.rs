//! Permutation protocol verifier.

use blake3::Hasher;
use mpz_fields::{ExtensionField, Field};
use serde::Serialize;

use crate::{Proof, backend::VerifierBackend, draw_field};

/// Permutation protocol verifier.
pub struct Verifier<W, E, B>
where
    W: Field,
    E: ExtensionField<W>,
    B: VerifierBackend<W, E>,
{
    backend: B,
    state: VerifierState<E>,
    _phantom: std::marker::PhantomData<(W, E)>,
}

impl<W, E, B> Verifier<W, E, B>
where
    W: Field,
    E: ExtensionField<W>,
    B: VerifierBackend<W, E>,
{
    /// Build a new verifier around `backend`.
    pub fn new(backend: B) -> Self {
        Self {
            backend,
            state: VerifierState::Initialized,
            _phantom: std::marker::PhantomData,
        }
    }

    /// Announce that a permutation proof of size `n` will run through
    /// this verifier.
    ///
    /// Multiple calls accumulate.
    pub fn alloc(&mut self, n: usize) -> Result<(), VerifyError<B::Error>> {
        match &self.state {
            VerifierState::Initialized => self.backend.alloc(n).map_err(VerifyError::Backend),
            _ => Err(VerifyError::WrongPhase),
        }
    }

    /// Compute the preparation phase of the protocol.
    ///
    /// # Arguments
    ///
    /// * `transcript` -  Fiat-Shamir transcript..
    /// * `x_keys` - Verifier-side keys for the first input vector.
    /// * `y_keys` - Verifier-side keys for the second input vector.
    /// * `preparation` - The prover-emitted preparation DTO.
    ///
    /// # Security
    ///
    /// It is crucial that `transcript` has absorbed `x_keys` and
    /// `y_keys` before this method is invoked. The protocol's soundness
    /// depends on this binding.
    pub fn prepare(
        &mut self,
        transcript: &mut Hasher,
        x_keys: &[Vec<E>],
        y_keys: &[Vec<E>],
        preparation: B::Preparation,
    ) -> Result<(), VerifyError<B::Error>> {
        match &self.state {
            VerifierState::Initialized => {}
            _ => return Err(VerifyError::WrongPhase),
        }

        let xn = x_keys.len();
        let yn = y_keys.len();
        if xn != yn {
            return Err(VerifyError::LengthMismatch { xn, yn });
        }
        if xn == 0 {
            return Err(VerifyError::EmptyInputs);
        }

        // Tuple width: read from the first input tuple.
        let tuple_width = x_keys[0].len();
        if tuple_width == 0 {
            return Err(VerifyError::EmptyInputs);
        }

        // Uniformity: every tuple (across both x and y) must have the
        // same width.
        let all_uniform = x_keys.iter().all(|k| k.len() == tuple_width)
            && y_keys.iter().all(|k| k.len() == tuple_width);
        if !all_uniform {
            return Err(VerifyError::TupleWidthMismatch);
        }

        // Draw the random challenge `r`.
        let r = draw_field::<E>(transcript, b"permutation-proof::challenge_r");

        // Draw the tuple-collapse challenge `s ∈ E^tuple_width`.
        let s: Vec<E> = (0..tuple_width)
            .map(|_| draw_field::<E>(transcript, b"permutation-proof::challenge_s"))
            .collect();

        // Compute per-position collapsed factors.
        //
        //   z_key  = Σ_j s[j] · keys[i][j]              (in E)
        //   factor_key = −Δ·r − z_key    // r's key is −Δ·r; the `−` carries through.
        let delta = self.backend.delta();
        let minus_delta_r = -(delta * r);
        let fx_keys: Vec<E> = x_keys
            .iter()
            .map(|k| minus_delta_r - E::inner_product(&s, k))
            .collect();
        let fy_keys: Vec<E> = y_keys
            .iter()
            .map(|k| minus_delta_r - E::inner_product(&s, k))
            .collect();

        // Install the preparation DTOs.
        self.backend.load_preparation(preparation);

        let px_k = self
            .backend
            .product(&fx_keys)
            .map_err(VerifyError::Backend)?;
        let py_k = self
            .backend
            .product(&fy_keys)
            .map_err(VerifyError::Backend)?;

        self.state = VerifierState::Prepared { px_k, py_k };

        Ok(())
    }

    /// Verify the proof.
    ///
    /// # Arguments
    ///
    /// * `proof` - The prover-emitted proof.
    /// * `transcript` - Fiat-Shamir transcript. Must be the same instance as in
    ///   [`prepare`](Self::prepare).
    pub fn verify(
        self,
        proof: Proof<E, B::BackendProof>,
        transcript: &mut Hasher,
    ) -> Result<(), VerifyError<B::Error>>
    where
        E: Serialize,
        B::BackendProof: Serialize,
    {
        let Verifier { backend, state, .. } = self;
        let (px_k, py_k) = match state {
            VerifierState::Prepared { px_k, py_k } => (px_k, py_k),
            _ => return Err(VerifyError::WrongPhase),
        };

        let proof_bytes = bcs::to_bytes(&proof).expect("serialize");

        let Proof {
            zero_proof,
            backend_proof,
        } = proof;

        // Zero-check: diff_k is the key for the difference wire. Under
        // `mac = key + Δ · value`, value-zero forces mac == key, so
        // the prover's opened mac (zero_proof) must equal this
        // locally-computed key.
        let diff_k = px_k - py_k;
        if zero_proof != diff_k {
            return Err(VerifyError::ZeroCheckFailed);
        }

        backend
            .verify(backend_proof, transcript)
            .map_err(VerifyError::Backend)?;

        // Absorb the proof into the transcript so any subsequent proof
        // sharing this transcript stays bound to this one.
        transcript.update(&proof_bytes);

        Ok(())
    }
}

/// Internal state machine for [`Verifier`].
enum VerifierState<E> {
    Initialized,
    Prepared { px_k: E, py_k: E },
}

/// Error produced by protocol verifier.
#[derive(Debug, thiserror::Error)]
pub enum VerifyError<E: std::error::Error + Send + Sync + 'static> {
    /// A method was called while the verifier was in the wrong phase.
    #[error("verifier called in the wrong phase")]
    WrongPhase,

    /// The two key slices did not have the same length.
    #[error("length mismatch: x_keys={xn}, y_keys={yn}")]
    LengthMismatch {
        /// Length of `x_keys`.
        xn: usize,
        /// Length of `y_keys`.
        yn: usize,
    },

    /// Input key slices had length zero, or the tuple width was zero.
    #[error("empty inputs: permutation proof requires at least one wire per side")]
    EmptyInputs,

    /// Not all input tuples had the same width.
    #[error("tuple width mismatch across input vectors")]
    TupleWidthMismatch,

    /// The prover's opened MAC disagreed with the verifier's
    /// locally-computed key.
    #[error("zero-check rejected: zero_proof does not match verifier's diff key")]
    ZeroCheckFailed,

    /// The backend reported an error.
    #[error("backend error: {0}")]
    Backend(#[source] E),
}

#[cfg(test)]
mod tests {
    use super::*;

    use mpz_fields::gf2_128::Gf2_128;
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha8Rng;

    use crate::backend::mock::{MockVerifierBackend, Preparation};

    /// Build a mock-backed verifier.
    fn build_mock_verifier() -> Verifier<Gf2_128, Gf2_128, MockVerifierBackend<Gf2_128, Gf2_128>> {
        let delta = Gf2_128::one();
        Verifier::new(MockVerifierBackend::<Gf2_128, Gf2_128>::new(delta))
    }

    /// Construct a uniform-width key Vec for tests.
    fn key_ones(n: usize, width: usize) -> Vec<Vec<Gf2_128>> {
        (0..n).map(|_| vec![Gf2_128::one(); width]).collect()
    }

    /// Mismatched `x_keys.len()` vs `y_keys.len()` must surface as
    /// `LengthMismatch`.
    #[test]
    fn prepare_rejects_length_mismatch() {
        let mut verifier = build_mock_verifier();
        let mut transcript = Hasher::new();
        let x_keys = key_ones(3, 1);
        let y_keys = key_ones(5, 1);
        let preparation = Preparation { prod_keys: vec![] };

        let err = verifier
            .prepare(&mut transcript, &x_keys, &y_keys, preparation)
            .err()
            .expect("length mismatch must surface an error");
        match err {
            VerifyError::LengthMismatch { xn, yn } => {
                assert_eq!((xn, yn), (3, 5));
            }
            other => panic!("expected LengthMismatch, got {other:?}"),
        }
    }

    /// A permutation proof over zero positions is vacuous.
    #[test]
    fn prepare_rejects_empty_vectors() {
        let mut verifier = build_mock_verifier();
        let mut transcript = Hasher::new();
        let empty: Vec<Vec<Gf2_128>> = Vec::new();
        let preparation = Preparation { prod_keys: vec![] };

        let err = verifier
            .prepare(&mut transcript, &empty, &empty, preparation)
            .err()
            .expect("empty inputs must surface an error");
        assert!(
            matches!(err, VerifyError::EmptyInputs),
            "expected EmptyInputs, got {err:?}"
        );
    }

    /// Zero-width tuples are rejected.
    #[test]
    fn prepare_rejects_zero_width_tuples() {
        let mut verifier = build_mock_verifier();
        let mut transcript = Hasher::new();
        let x_keys = key_ones(1, 0);
        let y_keys = key_ones(1, 0);
        let preparation = Preparation { prod_keys: vec![] };

        let err = verifier
            .prepare(&mut transcript, &x_keys, &y_keys, preparation)
            .err()
            .expect("zero-width tuples must surface an error");
        assert!(
            matches!(err, VerifyError::EmptyInputs),
            "expected EmptyInputs, got {err:?}"
        );
    }

    /// Non-uniform tuple widths rejected.
    #[test]
    fn prepare_rejects_tuple_width_mismatch() {
        let mut verifier = build_mock_verifier();
        let mut transcript = Hasher::new();
        let x_keys: Vec<Vec<Gf2_128>> = vec![vec![Gf2_128::one(); 2], vec![Gf2_128::one(); 3]];
        let y_keys = x_keys.clone();
        let preparation = Preparation { prod_keys: vec![] };

        let err = verifier
            .prepare(&mut transcript, &x_keys, &y_keys, preparation)
            .err()
            .expect("non-uniform tuple width must surface an error");
        assert!(
            matches!(err, VerifyError::TupleWidthMismatch),
            "expected TupleWidthMismatch, got {err:?}"
        );
    }

    /// `verify` accepts iff `zero_proof == px_k − py_k`.
    #[test]
    fn verify_accepts_matching_zero_proof() {
        let mut rng = ChaCha8Rng::seed_from_u64(0xDEAD);
        let delta: Gf2_128 = rng.random();
        let px_k: Gf2_128 = rng.random();
        let py_k: Gf2_128 = rng.random();

        let verifier = Verifier {
            backend: MockVerifierBackend::<Gf2_128, Gf2_128>::new(delta),
            state: VerifierState::Prepared { px_k, py_k },
            _phantom: std::marker::PhantomData,
        };

        let proof = Proof {
            zero_proof: px_k - py_k,
            backend_proof: (),
        };

        let mut transcript = Hasher::new();
        verifier
            .verify(proof, &mut transcript)
            .expect("matching zero_proof must be accepted");
    }

    /// `verify` rejects when `zero_proof != px_k − py_k`.
    #[test]
    fn verify_rejects_mismatched_zero_proof() {
        let mut rng = ChaCha8Rng::seed_from_u64(0xBEEF);
        let delta: Gf2_128 = rng.random();
        let px_k: Gf2_128 = rng.random();
        let py_k: Gf2_128 = rng.random();

        let verifier = Verifier {
            backend: MockVerifierBackend::<Gf2_128, Gf2_128>::new(delta),
            state: VerifierState::Prepared { px_k, py_k },
            _phantom: std::marker::PhantomData,
        };

        let tampered = Proof {
            zero_proof: (px_k - py_k) + Gf2_128::one(),
            backend_proof: (),
        };

        let mut transcript = Hasher::new();
        let err = verifier
            .verify(tampered, &mut transcript)
            .err()
            .expect("tampered zero_proof must be rejected");
        assert!(
            matches!(err, VerifyError::ZeroCheckFailed),
            "expected ZeroCheckFailed, got {err:?}"
        );
    }

    /// `verify` errors with `WrongPhase` if `prepare` hasn't been
    /// called.
    #[test]
    fn verify_rejects_initialized_phase() {
        let verifier = build_mock_verifier();
        let proof = Proof {
            zero_proof: Gf2_128::one(),
            backend_proof: (),
        };
        let mut transcript = Hasher::new();
        let err = verifier
            .verify(proof, &mut transcript)
            .err()
            .expect("verify without prepare must fail");
        assert!(matches!(err, VerifyError::WrongPhase));
    }
}
