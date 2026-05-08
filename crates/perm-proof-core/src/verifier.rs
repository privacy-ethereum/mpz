//! Permutation protocol verifier.

use blake3::Hasher;
use mpz_fields::{ExtensionField, Field};
use serde::Serialize;

use crate::{Proof, backend::VerifierBackend, draw_field};

/// Permutation protocol verifier.
pub struct Verifier<W, E, B, S = verifier_state::Initialized>
where
    W: Field,
    E: ExtensionField<W>,
    B: VerifierBackend<W, E>,
    S: verifier_state::State,
{
    backend: B,
    state: S,
    _phantom: std::marker::PhantomData<(W, E)>,
}

impl<W, E, B> Verifier<W, E, B, verifier_state::Initialized>
where
    W: Field,
    E: ExtensionField<W>,
    B: VerifierBackend<W, E>,
{
    /// Build a new verifier around `backend`.
    pub fn new(backend: B) -> Self {
        Self {
            backend,
            state: verifier_state::Initialized,
            _phantom: std::marker::PhantomData,
        }
    }

    /// Announce that a permutation proof of size `n` will run through
    /// this verifier.
    ///
    /// Multiple calls accumulate.
    pub fn alloc(&mut self, n: usize) -> Result<(), B::Error> {
        self.backend.alloc(n)
    }

    /// Compute the preparation phase of the protocol.
    ///
    /// # Arguments
    ///
    /// * `transcript` - Shared session transcript.
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
        mut self,
        mut transcript: Hasher,
        x_keys: &[Vec<E>],
        y_keys: &[Vec<E>],
        preparation: B::Preparation,
    ) -> Result<Verifier<W, E, B, verifier_state::Prepared<E>>, VerifyError<B::Error>> {
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
        let r = draw_field::<E>(&mut transcript, b"permutation-proof::challenge_r");

        // Draw the tuple-collapse challenge `s ∈ E^tuple_width`.
        let s: Vec<E> = (0..tuple_width)
            .map(|_| draw_field::<E>(&mut transcript, b"permutation-proof::challenge_s"))
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
            .product(&mut transcript, &fx_keys)
            .map_err(VerifyError::Backend)?;
        let py_k = self
            .backend
            .product(&mut transcript, &fy_keys)
            .map_err(VerifyError::Backend)?;

        Ok(Verifier {
            backend: self.backend,
            state: verifier_state::Prepared {
                transcript,
                px_k,
                py_k,
            },
            _phantom: std::marker::PhantomData,
        })
    }
}

impl<W, E, B> Verifier<W, E, B, verifier_state::Prepared<E>>
where
    W: Field,
    E: ExtensionField<W>,
    B: VerifierBackend<W, E>,
{
    /// Verify the proof.
    ///
    /// # Arguments
    ///
    /// * `proof` - The prover-emitted proof.
    pub fn verify(self, proof: Proof<E, B::BackendProof>) -> Result<(), VerifyError<B::Error>>
    where
        E: Serialize,
        B::BackendProof: Serialize,
    {
        let Verifier { backend, state, .. } = self;
        let verifier_state::Prepared {
            mut transcript,
            px_k,
            py_k,
        } = state;

        transcript.update(b"permutation-proof::proof");
        transcript.update(&bcs::to_bytes(&proof).expect("serialize"));

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

        // Backend's supplementary check.
        backend.verify(backend_proof).map_err(VerifyError::Backend)
    }
}

/// Error produced by protocol verifier.
#[derive(Debug, thiserror::Error)]
pub enum VerifyError<E: std::error::Error + Send + Sync + 'static> {
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

/// Type-state markers for [`Verifier`]'s phase.
pub mod verifier_state {
    use mpz_fields::Field;

    mod sealed {
        pub trait Sealed {}
    }

    /// Marker trait implemented by every legal
    /// [`Verifier`](super::Verifier) phase. Sealed: external crates
    /// cannot add new phases.
    pub trait State: sealed::Sealed {}

    /// Phase right after [`Verifier::new`](super::Verifier::new):
    /// `alloc` and `prepare` are callable; `verify` is not.
    pub struct Initialized;

    /// Phase right after a successful
    /// [`prepare`](super::Verifier::<_, _, _, Initialized>::prepare):
    /// `verify` is callable.
    pub struct Prepared<E: Field> {
        pub(super) transcript: blake3::Hasher,
        pub(super) px_k: E,
        pub(super) py_k: E,
    }

    impl sealed::Sealed for Initialized {}
    impl State for Initialized {}
    impl<E: Field> sealed::Sealed for Prepared<E> {}
    impl<E: Field> State for Prepared<E> {}
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
        let verifier = build_mock_verifier();
        let transcript = Hasher::new();
        let x_keys = key_ones(3, 1);
        let y_keys = key_ones(5, 1);
        let preparation = Preparation { prod_keys: vec![] };

        let err = verifier
            .prepare(transcript, &x_keys, &y_keys, preparation)
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
        let verifier = build_mock_verifier();
        let transcript = Hasher::new();
        let empty: Vec<Vec<Gf2_128>> = Vec::new();
        let preparation = Preparation { prod_keys: vec![] };

        let err = verifier
            .prepare(transcript, &empty, &empty, preparation)
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
        let verifier = build_mock_verifier();
        let transcript = Hasher::new();
        let x_keys = key_ones(1, 0);
        let y_keys = key_ones(1, 0);
        let preparation = Preparation { prod_keys: vec![] };

        let err = verifier
            .prepare(transcript, &x_keys, &y_keys, preparation)
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
        let verifier = build_mock_verifier();
        let transcript = Hasher::new();
        let x_keys: Vec<Vec<Gf2_128>> = vec![
            vec![Gf2_128::one(); 2],
            vec![Gf2_128::one(); 3],
        ];
        let y_keys = x_keys.clone();
        let preparation = Preparation { prod_keys: vec![] };

        let err = verifier
            .prepare(transcript, &x_keys, &y_keys, preparation)
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
            state: verifier_state::Prepared {
                transcript: Hasher::new(),
                px_k,
                py_k,
            },
            _phantom: std::marker::PhantomData,
        };

        let proof = Proof {
            zero_proof: px_k - py_k,
            backend_proof: (),
        };

        verifier
            .verify(proof)
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
            state: verifier_state::Prepared {
                transcript: Hasher::new(),
                px_k,
                py_k,
            },
            _phantom: std::marker::PhantomData,
        };

        let tampered = Proof {
            zero_proof: (px_k - py_k) + Gf2_128::one(),
            backend_proof: (),
        };

        let err = verifier
            .verify(tampered)
            .err()
            .expect("tampered zero_proof must be rejected");
        assert!(
            matches!(err, VerifyError::ZeroCheckFailed),
            "expected ZeroCheckFailed, got {err:?}"
        );
    }
}
