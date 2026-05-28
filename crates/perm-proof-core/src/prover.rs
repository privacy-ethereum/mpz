//! Permutation protocol prover.

use blake3::Hasher;
use mpz_fields::{ExtensionField, Field};
use serde::Serialize;

use crate::{Proof, backend::ProverBackend, draw_field};

/// Permutation protocol prover.
pub struct Prover<W, E, B>
where
    W: Field,
    E: ExtensionField<W>,
    B: ProverBackend<W, E>,
{
    backend: B,
    state: ProverState<E>,
    _phantom: std::marker::PhantomData<(W, E)>,
}

impl<W, E, B> Prover<W, E, B>
where
    W: Field,
    E: ExtensionField<W>,
    B: ProverBackend<W, E>,
{
    /// Build a new prover around `backend`.
    pub fn new(backend: B) -> Self {
        Self {
            backend,
            state: ProverState::Initialized,
            _phantom: std::marker::PhantomData,
        }
    }

    /// Announce that a permutation proof of size `n` will run through
    /// this prover.
    ///
    /// Multiple calls accumulate.
    pub fn alloc(&mut self, n: usize) -> Result<(), ProveError<B::Error>> {
        match &self.state {
            ProverState::Initialized => self.backend.alloc(n).map_err(ProveError::Backend),
            _ => Err(ProveError::WrongPhase),
        }
    }

    /// Compute the preparation message for phase 1 of the protocol.
    ///
    /// # Arguments
    ///
    /// * `transcript` - Fiat-Shamir transcript.
    /// * `x` - Pair `(values, macs)` for the first input vector.
    /// * `y` - Pair `(values, macs)` for the second input vector.
    ///
    /// # Security
    ///
    /// It is crucial that `transcript` has absorbed the input vectors
    /// `x` and `y` before this method is invoked. The protocol's
    /// soundness depends on this binding.
    pub fn prepare(
        &mut self,
        transcript: &mut Hasher,
        x: (&[Vec<W>], &[Vec<E>]),
        y: (&[Vec<W>], &[Vec<E>]),
    ) -> Result<B::Preparation, ProveError<B::Error>> {
        match &self.state {
            ProverState::Initialized => {}
            _ => return Err(ProveError::WrongPhase),
        }

        let (x_values, x_macs) = x;
        let (y_values, y_macs) = y;

        let xv = x_values.len();
        let xm = x_macs.len();
        let yv = y_values.len();
        let ym = y_macs.len();
        if xv != xm || yv != ym || xv != yv {
            return Err(ProveError::LengthMismatch { xv, xm, yv, ym });
        }
        let n = xv;
        if n == 0 {
            return Err(ProveError::EmptyInputs);
        }

        // Tuple width: read from the first input tuple.
        let tuple_width = x_values[0].len();
        if tuple_width == 0 {
            return Err(ProveError::EmptyInputs);
        }

        // Uniformity: every tuple (across both x and y, values and
        // macs) must have the same width.
        let all_uniform = x_values.iter().all(|v| v.len() == tuple_width)
            && x_macs.iter().all(|m| m.len() == tuple_width)
            && y_values.iter().all(|v| v.len() == tuple_width)
            && y_macs.iter().all(|m| m.len() == tuple_width);
        if !all_uniform {
            return Err(ProveError::TupleWidthMismatch);
        }

        // Draw the random challenge `r`.
        let r = draw_field::<E>(transcript, b"permutation-proof::challenge_r");

        // Draw the tuple-collapse challenge `s ∈ E^tuple_width`.
        let s: Vec<E> = (0..tuple_width)
            .map(|_| draw_field::<E>(transcript, b"permutation-proof::challenge_s"))
            .collect();

        // Compute per-position collapsed factors.
        //
        //   z_val  = Σ_j s[j] · values[i][j].embed()    (in E)
        //   z_mac  = Σ_j s[j] · macs[i][j]              (in E)
        //   factor_value = r − z_val
        //   factor_mac   = −z_mac    // r contributes no MAC; the `−` carries through.
        let mut fx_values: Vec<E> = Vec::with_capacity(n);
        let mut fx_macs: Vec<E> = Vec::with_capacity(n);
        let mut fy_values: Vec<E> = Vec::with_capacity(n);
        let mut fy_macs: Vec<E> = Vec::with_capacity(n);

        for i in 0..n {
            let (zx_val, zx_mac) = collapse_tuple(&s, &x_values[i], &x_macs[i]);
            let (zy_val, zy_mac) = collapse_tuple(&s, &y_values[i], &y_macs[i]);
            fx_values.push(r - zx_val);
            fx_macs.push(-zx_mac);
            fy_values.push(r - zy_val);
            fy_macs.push(-zy_mac);
        }

        // Commit the authenticated product of each vector's factors.
        let (_, px_m) = self
            .backend
            .product(&fx_values, &fx_macs)
            .map_err(ProveError::Backend)?;
        let (_, py_m) = self
            .backend
            .product(&fy_values, &fy_macs)
            .map_err(ProveError::Backend)?;

        // Drain the preparation message now so the caller can ship it
        // to the verifier immediately.
        let preparation = self
            .backend
            .drain_preparation()
            .map_err(ProveError::Backend)?;

        self.state = ProverState::Prepared { px_m, py_m };

        Ok(preparation)
    }

    /// Return the proof message for phase 2 of the protocol.
    ///
    /// # Arguments
    ///
    /// * `transcript` - Fiat-Shamir transcript. Must be the same instance as in
    ///   [`prepare`](Self::prepare).
    pub fn prove(
        self,
        transcript: &mut Hasher,
    ) -> Result<Proof<E, B::BackendProof>, ProveError<B::Error>>
    where
        E: Serialize,
        B::BackendProof: Serialize,
    {
        let Prover { backend, state, .. } = self;
        let (px_m, py_m) = match state {
            ProverState::Prepared { px_m, py_m } => (px_m, py_m),
            _ => return Err(ProveError::WrongPhase),
        };

        // Materialize the zero-check: the difference MAC is what the
        // verifier checks against its own diff_k. Under an honest
        // permutation, the underlying value diff is zero.
        let zero_proof = px_m - py_m;

        let backend_proof = backend.prove(transcript).map_err(ProveError::Backend)?;
        let proof = Proof {
            zero_proof,
            backend_proof,
        };

        // Absorb the proof into the transcript so any subsequent proof
        // sharing this transcript stays bound to this one.
        transcript.update(&bcs::to_bytes(&proof).expect("serialize"));

        Ok(proof)
    }
}

/// Internal state machine for [`Prover`].
enum ProverState<E> {
    Initialized,
    Prepared { px_m: E, py_m: E },
}

/// Collapse one tuple of authenticated wires into a single
/// `(value, MAC)` pair via the inner product with `s`.
///
/// `s.len()`, `values.len()`, and `macs.len()` are expected to be
/// equal; the inner product extends only as far as the shortest slice.
pub(crate) fn collapse_tuple<W, E>(s: &[E], values: &[W], macs: &[E]) -> (E, E)
where
    W: Field,
    E: ExtensionField<W>,
{
    let embedded: Vec<E> = values.iter().map(|v| E::embed(*v)).collect();
    (E::inner_product(s, &embedded), E::inner_product(s, macs))
}

/// Error produced by protocol prover.
#[derive(Debug, thiserror::Error)]
pub enum ProveError<E: std::error::Error + Send + Sync + 'static> {
    /// A method was called while the prover was in the wrong phase.
    #[error("prover called in the wrong phase")]
    WrongPhase,

    /// The four input slices did not all have the same length.
    #[error("length mismatch: x_values={xv}, x_macs={xm}, y_values={yv}, y_macs={ym}")]
    LengthMismatch {
        /// Length of `x.0` (values).
        xv: usize,
        /// Length of `x.1` (macs).
        xm: usize,
        /// Length of `y.0` (values).
        yv: usize,
        /// Length of `y.1` (macs).
        ym: usize,
    },

    /// Input vectors had length zero, or the tuple width was zero.
    #[error("empty inputs: permutation proof requires at least one wire per side")]
    EmptyInputs,

    /// Not all input tuples had the same width.
    #[error("tuple width mismatch across input vectors")]
    TupleWidthMismatch,

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

    use crate::backend::mock::MockProverBackend;

    /// Build a mock-backed prover.
    fn build_mock_prover() -> Prover<Gf2_128, Gf2_128, MockProverBackend<Gf2_128, Gf2_128>> {
        let delta = Gf2_128::one();
        Prover::new(MockProverBackend::<Gf2_128, Gf2_128>::new(delta))
    }

    /// Construct a uniform-width tuple Vec for tests.
    fn ones(n: usize, width: usize) -> Vec<Vec<Gf2_128>> {
        (0..n).map(|_| vec![Gf2_128::one(); width]).collect()
    }

    /// Mismatched `x_values.len()` vs `x_macs.len()` must surface as
    /// `LengthMismatch`.
    #[test]
    fn prepare_rejects_x_values_x_macs_length_mismatch() {
        let mut prover = build_mock_prover();
        let mut transcript = Hasher::new();
        let x_values = ones(3, 1);
        let x_macs = ones(2, 1); // short by 1
        let y_values = ones(3, 1);
        let y_macs = ones(3, 1);

        let err = prover
            .prepare(&mut transcript, (&x_values, &x_macs), (&y_values, &y_macs))
            .err()
            .expect("x-side length mismatch must surface an error");
        match err {
            ProveError::LengthMismatch { xv, xm, yv, ym } => {
                assert_eq!((xv, xm, yv, ym), (3, 2, 3, 3));
            }
            other => panic!("expected LengthMismatch, got {other:?}"),
        }
    }

    /// Mismatched `y_values.len()` vs `y_macs.len()` trips the second
    /// disjunct of the length check.
    #[test]
    fn prepare_rejects_y_values_y_macs_length_mismatch() {
        let mut prover = build_mock_prover();
        let mut transcript = Hasher::new();
        let x_values = ones(4, 1);
        let x_macs = ones(4, 1);
        let y_values = ones(4, 1);
        let y_macs = ones(3, 1); // short by 1

        let err = prover
            .prepare(&mut transcript, (&x_values, &x_macs), (&y_values, &y_macs))
            .err()
            .expect("y-side length mismatch must surface an error");
        match err {
            ProveError::LengthMismatch { xv, xm, yv, ym } => {
                assert_eq!((xv, xm, yv, ym), (4, 4, 4, 3));
            }
            other => panic!("expected LengthMismatch, got {other:?}"),
        }
    }

    /// With each side internally consistent but `x.len() != y.len()`,
    /// the third disjunct of the length check trips.
    #[test]
    fn prepare_rejects_x_vs_y_length_mismatch() {
        let mut prover = build_mock_prover();
        let mut transcript = Hasher::new();
        let x_values = ones(3, 1);
        let x_macs = ones(3, 1);
        let y_values = ones(5, 1);
        let y_macs = ones(5, 1);

        let err = prover
            .prepare(&mut transcript, (&x_values, &x_macs), (&y_values, &y_macs))
            .err()
            .expect("x-vs-y length mismatch must surface an error");
        match err {
            ProveError::LengthMismatch { xv, xm, yv, ym } => {
                assert_eq!((xv, xm, yv, ym), (3, 3, 5, 5));
            }
            other => panic!("expected LengthMismatch, got {other:?}"),
        }
    }

    /// A permutation proof over zero positions is vacuous.
    #[test]
    fn prepare_rejects_empty_vectors() {
        let mut prover = build_mock_prover();
        let mut transcript = Hasher::new();
        let empty: Vec<Vec<Gf2_128>> = Vec::new();

        let err = prover
            .prepare(&mut transcript, (&empty, &empty), (&empty, &empty))
            .err()
            .expect("empty inputs must surface an error");
        assert!(
            matches!(err, ProveError::EmptyInputs),
            "expected EmptyInputs, got {err:?}"
        );
    }

    /// Zero-width tuples rejected.
    #[test]
    fn prepare_rejects_zero_width_tuples() {
        let mut prover = build_mock_prover();
        let mut transcript = Hasher::new();
        // n = 1, tuple_width = 0.
        let x_values = ones(1, 0);
        let x_macs = ones(1, 0);
        let y_values = ones(1, 0);
        let y_macs = ones(1, 0);

        let err = prover
            .prepare(&mut transcript, (&x_values, &x_macs), (&y_values, &y_macs))
            .err()
            .expect("zero-width tuples must surface an error");
        assert!(
            matches!(err, ProveError::EmptyInputs),
            "expected EmptyInputs, got {err:?}"
        );
    }

    /// Non-uniform tuple widths rejected.
    #[test]
    fn prepare_rejects_tuple_width_mismatch() {
        let mut prover = build_mock_prover();
        let mut transcript = Hasher::new();
        // n = 2: first tuple width 2, second tuple width 3.
        let x_values: Vec<Vec<Gf2_128>> = vec![vec![Gf2_128::one(); 2], vec![Gf2_128::one(); 3]];
        let x_macs: Vec<Vec<Gf2_128>> = vec![vec![Gf2_128::one(); 2], vec![Gf2_128::one(); 3]];
        let y_values = x_values.clone();
        let y_macs = x_macs.clone();

        let err = prover
            .prepare(&mut transcript, (&x_values, &x_macs), (&y_values, &y_macs))
            .err()
            .expect("non-uniform tuple width must surface an error");
        assert!(
            matches!(err, ProveError::TupleWidthMismatch),
            "expected TupleWidthMismatch, got {err:?}"
        );
    }

    /// `prove` materializes the zero-check opening as
    /// `zero_proof = px_m − py_m`.
    #[test]
    fn prove_materializes_zero_proof_as_px_minus_py() {
        let mut rng = ChaCha8Rng::seed_from_u64(0xF00F);
        let delta: Gf2_128 = rng.random();
        let px_m: Gf2_128 = rng.random();
        let py_m: Gf2_128 = rng.random();

        // Construct the Prepared state directly — bypasses `prepare`
        // so this test pins `prove` in isolation from the rest of the
        // lifecycle.
        let prover = Prover {
            backend: MockProverBackend::<Gf2_128, Gf2_128>::new(delta),
            state: ProverState::Prepared { px_m, py_m },
            _phantom: std::marker::PhantomData,
        };

        let mut transcript = Hasher::new();
        let proof = prover
            .prove(&mut transcript)
            .expect("mock prove must succeed");
        assert_eq!(proof.zero_proof, px_m - py_m);
        assert_eq!(proof.backend_proof, ());
    }

    /// `prove` errors with `WrongPhase` if `prepare` hasn't been
    /// called.
    #[test]
    fn prove_rejects_initialized_phase() {
        let prover = build_mock_prover();
        let mut transcript = Hasher::new();
        let err = prover
            .prove(&mut transcript)
            .err()
            .expect("prove without prepare must fail");
        assert!(matches!(err, ProveError::WrongPhase));
    }
}
