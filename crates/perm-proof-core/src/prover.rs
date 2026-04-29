//! Permutation protocol prover.

use blake3::Hasher;
use mpz_fields::Field;
use poly_proof_core::SubfieldOf;
use serde::Serialize;

use crate::{MacTuple, Proof, ValueTuple, backend::ProverBackend, draw_field, inner_product};

/// Permutation protocol prover.
pub struct Prover<W, E, B, S = prover_state::Initialized>
where
    W: SubfieldOf<E>,
    E: Field,
    B: ProverBackend<W, E>,
    S: prover_state::State,
{
    backend: B,
    state: S,
    _phantom: std::marker::PhantomData<(W, E)>,
}

impl<W, E, B> Prover<W, E, B, prover_state::Initialized>
where
    W: SubfieldOf<E>,
    E: Field,
    B: ProverBackend<W, E>,
{
    /// Build a new prover around `backend`.
    pub fn new(backend: B) -> Self {
        Self {
            backend,
            state: prover_state::Initialized,
            _phantom: std::marker::PhantomData,
        }
    }

    /// Announce that a permutation proof of size `n` will run through
    /// this prover.
    ///
    /// Multiple calls accumulate.
    pub fn alloc(&mut self, n: usize) -> Result<(), B::Error> {
        self.backend.alloc(n)
    }

    /// Compute the preparation message for phase 1 of the protocol.
    ///
    /// # Arguments
    ///
    /// * `transcript` - Shared session transcript.
    /// * `x` - Pair `(values, macs)` for the first input vector.
    /// * `y` - Pair `(values, macs)` for the second input vector.
    ///
    /// # Security
    ///
    /// It is crucial that `transcript` has absorbed the input vectors
    /// `x` and `y` before this method is invoked. The protocol's
    /// soundness depends on this binding.
    pub fn prepare<const L: usize>(
        mut self,
        mut transcript: Hasher,
        x: (&[ValueTuple<W, L>], &[MacTuple<E, L>]),
        y: (&[ValueTuple<W, L>], &[MacTuple<E, L>]),
    ) -> Result<(B::Preparation, Prover<W, E, B, prover_state::Prepared<E>>), ProveError<B::Error>>
    {
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
        if n == 0 || L == 0 {
            return Err(ProveError::EmptyInputs);
        }

        // Draw the random challenge `r`.
        let r = draw_field::<E>(&mut transcript, b"permutation-proof::challenge_r");

        // Draw the tuple-collapse challenge `s ∈ E^L`.
        let s: [E; L] = std::array::from_fn(|_| {
            draw_field::<E>(&mut transcript, b"permutation-proof::challenge_s")
        });

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

        // Commit the authenticated product of each vectors's factors.
        let (_, px_m) = self
            .backend
            .product(&mut transcript, &fx_values, &fx_macs)
            .map_err(ProveError::Backend)?;
        let (_, py_m) = self
            .backend
            .product(&mut transcript, &fy_values, &fy_macs)
            .map_err(ProveError::Backend)?;

        // Drain the preparation message now so the caller can ship it
        // to the verifier immediately.
        let preparation = self
            .backend
            .drain_preparation()
            .map_err(ProveError::Backend)?;

        Ok((
            preparation,
            Prover {
                backend: self.backend,
                state: prover_state::Prepared {
                    transcript,
                    px_m,
                    py_m,
                },
                _phantom: std::marker::PhantomData,
            },
        ))
    }
}

impl<W, E, B> Prover<W, E, B, prover_state::Prepared<E>>
where
    W: SubfieldOf<E>,
    E: Field,
    B: ProverBackend<W, E>,
{
    /// Return the proof message for phase 2 of the protocol.
    pub fn prove(self) -> Result<Proof<E, B::BackendProof>, ProveError<B::Error>>
    where
        E: Serialize,
        B::BackendProof: Serialize,
    {
        let Prover { backend, state, .. } = self;
        let prover_state::Prepared {
            mut transcript,
            px_m,
            py_m,
        } = state;

        // Materialize the zero-check: the difference MAC is what the
        // verifier checks against its own diff_k. Under an honest
        // permutation, the underlying value diff is zero.
        let zero_proof = px_m - py_m;

        // Absorb the proof into the transcript so any subsequent proof
        // sharing this transcript stays bound to this one.
        let backend_proof = backend.prove().map_err(ProveError::Backend)?;
        let proof = Proof {
            zero_proof,
            backend_proof,
        };
        transcript.update(b"permutation-proof::proof");
        transcript.update(&bcs::to_bytes(&proof).expect("serialize"));

        Ok(proof)
    }
}

/// Type-state markers for [`Prover`]'s phase.
pub mod prover_state {
    use mpz_fields::Field;

    mod sealed {
        pub trait Sealed {}
    }

    /// Marker trait implemented by every legal [`Prover`](super::Prover)
    /// phase. Sealed: external crates cannot add new phases.
    pub trait State: sealed::Sealed {}

    /// Phase right after [`Prover::new`](super::Prover::new): `alloc`
    /// and `prepare` are callable; `prove` is not.
    pub struct Initialized;

    /// Phase right after a successful
    /// [`prepare`](super::Prover::<_, _, _, Initialized>::prepare):
    /// `prove` is callable.
    pub struct Prepared<E: Field> {
        pub(super) transcript: blake3::Hasher,
        pub(super) px_m: E,
        pub(super) py_m: E,
    }

    impl sealed::Sealed for Initialized {}
    impl State for Initialized {}
    impl<E: Field> sealed::Sealed for Prepared<E> {}
    impl<E: Field> State for Prepared<E> {}
}

/// Collapse one `L`-tuple of authenticated wires into a single
/// `(value, MAC)` pair via the inner product with `s`:
///
/// ```text
/// z_val = Σ_j s[j] · values[j].embed()
/// z_mac = Σ_j s[j] · macs[j]
/// ```
pub(crate) fn collapse_tuple<W, E, const L: usize>(
    s: &[E; L],
    values: &[W; L],
    macs: &[E; L],
) -> (E, E)
where
    W: SubfieldOf<E>,
    E: Field,
{
    let embedded: [E; L] = std::array::from_fn(|j| values[j].embed());
    (inner_product(s, &embedded), inner_product(s, macs))
}

/// Error produced by protocol prover.
#[derive(Debug, thiserror::Error)]
pub enum ProveError<E: std::error::Error + Send + Sync + 'static> {
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

    /// Input vectors had length zero.
    #[error("empty inputs: permutation proof requires at least one wire per side")]
    EmptyInputs,

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

    /// Mismatched `x_values.len()` vs `x_macs.len()` must surface as
    /// `LengthMismatch`.
    #[test]
    fn prepare_rejects_x_values_x_macs_length_mismatch() {
        let prover = build_mock_prover();
        let transcript = Hasher::new();
        let x_values: Vec<[Gf2_128; 1]> = vec![[Gf2_128::one()]; 3];
        let x_macs: Vec<[Gf2_128; 1]> = vec![[Gf2_128::one()]; 2]; // short by 1
        let y_values: Vec<[Gf2_128; 1]> = vec![[Gf2_128::one()]; 3];
        let y_macs: Vec<[Gf2_128; 1]> = vec![[Gf2_128::one()]; 3];

        let err = prover
            .prepare::<1>(transcript, (&x_values, &x_macs), (&y_values, &y_macs))
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
        let prover = build_mock_prover();
        let transcript = Hasher::new();
        let x_values: Vec<[Gf2_128; 1]> = vec![[Gf2_128::one()]; 4];
        let x_macs: Vec<[Gf2_128; 1]> = vec![[Gf2_128::one()]; 4];
        let y_values: Vec<[Gf2_128; 1]> = vec![[Gf2_128::one()]; 4];
        let y_macs: Vec<[Gf2_128; 1]> = vec![[Gf2_128::one()]; 3]; // short by 1

        let err = prover
            .prepare::<1>(transcript, (&x_values, &x_macs), (&y_values, &y_macs))
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
        let prover = build_mock_prover();
        let transcript = Hasher::new();
        let x_values: Vec<[Gf2_128; 1]> = vec![[Gf2_128::one()]; 3];
        let x_macs: Vec<[Gf2_128; 1]> = vec![[Gf2_128::one()]; 3];
        let y_values: Vec<[Gf2_128; 1]> = vec![[Gf2_128::one()]; 5];
        let y_macs: Vec<[Gf2_128; 1]> = vec![[Gf2_128::one()]; 5];

        let err = prover
            .prepare::<1>(transcript, (&x_values, &x_macs), (&y_values, &y_macs))
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
        let prover = build_mock_prover();
        let transcript = Hasher::new();
        let empty: Vec<[Gf2_128; 1]> = Vec::new();

        let err = prover
            .prepare::<1>(transcript, (&empty, &empty), (&empty, &empty))
            .err()
            .expect("empty inputs must surface an error");
        assert!(
            matches!(err, ProveError::EmptyInputs),
            "expected EmptyInputs, got {err:?}"
        );
    }

    /// Zero-width tuples (`L = 0`) rejected.
    #[test]
    fn prepare_rejects_zero_width_tuples() {
        let prover = build_mock_prover();
        let transcript = Hasher::new();
        // n = 1, L = 0: one position, zero-width tuple.
        let x_values: Vec<[Gf2_128; 0]> = vec![[]];
        let x_macs: Vec<[Gf2_128; 0]> = vec![[]];
        let y_values: Vec<[Gf2_128; 0]> = vec![[]];
        let y_macs: Vec<[Gf2_128; 0]> = vec![[]];

        let err = prover
            .prepare::<0>(transcript, (&x_values, &x_macs), (&y_values, &y_macs))
            .err()
            .expect("zero-width tuples must surface an error");
        assert!(
            matches!(err, ProveError::EmptyInputs),
            "expected EmptyInputs, got {err:?}"
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
        // lifecycle. `pub(super)` fields on `Prepared` make this
        // accessible from inside `prover.rs`'s test submodule.
        let prover = Prover {
            backend: MockProverBackend::<Gf2_128, Gf2_128>::new(delta),
            state: prover_state::Prepared {
                transcript: Hasher::new(),
                px_m,
                py_m,
            },
            _phantom: std::marker::PhantomData,
        };

        let proof = prover.prove().expect("mock prove must succeed");
        assert_eq!(proof.zero_proof, px_m - py_m);
        assert_eq!(proof.backend_proof, ());
    }
}
