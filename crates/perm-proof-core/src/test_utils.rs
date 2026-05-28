//! Test utilities for the permutation-proof protocol.

use mpz_common::future::Output;
use mpz_fields::{ExtensionField, Field};
use rand::Rng;

use mpz_vole_core::{
    RVOLEReceiver, RVOLESender, RVOPEReceiver, RVOPESender, VOLEReceiver,
    ideal::{
        rvole::{IdealRVOLEReceiver, IdealRVOLESender, ideal_rvole},
        rvope::{IdealRVOPEReceiver, IdealRVOPESender, ideal_rvope},
        vole::{FlushMsg, ideal_vole},
    },
};

use crate::{
    Prover, Verifier,
    backend::vole_zk::{VoleZkProverBackend, VoleZkVerifierBackend},
};

/// `vole_zk` perm-proof prover backed by ideal RVOLE / RVOPE
/// correlations over field `E`.
pub type IdealVoleZkPermProver<E> =
    Prover<E, E, VoleZkProverBackend<E, E, IdealRVOLEReceiver<E, E>, IdealRVOPEReceiver<E>>>;

/// `vole_zk` perm-proof verifier backed by ideal RVOLE / RVOPE
/// correlations over field `E`.
pub type IdealVoleZkPermVerifier<E> =
    Verifier<E, E, VoleZkVerifierBackend<E, E, IdealRVOLESender<E>, IdealRVOPESender<E>>>;

/// Build an ideal RVOLE `(sender, receiver)` pair, allocated and
/// flushed for exactly one perm-proof prover run over `n_perm` rows at
/// the given `fan_in`. The returned halves are ready to be passed to
/// [`VoleZkProverBackend::new`] / [`VoleZkVerifierBackend::new`].
pub fn ideal_perm_proof_rvole_pair<E>(
    rng: &mut impl Rng,
    delta: E,
    n_perm: usize,
    fan_in: usize,
) -> (IdealRVOLESender<E>, IdealRVOLEReceiver<E, E>)
where
    E: Field + ExtensionField<E>,
    rand::distr::StandardUniform: rand::distr::Distribution<E>,
{
    let seed = rand::Rng::random::<u64>(rng);
    let count = vole_zk_rvole_pregenerate_count(n_perm, fan_in);
    let (mut sender, mut receiver) = ideal_rvole::<E, E>(seed, delta);
    <_ as RVOLESender<E>>::alloc(&mut sender, count).expect("rvole sender alloc");
    <_ as RVOLEReceiver<E, E>>::alloc(&mut receiver, count).expect("rvole receiver alloc");
    if let Some(msg) = sender.flush() {
        receiver.flush(msg).expect("rvole flush");
    }
    (sender, receiver)
}

/// Build an ideal RVOPE `(sender, receiver)` pair, allocated and
/// flushed for exactly one perm-proof prover run at the given `fan_in`.
/// One polynomial; degree is derived from `fan_in` via
/// [`vole_zk_rvope_pregenerate_degree`].
pub fn ideal_perm_proof_rvope_pair<E>(
    rng: &mut impl Rng,
    delta: E,
    fan_in: usize,
) -> (IdealRVOPESender<E>, IdealRVOPEReceiver<E>)
where
    E: Field + ExtensionField<E>,
    rand::distr::StandardUniform: rand::distr::Distribution<E>,
{
    let seed = rand::Rng::random::<u64>(rng);
    let degree = vole_zk_rvope_pregenerate_degree::<E>(fan_in);
    let (mut sender, mut receiver) = ideal_rvope::<E>(seed, delta);
    <_ as RVOPESender<E>>::alloc(&mut sender, 1, degree).expect("rvope sender alloc");
    <_ as RVOPEReceiver<E>>::alloc(&mut receiver, 1, degree).expect("rvope receiver alloc");
    for msg in sender.flush() {
        receiver.flush(msg).expect("rvope flush");
    }
    (sender, receiver)
}

/// Build a `vole_zk` perm-proof `(Prover, Verifier)` pair backed by
/// ideal RVOLE / RVOPE correlations sized for `n_perm` rows with the
/// given `fan_in`.
pub fn build_ideal_perm_proof_pair<E>(
    rng: &mut impl Rng,
    delta: E,
    n_perm: usize,
    fan_in: usize,
) -> (IdealVoleZkPermProver<E>, IdealVoleZkPermVerifier<E>)
where
    E: Field
        + ExtensionField<E>
        + serde::Serialize
        + serde::de::DeserializeOwned
        + zerocopy::IntoBytes
        + zerocopy::FromBytes,
    rand::distr::StandardUniform: rand::distr::Distribution<E>,
{
    let (rvole_s, rvole_r) = ideal_perm_proof_rvole_pair::<E>(rng, delta, n_perm, fan_in);
    let (rvope_s, rvope_r) = ideal_perm_proof_rvope_pair::<E>(rng, delta, fan_in);

    let prover_backend = VoleZkProverBackend::<E, E, _, _>::new(fan_in, rvole_r, rvope_r)
        .expect("vole-zk prover backend");
    let verifier_backend =
        VoleZkVerifierBackend::<E, E, _, _>::new(fan_in, delta, rvole_s, rvope_s)
            .expect("vole-zk verifier backend");

    (Prover::new(prover_backend), Verifier::new(verifier_backend))
}

/// Tight bundle of what [`commit_values`] produces: per-vector
/// prover-side MAC tuples and verifier-side key tuples plus the
/// transcript carrying a binding to all of them. Each inner `Vec<E>`
/// is one tuple-position; outer `Vec` is one entry per input vector.
#[derive(Debug)]
pub struct Committed<E: Field, const N: usize> {
    /// Prover-side MAC tuples, one `Vec` per input vector, in
    /// submission order.
    pub macs: [Vec<Vec<E>>; N],
    /// Verifier-side key tuples, one `Vec` per input vector, in
    /// submission order.
    pub keys: [Vec<Vec<E>>; N],
    /// Transcript with the on-wire setup message absorbed under a
    /// fixed label.
    pub transcript: blake3::Hasher,
}

/// Commit `vectors` of runtime-width tuples as authenticated wires
/// via a single ideal chosen-VOLE session.
///
/// Each input `&[Vec<W>]` is a slice of tuples; every tuple within a
/// given input must have the same width. Across inputs, tuple widths
/// may differ — the per-input width is read from the first tuple.
pub fn commit_values<W, E, const N: usize>(
    vectors: [&[Vec<W>]; N],
    delta: E,
    rng: &mut impl Rng,
) -> Committed<E, N>
where
    W: Field,
    E: ExtensionField<W> + serde::Serialize,
{
    let seed: u64 = rng.random();

    // Per-input tuple widths and flat counts.
    let widths: [usize; N] = std::array::from_fn(|i| vectors[i].first().map_or(0, |t| t.len()));
    for (i, v) in vectors.iter().enumerate() {
        assert!(
            v.iter().all(|t| t.len() == widths[i]),
            "commit_values: input {i} has non-uniform tuple widths",
        );
    }
    let total_scalars: usize = vectors
        .iter()
        .enumerate()
        .map(|(i, v)| v.len() * widths[i])
        .sum();

    let (mut sender, mut receiver) = ideal_vole::<W, E>(seed, delta);
    <_ as RVOLESender<E>>::alloc(&mut sender, total_scalars).expect("sender alloc");
    <_ as VOLEReceiver<W, E>>::alloc(&mut receiver, total_scalars).expect("receiver alloc");

    let flat_inputs: [Vec<W>; N] =
        std::array::from_fn(|i| vectors[i].iter().flatten().copied().collect());
    let mut futs: [_; N] =
        std::array::from_fn(|i| Some(receiver.queue_recv_vole(&flat_inputs[i]).expect("queue")));

    // Single flush covers every queued wire.
    let flush = sender.flush().expect("flush must produce a message");
    let mut transcript = blake3::Hasher::new();
    absorb_vole_flush(&mut transcript, &flush);
    receiver.flush(flush).expect("receiver flush");

    // Re-bundle the returned flat MACs / keys into per-vector tuple
    // shapes matching the input.
    let macs: [Vec<Vec<E>>; N] = std::array::from_fn(|i| {
        let flat = futs[i]
            .take()
            .expect("future slot populated")
            .try_recv()
            .expect("future must not cancel")
            .expect("future must resolve after flush")
            .macs;
        chunk_into_vecs(flat, widths[i])
    });
    let keys: [Vec<Vec<E>>; N] = std::array::from_fn(|i| {
        let flat = sender
            .try_send_vole(vectors[i].len() * widths[i])
            .expect("sender keys")
            .keys;
        chunk_into_vecs(flat, widths[i])
    });

    Committed {
        macs,
        keys,
        transcript,
    }
}

/// Reshape a flat `Vec<E>` into a `Vec<Vec<E>>` where each inner vec
/// holds `width` consecutive elements. With `width == 0` returns an
/// empty outer vec.
fn chunk_into_vecs<E: Field>(flat: Vec<E>, width: usize) -> Vec<Vec<E>> {
    if width == 0 {
        return Vec::new();
    }
    assert!(
        flat.len() % width == 0,
        "flat length {} not divisible by tuple width {}",
        flat.len(),
        width
    );
    flat.chunks_exact(width)
        .map(|chunk| chunk.to_vec())
        .collect()
}

/// Absorb the bytes of an ideal-VOLE [`FlushMsg`] into a transcript.
fn absorb_vole_flush<E: Field + serde::Serialize>(
    transcript: &mut blake3::Hasher,
    msg: &FlushMsg<E>,
) {
    transcript.update(b"permutation-proof::test::ideal-vole-flush");
    transcript.update(&bcs::to_bytes(msg).expect("serialize"));
}

/// Number of RVOLE correlations the `vole_zk` backend consumes across
/// one prover/verifier pair running on `n` inputs with fan-in `eps`.
pub fn vole_zk_rvole_pregenerate_count(n: usize, eps: usize) -> usize {
    2 * crate::backend::vole_zk::fan_in_tree_internal_nodes(n, eps)
}

/// Polynomial degree the `vole_zk` backend's QS finalize expects from
/// its single RVOPE correlation, for fan-in `eps` over field `E`.
pub fn vole_zk_rvope_pregenerate_degree<E: Field + mpz_fields::ExtensionField<E>>(
    eps: usize,
) -> usize {
    let (constraints, _, _) = crate::backend::vole_zk::build_product_constraints::<E>(eps)
        .expect("eps must be in SUPPORTED_FAN_IN");
    mpz_poly_proof_core::prover::Prover::<E>::new(&constraints).required_vopes()
}
