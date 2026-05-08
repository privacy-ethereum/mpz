//! Test utilities for the permutation-proof protocol.

use mpz_common::future::Output;
use mpz_fields::{ExtensionField, Field};
use rand::Rng;

use mpz_vole_core::{
    RVOLESender, VOLEReceiver,
    ideal::vole::{FlushMsg, ideal_vole},
};

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
    let total_scalars: usize = vectors.iter().enumerate().map(|(i, v)| v.len() * widths[i]).sum();

    let (mut sender, mut receiver) = ideal_vole::<W, E>(seed, delta);
    <_ as RVOLESender<E>>::alloc(&mut sender, total_scalars).expect("sender alloc");
    <_ as VOLEReceiver<W, E>>::alloc(&mut receiver, total_scalars).expect("receiver alloc");

    let flat_inputs: [Vec<W>; N] =
        std::array::from_fn(|i| vectors[i].iter().flatten().copied().collect());
    let mut futs: [_; N] = std::array::from_fn(|i| {
        Some(
            receiver
                .queue_recv_vole(&flat_inputs[i])
                .expect("queue"),
        )
    });

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
    flat.chunks_exact(width).map(|chunk| chunk.to_vec()).collect()
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
pub fn vole_zk_rvope_pregenerate_degree<E: Field>(eps: usize) -> usize {
    let (constraints, _) = crate::backend::vole_zk::build_product_constraints::<E>(eps);
    mpz_poly_proof_core::prover::Prover::<E>::new(&constraints).required_vopes()
}
