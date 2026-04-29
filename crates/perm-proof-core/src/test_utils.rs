//! Test utilities for the permutation-proof protocol.

use mpz_common::future::Output;
use mpz_fields::Field;
use poly_proof_core::SubfieldOf;
use rand::Rng;

use crate::{KeyTuple, MacTuple, ValueTuple};
use mpz_vole_core::{
    RVOLESender, VOLEReceiver,
    ideal::vole::{FlushMsg, ideal_vole},
};

/// Tight bundle of what [`commit_values`] produces: per-vector
/// prover-side [`MacTuple`]s and verifier-side [`KeyTuple`]s plus
/// the transcript carrying a binding to all of them.
#[derive(Debug)]
pub struct Committed<E: Field, const L: usize, const N: usize> {
    /// Prover-side MAC tuples, one `Vec` per input vector, in
    /// submission order.
    pub macs: [Vec<MacTuple<E, L>>; N],
    /// Verifier-side key tuples, one `Vec` per input vector, in
    /// submission order.
    pub keys: [Vec<KeyTuple<E, L>>; N],
    /// Transcript with the on-wire setup message absorbed under a
    /// fixed label.
    pub transcript: blake3::Hasher,
}

/// Commit `vectors` of `L`-tuples as authenticated wires via a
/// single ideal chosen-VOLE session.
pub fn commit_values<W, E, const L: usize, const N: usize>(
    vectors: [&[ValueTuple<W, L>]; N],
    delta: E,
    rng: &mut impl Rng,
) -> Committed<E, L, N>
where
    W: SubfieldOf<E>,
    E: Field + serde::Serialize,
{
    assert!(L >= 1, "commit_values: L must be at least 1");

    let seed: u64 = rng.random();
    let total_scalars: usize = vectors.iter().map(|v| v.len() * L).sum();

    let (mut sender, mut receiver) = ideal_vole::<W, E>(seed, delta);
    <_ as RVOLESender<E>>::alloc(&mut sender, total_scalars).expect("sender alloc");
    <_ as VOLEReceiver<W, E>>::alloc(&mut receiver, total_scalars).expect("receiver alloc");

    let mut futs: [_; N] = std::array::from_fn(|i| {
        Some(
            receiver
                .queue_recv_vole(vectors[i].as_flattened())
                .expect("queue"),
        )
    });

    // Single flush covers every queued wire.
    let flush = sender.flush().expect("flush must produce a message");
    let mut transcript = blake3::Hasher::new();
    absorb_vole_flush(&mut transcript, &flush);
    receiver.flush(flush).expect("receiver flush");

    // Re-bundle the returned flat MACs / keys back into `L`-tuples so
    // the layout matches the input shape vector for vector.
    let macs: [Vec<MacTuple<E, L>>; N] = std::array::from_fn(|i| {
        let flat = futs[i]
            .take()
            .expect("future slot populated")
            .try_recv()
            .expect("future must not cancel")
            .expect("future must resolve after flush")
            .macs;
        bundle_into_tuples::<E, L>(flat)
    });
    let keys: [Vec<KeyTuple<E, L>>; N] = std::array::from_fn(|i| {
        let flat = sender
            .try_send_vole(vectors[i].len() * L)
            .expect("sender keys")
            .keys;
        bundle_into_tuples::<E, L>(flat)
    });

    Committed {
        macs,
        keys,
        transcript,
    }
}

/// Reshape a flat `Vec<E>` of length `n · L` into a `Vec<[E; L]>` of
/// length `n`. Panics if the length isn't a multiple of `L`.
fn bundle_into_tuples<E: Field, const L: usize>(flat: Vec<E>) -> Vec<[E; L]> {
    assert!(
        flat.len() % L == 0,
        "flat length {} not divisible by tuple width {}",
        flat.len(),
        L
    );
    flat.chunks_exact(L)
        .map(|chunk| <[E; L]>::try_from(chunk).expect("exact-length chunk"))
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
pub fn vole_zk_rvope_pregenerate_degree<E: Field>(eps: usize) -> usize {
    let circuit = crate::backend::vole_zk::build_circuit::<E>(eps);
    poly_proof_core::prover::Prover::<E>::new(vec![circuit]).required_vopes()
}
