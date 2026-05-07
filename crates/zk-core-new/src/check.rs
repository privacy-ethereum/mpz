//! QuickSilver consistency check (Fig 5, step 7).
//!
//! Prover and verifier accumulate one [`Triple`] per AND gate during the
//! replay pass, then collapse them via Fiat–Shamir into a single linear
//! relation `B = A_0 + A_1·Δ` protected by a VOPE(1) mask.
//!
//! Both sides compute an inner product against a PRG-derived challenge
//! vector `χ`:
//! - Prover:  `U = <x·y, χ> + a_0`, `V = <(lsb(x)·y + lsb(y)·x + z), χ> + a_1`.
//! - Verifier: `W = <(x·y + Δ·z), χ> + b`.
//!
//! To keep memory bounded (for runs with ~10⁷+ triples) and to enable
//! SIMD/rayon acceleration, triples are processed in ~L1-sized
//! segments. When the `rayon` feature is enabled each segment runs on
//! its own worker thread; deterministic `χ` generation across workers
//! is preserved via [`ChaCha12Rng::set_stream`].

use itybity::{GetBit, Lsb0};
use mpz_fields::{Field, gf2_128::Gf2_128};
use rand_chacha::{
    ChaCha12Rng,
    rand_core::{RngCore, SeedableRng},
};
#[cfg(feature = "rayon")]
use rayon::prelude::*;
use zerocopy::IntoBytes;

use crate::{Error, Result};

/// Segment size for the chunked inner-product loop. Sized so the
/// per-segment on-stack SoA buffers (up to 4 × 16 B × SEGMENT_SIZE) plus
/// the source triples stay comfortably inside L1-D on modern cores.
const SEGMENT_SIZE: usize = 256;

/// Bit-0 accessor for the LSB-of-MAC "pointer bit" trick.
#[inline]
fn lsb(g: Gf2_128) -> bool {
    GetBit::<Lsb0>::get_bit(&g, 0)
}

/// Per-AND-gate tuple. On the prover side: `(m_α, m_β, m_γ)`. On the
/// verifier side: `(k_α, k_β, k_γ)` with `k_γ` already adjusted.
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct Triple {
    pub x: Gf2_128,
    pub y: Gf2_128,
    pub z: Gf2_128,
}

/// Accumulates `(u, v)` over one segment of triples using its own
/// (stream-separated) `χ` generator.
///
/// Per segment:
/// - Transpose the AoS `segment` slice into on-stack SoA `xs`, `ys` plus a
///   precomputed `body_v[i] = a_10 + a_11 + z` (masked XORs only, no muls).
/// - Bulk-fill `χ` with one `ChaCha12Rng::fill_bytes` call, which amortises
///   ChaCha12's block-generation setup across the whole segment.
/// - `u = Σ xᵢ·yᵢ·χᵢ` via [`Gf2_128::double_inner_product`] (one reduction per
///   iter for `xᵢ·yᵢ`, then raw-accumulated `·χᵢ`).
/// - `v = Σ body_vᵢ·χᵢ` via [`Gf2_128::inner_product`] (raw-accumulated).
#[inline]
fn prover_segment(
    base_rng: &ChaCha12Rng,
    stream_id: u64,
    segment: &[Triple],
) -> (Gf2_128, Gf2_128) {
    let mut rng = base_rng.clone();
    rng.set_stream(stream_id);

    let len = segment.len();
    let mut xs = [Gf2_128::new(0); SEGMENT_SIZE];
    let mut ys = [Gf2_128::new(0); SEGMENT_SIZE];
    let mut body_v = [Gf2_128::new(0); SEGMENT_SIZE];
    let mut chi = [Gf2_128::new(0); SEGMENT_SIZE];

    for (i, t) in segment.iter().enumerate() {
        xs[i] = t.x;
        ys[i] = t.y;
        // `a_10 = y if lsb(x) else 0`, `a_11 = x if lsb(y) else 0`,
        // expressed as `a · mask` with `mask ∈ {0, u128::MAX}` so there
        // is no data-dependent branch.
        let mask_x = (lsb(t.x) as u128).wrapping_neg();
        let mask_y = (lsb(t.y) as u128).wrapping_neg();
        body_v[i] =
            Gf2_128::new(t.y.to_inner() & mask_x) + Gf2_128::new(t.x.to_inner() & mask_y) + t.z;
    }

    rng.fill_bytes(chi[..len].as_mut_bytes());

    let u = Gf2_128::double_inner_product(&xs[..len], &ys[..len], &chi[..len]);
    let v = Gf2_128::inner_product(&body_v[..len], &chi[..len]);
    (u, v)
}

/// Accumulates `w` over one segment of triples via the distributivity
/// split `Σ (xᵢyᵢ + δzᵢ)·χᵢ = Σ xᵢyᵢχᵢ + δ·Σ zᵢχᵢ`.
#[inline]
fn verifier_segment(
    base_rng: &ChaCha12Rng,
    stream_id: u64,
    segment: &[Triple],
    delta: Gf2_128,
) -> Gf2_128 {
    let mut rng = base_rng.clone();
    rng.set_stream(stream_id);

    let len = segment.len();
    let mut xs = [Gf2_128::new(0); SEGMENT_SIZE];
    let mut ys = [Gf2_128::new(0); SEGMENT_SIZE];
    let mut zs = [Gf2_128::new(0); SEGMENT_SIZE];
    let mut chi = [Gf2_128::new(0); SEGMENT_SIZE];

    for (i, t) in segment.iter().enumerate() {
        xs[i] = t.x;
        ys[i] = t.y;
        zs[i] = t.z;
    }

    rng.fill_bytes(chi[..len].as_mut_bytes());

    let xy_chi = Gf2_128::double_inner_product(&xs[..len], &ys[..len], &chi[..len]);
    let z_chi = Gf2_128::inner_product(&zs[..len], &chi[..len]);
    xy_chi + delta * z_chi
}

/// Prover-side batch check. Consumes the per-gate triples and the
/// already-packed VOPE(1) mask `(a_0, a_1)` (receiver side), returns
/// `(U, V)` to send.
pub(crate) fn check_prover(
    triples: &[Triple],
    chi: [u8; 32],
    a_0: Gf2_128,
    a_1: Gf2_128,
) -> (Gf2_128, Gf2_128) {
    let rng = ChaCha12Rng::from_seed(chi);

    let (mut u_acc, mut v_acc) = cfg_select! {
        feature = "rayon" => triples
            .par_chunks(SEGMENT_SIZE)
            .enumerate()
            .map(|(id, seg)| prover_segment(&rng, id as u64, seg))
            .reduce(
                || (Gf2_128::new(0), Gf2_128::new(0)),
                |(u1, v1), (u2, v2)| (u1 + u2, v1 + v2),
            ),
        _ => triples
            .chunks(SEGMENT_SIZE)
            .enumerate()
            .map(|(id, seg)| prover_segment(&rng, id as u64, seg))
            .fold(
                (Gf2_128::new(0), Gf2_128::new(0)),
                |(u1, v1), (u2, v2)| (u1 + u2, v1 + v2),
            ),
    };

    u_acc = u_acc + a_0;
    v_acc = v_acc + a_1;

    (u_acc, v_acc)
}

/// Verifier-side batch check. Consumes the per-gate triples and the
/// already-packed VOPE(1) mask `b` (sender side). Returns `Err` on
/// mismatch.
pub(crate) fn check_verifier(
    triples: &[Triple],
    delta: Gf2_128,
    chi: [u8; 32],
    b: Gf2_128,
    u: Gf2_128,
    v: Gf2_128,
) -> Result<()> {
    let rng = ChaCha12Rng::from_seed(chi);

    let mut w_acc = cfg_select! {
        feature = "rayon" => triples
            .par_chunks(SEGMENT_SIZE)
            .enumerate()
            .map(|(id, seg)| verifier_segment(&rng, id as u64, seg, delta))
            .reduce(|| Gf2_128::new(0), |w1, w2| w1 + w2),
        _ => triples
            .chunks(SEGMENT_SIZE)
            .enumerate()
            .map(|(id, seg)| verifier_segment(&rng, id as u64, seg, delta))
            .fold(Gf2_128::new(0), |w1, w2| w1 + w2),
    };

    w_acc = w_acc + b;

    if w_acc != u + delta * v {
        return Err(Error::check());
    }

    Ok(())
}
