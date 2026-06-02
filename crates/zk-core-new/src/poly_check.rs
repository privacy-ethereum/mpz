//! Batch check for the degree-`d` polynomial constraints (eprint 2021/076, §6).
//!
//! Runs alongside the degree-2 triple check ([`crate::check`]) under the same
//! `Δ` and Fiat–Shamir challenge `chi`. Each buffered constraint contributes a
//! χ-weighted term; the prover sends `d_max` coefficients (masked by a VOPE of
//! degree `d_max - 1`) and the verifier checks `Σ B_i·χ_i + B* = Σ_h U_h·Δ^h`.
//!
//! χ weights are drawn from `chi` on a dedicated ChaCha12 stream
//! ([`POLY_STREAM`]) so they are independent of the triple check's stream ids.

use mpz_fields::gf2_128::Gf2_128;
use rand_chacha::{
    ChaCha12Rng,
    rand_core::{RngCore, SeedableRng},
};
use zerocopy::IntoBytes;

use crate::{
    Error, Result,
    poly::{ProverExpr, VerifierTerm},
};

/// ChaCha12 stream id for the poly check's χ weights. `u64::MAX` cannot collide
/// with the triple check's per-segment stream ids.
const POLY_STREAM: u64 = u64::MAX;

/// Per-constraint χ weights derived from `chi`, one per buffered constraint.
fn chi_weights(chi: [u8; 32], n: usize) -> Vec<Gf2_128> {
    let mut chis = vec![Gf2_128::ZERO; n];
    let mut rng = ChaCha12Rng::from_seed(chi);
    rng.set_stream(POLY_STREAM);
    rng.fill_bytes(chis.as_mut_slice().as_mut_bytes());
    chis
}

/// Prover side: fold the buffered constraint coefficient vectors, χ-weighted,
/// into `d_max = vope.len()` accumulators, then mask with the VOPE coefficients.
pub(crate) fn check_prover(exprs: &[ProverExpr], chi: [u8; 32], vope: &[Gf2_128]) -> Vec<Gf2_128> {
    let d_max = vope.len();
    let mut acc = vec![Gf2_128::ZERO; d_max];

    if !exprs.is_empty() {
        let chis = chi_weights(chi, exprs.len());
        for (e, &c) in exprs.iter().zip(&chis) {
            e.accumulate(&mut acc, c);
        }
    }

    for (a, m) in acc.iter_mut().zip(vope) {
        *a = *a + *m;
    }
    acc
}

/// Verifier side: fold the buffered constraint values, χ-weighted, add the VOPE
/// sum, and check it equals `Σ_h coefficients[h]·Δ^h`.
pub(crate) fn check_verifier(
    terms: &[VerifierTerm],
    delta_pow: &[Gf2_128],
    chi: [u8; 32],
    vope_sum: Gf2_128,
    coefficients: &[Gf2_128],
) -> Result<()> {
    let d_max = coefficients.len();

    let mut b = vope_sum;
    if !terms.is_empty() {
        let chis = chi_weights(chi, terms.len());
        for (t, &c) in terms.iter().zip(&chis) {
            b = b + t.batch_value(d_max, delta_pow) * c;
        }
    }

    let rhs = coefficients
        .iter()
        .zip(delta_pow)
        .map(|(&u, &d)| u * d)
        .fold(Gf2_128::ZERO, |a, x| a + x);

    if b != rhs {
        return Err(Error::check());
    }
    Ok(())
}
