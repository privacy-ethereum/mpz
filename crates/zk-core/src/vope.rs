//! Vector oblivious polynomial evaluation (VOPE) over `GF(2^128)`.
//!
//! Lifts a batch of 128 single-bit correlations into a single
//! [`Gf2_128`] correlation by combining them with the monomial basis of
//! `GF(2^128)` viewed as a degree-128 extension of `GF(2)`. The sender side
//! folds its keys ([`vope_sender`]), while the receiver side folds its choices
//! and evaluations into the two coefficients of the resulting affine line
//! ([`vope_receiver`]).

use mpz_fields::{ExtensionField, Field, gf2::Gf2, gf2_128::Gf2_128};

/// Folds the sender's VOPE keys into the mask `b` the verifier applies to its
/// check accumulator `w`.
pub fn vope_sender(keys: &[Gf2_128; 128]) -> Gf2_128 {
    Gf2_128::inner_product(<Gf2_128 as ExtensionField<Gf2>>::MONOMIAL_BASIS, keys)
}

/// Folds the receiver's VOPE correlation into the coefficients `(a_0, a_1)`
/// of the affine line used to mask the proof accumulators `(u, v)`.
pub fn vope_receiver(choices: &[bool; 128], ev: &[Gf2_128; 128]) -> (Gf2_128, Gf2_128) {
    let a_0 = Gf2_128::inner_product(<Gf2_128 as ExtensionField<Gf2>>::MONOMIAL_BASIS, ev);
    let choices_gf2: [Gf2; 128] = core::array::from_fn(|i| Gf2(choices[i]));
    let a_1 = Gf2_128::inner_product_subfield(
        &choices_gf2,
        <Gf2_128 as ExtensionField<Gf2>>::MONOMIAL_BASIS,
    );
    (a_0, a_1)
}
