//! Extension-field VOLE (VOPE degree 1) for the consistency check's mask.
//!
//! Packs 128 base-field sVOLE correlations into one F_{2^128} correlation
//! via inner product with the monomial basis. Used to sample
//! `(A_0*, A_1*)` (prover) and `B*` (verifier) for Fig 5 step 7.

use mpz_fields::{ExtensionField, Field, gf2::Gf2, gf2_128::Gf2_128};

/// Verifier (sVOLE sender) side: collapse 128 keys into `B*`.
pub(crate) fn vope_sender(keys: &[Gf2_128; 128]) -> Gf2_128 {
    Gf2_128::inner_product(Gf2_128::MONOMIAL_BASIS, keys)
}

/// Prover (sVOLE receiver) side: collapse 128 `(choice, mac)` pairs into
/// `(A_0*, A_1*)`.
pub(crate) fn vope_receiver(choices: &[bool; 128], ev: &[Gf2_128; 128]) -> (Gf2_128, Gf2_128) {
    let a_0 = Gf2_128::inner_product(Gf2_128::MONOMIAL_BASIS, ev);
    let choices_gf2: [Gf2; 128] = core::array::from_fn(|i| Gf2(choices[i]));
    let a_1 = Gf2_128::inner_product_subfield(&choices_gf2, Gf2_128::MONOMIAL_BASIS);
    (a_0, a_1)
}
