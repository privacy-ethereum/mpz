//! Provides implementations of ROLEe protocols based on random OT.

mod evaluator;
mod provider;

pub use evaluator::ROLEeEvaluator;
pub use provider::ROLEeProvider;

use mpz_share_conversion_core::Field;

/// Workaround because of feature `generic_const_exprs` not available in stable.
///
/// This is used to check at compile-time that the correct const-generic implementation is used for
/// a specific field.
struct Check<const N: usize, F: Field>(std::marker::PhantomData<F>);

impl<const N: usize, F: Field> Check<N, F> {
    const IS_BITSIZE_CORRECT: () = assert!(
        N as u32 == F::BIT_SIZE,
        "Wrong bit size used for field. You need to use `F::BIT_SIZE` for N."
    );
}
