//! Fan-in-product kernels.
//!
//! One kernel per supported fan-in in [`super::SUPPORTED_FAN_IN`];

use mpz_circuits_new::Context;
use mpz_fields::{ExtensionField, Field};
use mpz_poly_proof_core::{ConstraintId, ConstraintsBuilder};
use mpz_poly_proof_macros::poly_kernel;

/// Returned by [`add_product_kernel`] when the requested fan-in has no
/// pre-expanded kernel.
#[derive(Debug, thiserror::Error)]
#[error("fan-in {0} is outside the supported range")]
pub(crate) struct UnsupportedFanIn(pub usize);

// `len` is `n + 1`; passed explicitly because `#[poly_kernel]` requires
// the array length to be an integer literal, not a const expression.
macro_rules! product_kernel {
    ($n:literal, $len:literal) => {
        paste::paste! {
            #[poly_kernel]
            // The fn body is read by `#[poly_kernel]` at macro-expansion time
            // (lifted into a `ConstraintDef` impl) but never called at runtime.
            #[allow(dead_code)]
            pub fn [<product_ $n>]<C, E>(
                ctx: &mut C,
                vars: [C::Wire; $len],
            ) -> Result<(), C::Error>
            where
                C: Context<Field = E>,
                E: Field,
            {
                let mut p = vars[0];
                for i in 1..$n {
                    p = ctx.mul(p, vars[i]);
                }
                let diff = ctx.sub(p, vars[$n]);
                ctx.assert_const(diff, E::zero())
            }
        }
    };
}

macro_rules! product_kernels {
    ($(($n:literal, $len:literal)),+ $(,)?) => {
        $( product_kernel!($n, $len); )+

        /// Register the product-kernel matching `arity` on `b` and
        /// return the new constraint's id, or [`UnsupportedFanIn`] if
        /// no pre-expanded kernel exists for that fan-in.
        pub(crate) fn add_product_kernel<E: Field + ExtensionField<E>>(
            b: &mut ConstraintsBuilder<E>,
            arity: usize,
        ) -> Result<ConstraintId, UnsupportedFanIn> {
            paste::paste! {
                match arity {
                    $(
                        $n => Ok(
                            b.add::<[<Product $n>]>()
                                .expect("kernel registration is infallible"),
                        ),
                    )+
                    _ => Err(UnsupportedFanIn(arity)),
                }
            }
        }
    };
}

product_kernels!(
    (4, 5),
    (5, 6),
    (6, 7),
    (7, 8),
    (8, 9),
    (9, 10),
    (10, 11),
    (11, 12),
    (12, 13),
    (13, 14),
    (14, 15),
    (15, 16),
    (16, 17),
    (17, 18),
    (18, 19),
    (19, 20),
    (20, 21),
    (21, 22),
    (22, 23),
    (23, 24),
    (24, 25),
    (25, 26),
    (26, 27),
    (27, 28),
    (28, 29),
    (29, 30),
    (30, 31),
    (31, 32),
    (32, 33),
);
