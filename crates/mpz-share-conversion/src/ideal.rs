//! Ideal share conversion.

use async_trait::async_trait;

use mpz_common::{
    ideal::{ideal_f2p, Alice, Bob},
    Context,
};
use mpz_fields::Field;
use mpz_share_conversion_core::ideal::{IdealA2M, IdealM2A};

use crate::{AdditiveToMultiplicative, MultiplicativeToAdditive, ShareConversionError};

#[derive(Debug, Default)]
struct Inner {
    m2a: IdealM2A,
    a2m: IdealA2M,
}

#[derive(Debug)]
enum Role {
    Alice(Alice<Inner>),
    Bob(Bob<Inner>),
}

/// An ideal share converter.
#[derive(Debug)]
pub struct IdealShareConverter(Role);

#[async_trait]
impl<Ctx: Context, F: Field> AdditiveToMultiplicative<Ctx, F> for IdealShareConverter {
    async fn to_multiplicative(
        &mut self,
        ctx: &mut Ctx,
        inputs: Vec<F>,
    ) -> Result<Vec<F>, ShareConversionError> {
        Ok(match &mut self.0 {
            Role::Alice(alice) => {
                alice
                    .call(ctx, inputs, |inner, a, b: Vec<F>| {
                        inner.a2m.generate(&a, &b)
                    })
                    .await
            }
            Role::Bob(bob) => {
                bob.call(ctx, inputs, |inner, a: Vec<F>, b| {
                    inner.a2m.generate(&a, &b)
                })
                .await
            }
        })
    }
}

#[async_trait]
impl<Ctx: Context, F: Field> MultiplicativeToAdditive<Ctx, F> for IdealShareConverter {
    async fn to_additive(
        &mut self,
        ctx: &mut Ctx,
        inputs: Vec<F>,
    ) -> Result<Vec<F>, ShareConversionError> {
        Ok(match &mut self.0 {
            Role::Alice(alice) => {
                alice
                    .call(ctx, inputs, |inner, a, b: Vec<F>| {
                        inner.m2a.generate(&a, &b)
                    })
                    .await
            }
            Role::Bob(bob) => {
                bob.call(ctx, inputs, |inner, a: Vec<F>, b| {
                    inner.m2a.generate(&a, &b)
                })
                .await
            }
        })
    }
}

/// Creates a pair of ideal share converters.
pub fn ideal_share_converter() -> (IdealShareConverter, IdealShareConverter) {
    let (alice, bob) = ideal_f2p(Inner::default());

    (
        IdealShareConverter(Role::Alice(alice)),
        IdealShareConverter(Role::Bob(bob)),
    )
}
