use std::sync::Arc;

use mpz_circuits::Circuit;
use mpz_common::Context;
use mpz_core::Block;
use mpz_garble_core::{AuthGen as AuthGenCore, AuthGenOutput, SSP};
use mpz_memory_core::correlated::{Delta, Key};
use mpz_garble_core::fpre::AuthBitShare;
use serio::{SinkExt, stream::IoStreamExt};

/// Generate a garbled circuit, streaming the encrypted gates to the evaluator
///
/// # Blocking
///
/// This function performs blocking computation, so be careful when calling it
/// from an async context.
#[tracing::instrument(fields(thread = %ctx.id()), skip_all)]
pub async fn generate(
    ctx: &mut Context,
    circ: Arc<Circuit>,
    delta: Delta,
    input_labels: &[Key],
    input_auth_bits: &[AuthBitShare],
    shares: &[AuthBitShare],
) -> Result<AuthGenOutput, AuthGeneratorError> {
    // TODO: use cointossing to generate random seed
    let seed = 0;
    let bucket_size = (SSP as f64 / (circ.and_count() as f64).log2()).ceil() as usize;
    let mut gb = AuthGenCore::new(seed, bucket_size);
    let io = ctx.io_mut();

    let (c, mut g) = gb.generate_pre_1(&circ, delta, input_auth_bits, shares).unwrap();
    io.feed(g.clone()).await?;
    io.flush().await?;
    let gr: Vec<Block>  = io.expect_next().await?;

    let d = gb.generate_pre_2(delta, c, &mut g, gr).unwrap();
    io.feed(d.clone()).await?;
    io.flush().await?;
    let dr: Vec<bool> = io.expect_next().await?;

    let data = gb.generate_pre_3(delta, &mut g, d, dr).unwrap();
    
    
    // Secure equality check
    let (digest, salt, hash) = gb.check_equality(g).unwrap();
    io.feed(hash).await?;
    io.flush().await?;
    
    let digest_recv: Block = io.expect_next().await?;
    if digest != digest_recv {
        return Err(AuthGeneratorError(ErrorRepr::EqualityCheckFailed));
    }

    io.feed(salt).await?;
    io.flush().await?;

    
    io.feed(data.clone()).await?;
    io.flush().await?;
    let data_recv: Vec<bool> = io.expect_next().await?;

    gb.generate_pre_4(data, data_recv).unwrap();
    gb.generate_free(&circ).unwrap();

    let (px, py) = gb.generate_de(&circ).unwrap();
    io.feed((px,py)).await?;
    io.flush().await?;
    let (px_recv, py_recv): (Vec<bool>, Vec<bool>) = io.expect_next().await?;

    let mut gb_iter= gb.generate_batched(&circ, delta, &input_labels, px_recv, py_recv).unwrap();
    while let Some(batch) = gb_iter.by_ref().next() {
        io.feed(batch).await?;
    }
    io.flush().await?;

    let masked_values: Vec<bool> = io.expect_next().await?;
    Ok(gb_iter.finish(masked_values)?)
}

/// Garbler error.
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub(crate) struct AuthGeneratorError(#[from] ErrorRepr);

#[derive(Debug, thiserror::Error)]
enum ErrorRepr {
    #[error("core error: {0}")]
    Core(#[from] mpz_garble_core::AuthGeneratorError),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("equality check failed")]
    EqualityCheckFailed,
}

impl From<std::io::Error> for AuthGeneratorError {
    fn from(err: std::io::Error) -> Self {
        AuthGeneratorError(ErrorRepr::Io(err))
    }
}

impl From<mpz_garble_core::AuthGeneratorError> for AuthGeneratorError {
    fn from(err: mpz_garble_core::AuthGeneratorError) -> Self {
        AuthGeneratorError(ErrorRepr::Core(err))
    }
}
