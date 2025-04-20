use std::sync::Arc;

use mpz_circuits::Circuit;
use mpz_common::Context;
use mpz_garble_core::{
    AuthHalfGateBatch, AuthEval as AuthEvalCore, AuthEvalOutput, AuthGarbledCircuit, SSP
};
use mpz_garble_core::fpre::AuthBitShare;

use mpz_memory_core::correlated::{Delta, Mac};
use serio::{SinkExt, stream::IoStreamExt};

use mpz_core::Block;
use mpz_cointoss::{cointoss_receiver, CointossError};

#[tracing::instrument(fields(thread = %ctx.id()), skip_all)]
pub async fn receive_garbled_circuit(
    ctx: &mut Context,
    circ: &Circuit,
) -> Result<AuthGarbledCircuit, AuthEvaluatorError> {
    let gate_count = circ.and_count();
    let mut gates = Vec::with_capacity(gate_count);

    while gates.len() < gate_count {
        let batch: AuthHalfGateBatch = ctx.io_mut().expect_next().await?;
        gates.extend_from_slice(&batch.into_array());
    }

    // Trim off any batch padding.
    gates.truncate(gate_count);

    Ok(AuthGarbledCircuit { gates })
}

/// Evaluate an authenticated garbled circuit, streaming the encrypted gates from the evaluator
/// in batches.
///
/// # Blocking
///
/// This function performs blocking computation, so be careful when calling it
/// from an async context.
#[tracing::instrument(fields(thread = %ctx.id()), skip_all)]
pub async fn evaluate(
    ctx: &mut Context,
    circ: Arc<Circuit>,
    delta: Delta,
    input_labels: &[Mac],
    masked_inputs: Vec<bool>,
    input_auth_bits: &[AuthBitShare],
    shares: &[AuthBitShare],
) -> Result<AuthEvalOutput, AuthEvaluatorError> {
    // Use cointoss to agree on a random seed
    let receiver_seed = vec![Block::random(&mut rand::rng())];
    let receiver_output = cointoss_receiver(ctx, receiver_seed).await?;
    let seed = u64::from_le_bytes(receiver_output[0].as_bytes()[..8].try_into().unwrap());
    
    let bucket_size = (SSP as f64 / (circ.and_count() as f64).log2()).ceil() as usize;
    let mut ev = AuthEvalCore::new(seed, bucket_size);
    let io = ctx.io_mut();  

    // Function independent pre-processing: using auth bits to generate auth triples
    let (c, mut g) = ev.evaluate_pre_1(&circ, delta, input_auth_bits, shares).unwrap();
    io.feed(g.clone()).await?;
    io.flush().await?;
    let gr: Vec<Block>  = io.expect_next().await?;

    let d = ev.evaluate_pre_2(delta, c, &mut g, gr).unwrap();
    io.feed(d.clone()).await?;
    io.flush().await?;
    let dr: Vec<bool> = io.expect_next().await?;

    let data = ev.evaluate_pre_3(delta, &mut g, d, dr).unwrap();
    

    // Secure equality check for authenticity of triples
    let digest = ev.check_equality(g).unwrap();
    let hash_recv: Block = io.expect_next().await?;
    io.feed(digest).await?;
    io.flush().await?;
    
    let salt_recv: Block = io.expect_next().await?;

    let expected_hash = ev.check_salt(salt_recv, digest).unwrap();
    if expected_hash != hash_recv {
        return Err(AuthEvaluatorError(ErrorRepr::EqualityCheckFailed));
    }

    io.feed(data.clone()).await?;
    io.flush().await?;
    let data_recv: Vec<bool> = io.expect_next().await?;

    ev.evaluate_pre_4(data, data_recv).unwrap();
    
    
    // Function dependent pre-processing: generate auth bits for all wires in the circuit
    ev.evaluate_free(&circ).unwrap();
    let (px, py) = ev.evaluate_de(&circ).unwrap();
    io.feed((px,py)).await?;
    io.flush().await?;
    let (px_recv, py_recv): (Vec<bool>, Vec<bool>) = io.expect_next().await?;

    let mut ev_consumer = ev.evaluate_batched(&circ, delta, &input_labels, masked_inputs, px_recv, py_recv).unwrap();

    while ev_consumer.wants_gates() {
        let batch: AuthHalfGateBatch = io.expect_next().await?;
        ev_consumer.next(batch);
    }

    let output = ev_consumer.finish()?;
    let masked_values = output.masked_values.clone();

    // TODO: For preprocessing, send all the masked values at the end
    io.feed(masked_values).await?;
    io.flush().await?;

    Ok(output)
}

/// Authenticated evaluator error.
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub(crate) struct AuthEvaluatorError(#[from] ErrorRepr);

#[derive(Debug, thiserror::Error)]
enum ErrorRepr {
    #[error("core error: {0}")]
    Core(#[from] mpz_garble_core::AuthEvaluatorError),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("equality check failed")]
    EqualityCheckFailed,
    #[error("cointoss error: {0}")]
    Cointoss(#[from] CointossError),
}

impl From<std::io::Error> for AuthEvaluatorError {
    fn from(err: std::io::Error) -> Self {
        AuthEvaluatorError(ErrorRepr::Io(err))
    }
}

impl From<mpz_garble_core::AuthEvaluatorError> for AuthEvaluatorError {
    fn from(err: mpz_garble_core::AuthEvaluatorError) -> Self {
        AuthEvaluatorError(ErrorRepr::Core(err))
    }
}

impl From<CointossError> for AuthEvaluatorError {
    fn from(err: CointossError) -> Self {
        AuthEvaluatorError(ErrorRepr::Cointoss(err))
    }
}