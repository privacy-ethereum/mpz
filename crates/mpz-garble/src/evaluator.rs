use std::sync::Arc;

use mpz_circuits::Circuit;
use mpz_common::Context;
use mpz_garble_core::{
    EncryptedGateBatch, Evaluator as EvaluatorCore, EvaluatorOutput, GarbledCircuit,
};
use mpz_memory_core::correlated::Mac;
use serio::stream::IoStreamExt;

#[tracing::instrument(fields(thread = %ctx.id()), skip_all)]
pub async fn receive_garbled_circuit<Ctx: Context>(
    ctx: &mut Ctx,
    circ: &Circuit,
) -> Result<GarbledCircuit, EvaluatorError> {
    let gate_count = circ.and_count();
    let mut gates = Vec::with_capacity(gate_count);

    while gates.len() < gate_count {
        let batch: EncryptedGateBatch = ctx.io_mut().expect_next().await?;
        gates.extend_from_slice(&batch.into_array());
    }

    // Trim off any batch padding.
    gates.truncate(gate_count);

    Ok(GarbledCircuit { gates })
}

/// Evaluate a garbled circuit, streaming the encrypted gates from the evaluator
/// in batches.
///
/// # Blocking
///
/// This function performs blocking computation, so be careful when calling it
/// from an async context.
///
/// # Arguments
///
/// * `ctx` - The context to use.
/// * `circ` - The circuit to evaluate.
/// * `inputs` - The inputs of the circuit.
#[tracing::instrument(fields(thread = %ctx.id()), skip_all)]
pub async fn evaluate<Ctx: Context>(
    ctx: &mut Ctx,
    circ: Arc<Circuit>,
    inputs: Vec<Mac>,
) -> Result<EvaluatorOutput, EvaluatorError> {
    let mut ev = EvaluatorCore::default();
    let mut ev_consumer = ev.evaluate_batched(&circ, inputs)?;
    let io = ctx.io_mut();

    while ev_consumer.wants_gates() {
        let batch: EncryptedGateBatch = io.expect_next().await?;
        ev_consumer.next(batch);
    }

    Ok(ev_consumer.finish()?)
}

/// Garbled circuit evaluator error.
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct EvaluatorError(#[from] ErrorRepr);

#[derive(Debug, thiserror::Error)]
enum ErrorRepr {
    #[error("core error: {0}")]
    Core(#[from] mpz_garble_core::EvaluatorError),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

impl From<std::io::Error> for EvaluatorError {
    fn from(err: std::io::Error) -> Self {
        EvaluatorError(ErrorRepr::Io(err))
    }
}

impl From<mpz_garble_core::EvaluatorError> for EvaluatorError {
    fn from(err: mpz_garble_core::EvaluatorError) -> Self {
        EvaluatorError(ErrorRepr::Core(err))
    }
}
