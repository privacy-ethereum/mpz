use std::sync::Arc;

use mpz_circuits::Circuit;
use mpz_common::Context;
use mpz_garble_core::{GarblerOutput, GarblerWorker};
use mpz_memory_core::correlated::Key;
use serio::SinkExt;

/// Generate a garbled circuit, streaming the encrypted gates to the evaluator
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
/// * `circ` - The circuit to garble.
/// * `inputs` - The inputs of the circuit.
/// * `worker` - The worker to use.
#[tracing::instrument(fields(thread = %ctx.id()), skip_all)]
pub(crate) async fn generate(
    ctx: &mut Context,
    circ: Arc<Circuit>,
    inputs: &[Key],
    worker: GarblerWorker,
) -> Result<GarblerOutput, GarblerError> {
    let mut gb_iter = worker.generate_batched(&circ, inputs)?;
    let io = ctx.io_mut();

    while let Some(batch) = gb_iter.by_ref().next() {
        io.feed(batch).await?;
    }
    io.flush().await?;

    Ok(gb_iter.finish()?)
}

/// Garbler error.
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub(crate) struct GarblerError(#[from] ErrorRepr);

#[derive(Debug, thiserror::Error)]
enum ErrorRepr {
    #[error("core error: {0}")]
    Core(#[from] mpz_garble_core::GarblerError),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

impl From<std::io::Error> for GarblerError {
    fn from(err: std::io::Error) -> Self {
        GarblerError(ErrorRepr::Io(err))
    }
}

impl From<mpz_garble_core::GarblerError> for GarblerError {
    fn from(err: mpz_garble_core::GarblerError) -> Self {
        GarblerError(ErrorRepr::Core(err))
    }
}
