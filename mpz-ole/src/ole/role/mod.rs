//! Provides implementations of OLE with errors (OLEe) based on ROLEe.

mod evaluator;
mod provider;

pub use evaluator::OLEeEvaluator;
use futures::{SinkExt, StreamExt};
use mpz_share_conversion_core::Field;
pub use provider::OLEeProvider;
use utils_aio::{sink::IoSink, stream::IoStream};

use crate::msg::OLEeMessage;

/// Converts a sink of OLEe messages into a sink of ROLEe messsages.
fn into_role_sink<'a, Si: IoSink<OLEeMessage<T, F>> + Send + Unpin, T: Send + 'a, F: Field>(
    sink: &'a mut Si,
) -> impl IoSink<T> + Send + Unpin + 'a {
    Box::pin(SinkExt::with(sink, |msg| async move {
        Ok(OLEeMessage::ROLEeMessage(msg))
    }))
}

/// Converts a stream of OLEe messages into a stream of ROLEe messsages.
fn into_role_stream<'a, St: IoStream<OLEeMessage<T, F>> + Send + Unpin, T: Send + 'a, F: Field>(
    stream: &'a mut St,
) -> impl IoStream<T> + Send + Unpin + 'a {
    StreamExt::map(stream, |msg| match msg {
        Ok(msg) => msg.try_into_rol_ee_message().map_err(From::from),
        Err(err) => Err(err),
    })
}
