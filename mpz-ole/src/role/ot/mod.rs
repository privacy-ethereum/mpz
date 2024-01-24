//! Provides implementations of ROLEe protocols based on oblivious transfer.

mod evaluator;
mod provider;

pub use evaluator::ROLEeEvaluator;
use mpz_share_conversion_core::Field;
pub use provider::ROLEeProvider;

use crate::msg::ROLEeMessage;
use futures::{SinkExt, StreamExt};
use utils_aio::{sink::IoSink, stream::IoStream};

/// Converts a sink of random OLE messages into a sink of random OT messages.
fn into_rot_sink<'a, Si: IoSink<ROLEeMessage<T, F>> + Send + Unpin, T: Send + 'a, F: Field>(
    sink: &'a mut Si,
) -> impl IoSink<T> + Send + Unpin + 'a {
    Box::pin(SinkExt::with(sink, |msg| async move {
        Ok(ROLEeMessage::RandomOTMessage(msg))
    }))
}

/// Converts a stream of random OLE messages into a stream of random OT messages.
fn into_rot_stream<'a, St: IoStream<ROLEeMessage<T, F>> + Send + Unpin, T: Send + 'a, F: Field>(
    stream: &'a mut St,
) -> impl IoStream<T> + Send + Unpin + 'a {
    StreamExt::map(stream, |msg| match msg {
        Ok(msg) => msg.try_into_random_ot_message().map_err(From::from),
        Err(err) => Err(err),
    })
}
