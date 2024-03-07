//! Mocks for testing the share conversion protocol.

use crate::{OTReceiveElement, OTSendElement};

use super::{ConverterReceiver, ConverterSender, ReceiverConfig, SenderConfig};
use mpz_fields::Field;
use mpz_ot::ideal::{ideal_ot_shared_pair, IdealSharedOTReceiver, IdealSharedOTSender};
use utils_aio::duplex::MemoryDuplex;

/// A mock converter sender
pub type MockConverterSender<F> = ConverterSender<F, IdealSharedOTSender>;
/// A mock converter receiver
pub type MockConverterReceiver<F> = ConverterReceiver<F, IdealSharedOTReceiver>;

/// Creates a mock sender and receiver for testing the share conversion protocol.
#[allow(clippy::type_complexity)]
pub fn mock_converter_pair<F: Field>(
    sender_config: SenderConfig,
    receiver_config: ReceiverConfig,
) -> (
    ConverterSender<F, IdealSharedOTSender>,
    ConverterReceiver<F, IdealSharedOTReceiver>,
)
where
    IdealSharedOTSender: OTSendElement<F>,
    IdealSharedOTReceiver: OTReceiveElement<F>,
{
    let (c1, c2) = MemoryDuplex::new();

    let (ot_sender, ot_receiver) = ideal_ot_shared_pair();

    let sender = ConverterSender::new(sender_config, ot_sender, Box::new(c1));
    let receiver = ConverterReceiver::new(receiver_config, ot_receiver, Box::new(c2));

    (sender, receiver)
}
