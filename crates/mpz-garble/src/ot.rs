//! Traits for transferring encodings via oblivious transfer.

use async_trait::async_trait;
use itybity::IntoBits;
use mpz_circuits::types::Value;
use mpz_common::Context;
use mpz_core::Block;
use mpz_garble_core::{encoding_state, EncodedValue, Label};
use mpz_ot::TransferId;

/// A trait for sending encodings via oblivious transfer.
#[async_trait]
pub trait OTSendEncoding<Ctx> {
    /// Sends encodings to the receiver.
    async fn send(
        &mut self,
        ctx: &mut Ctx,
        input: Vec<EncodedValue<encoding_state::Full>>,
    ) -> Result<EncodingSenderOutput, mpz_ot::OTError>;
}

/// The output of an encoding sender.
#[derive(Debug)]
pub struct EncodingSenderOutput {
    /// The transfer id.
    pub id: TransferId,
}

#[async_trait]
impl<Ctx: Context, T> OTSendEncoding<Ctx> for T
where
    T: mpz_ot::OTSender<Ctx, [Block; 2]> + Send + Sync,
{
    async fn send(
        &mut self,
        ctx: &mut Ctx,
        input: Vec<EncodedValue<encoding_state::Full>>,
    ) -> Result<EncodingSenderOutput, mpz_ot::OTError> {
        let blocks: Vec<[Block; 2]> = input
            .into_iter()
            .flat_map(|v| v.iter_blocks().collect::<Vec<_>>())
            .collect();

        let output = self.send(ctx, &blocks).await?;

        Ok(EncodingSenderOutput { id: output.id })
    }
}

/// A trait for receiving encodings via oblivious transfer.
#[async_trait]
pub trait OTReceiveEncoding<Ctx> {
    /// Receives encodings from the sender.
    async fn receive(
        &mut self,
        ctx: &mut Ctx,
        choice: Vec<Value>,
    ) -> Result<EncodingReceiverOutput, mpz_ot::OTError>;
}

/// The output of an encoding receiver.
#[derive(Debug)]
pub struct EncodingReceiverOutput {
    /// The transfer id.
    pub id: TransferId,
    /// The encodings.
    pub encodings: Vec<EncodedValue<encoding_state::Active>>,
}

#[async_trait]
impl<Ctx: Context, T> OTReceiveEncoding<Ctx> for T
where
    T: mpz_ot::OTReceiver<Ctx, bool, Block> + Send + Sync,
{
    async fn receive(
        &mut self,
        ctx: &mut Ctx,
        choice: Vec<Value>,
    ) -> Result<EncodingReceiverOutput, mpz_ot::OTError> {
        let mut output = self
            .receive(
                ctx,
                &choice
                    .iter()
                    .flat_map(|value| value.clone().into_iter_lsb0())
                    .collect::<Vec<bool>>(),
            )
            .await?;

        let encodings = choice
            .iter()
            .map(|value| {
                let labels = output
                    .msgs
                    .drain(..value.value_type().len())
                    .map(Label::new)
                    .collect::<Vec<_>>();
                EncodedValue::<encoding_state::Active>::from_labels(value.value_type(), &labels)
                    .expect("label length should match value length")
            })
            .collect();

        Ok(EncodingReceiverOutput {
            id: output.id,
            encodings,
        })
    }
}

/// A trait for verifying encodings sent via oblivious transfer.
#[async_trait]
pub trait OTVerifyEncoding<Ctx> {
    /// Verifies that the encodings sent by the sender are correct.
    async fn verify(
        &mut self,
        ctx: &mut Ctx,
        id: TransferId,
        input: Vec<EncodedValue<encoding_state::Full>>,
    ) -> Result<(), mpz_ot::OTError>;
}

#[async_trait]
impl<Ctx: Context, T> OTVerifyEncoding<Ctx> for T
where
    T: mpz_ot::VerifiableOTReceiver<Ctx, bool, Block, [Block; 2]> + Send + Sync,
{
    async fn verify(
        &mut self,
        ctx: &mut Ctx,
        id: TransferId,
        input: Vec<EncodedValue<encoding_state::Full>>,
    ) -> Result<(), mpz_ot::OTError> {
        let blocks: Vec<[Block; 2]> = input
            .into_iter()
            .flat_map(|v| v.iter_blocks().collect::<Vec<_>>())
            .collect();

        mpz_ot::VerifiableOTReceiver::verify(self, ctx, id, &blocks).await
    }
}

/// A trait for verifiable oblivious transfer of encodings.
pub trait VerifiableOTSendEncoding<Ctx>: mpz_ot::CommittedOTSender<Ctx, [Block; 2]> {}

impl<Ctx, T> VerifiableOTSendEncoding<Ctx> for T where T: mpz_ot::CommittedOTSender<Ctx, [Block; 2]> {}

/// A trait for verifiable oblivious transfer of encodings.
pub trait VerifiableOTReceiveEncoding<Ctx>: OTReceiveEncoding<Ctx> + OTVerifyEncoding<Ctx> {}

impl<Ctx, T> VerifiableOTReceiveEncoding<Ctx> for T where
    T: OTReceiveEncoding<Ctx> + OTVerifyEncoding<Ctx>
{
}

#[cfg(test)]
mod tests {
    use super::*;

    use mpz_circuits::circuits::AES128;
    use mpz_common::executor::test_st_executor;
    use mpz_garble_core::{ChaChaEncoder, Encoder};
    use mpz_ot::ideal::ot::ideal_ot;

    #[tokio::test]
    async fn test_encoding_transfer() {
        let encoder = ChaChaEncoder::new([0u8; 32]);
        let (mut sender, mut receiver) = ideal_ot();
        let (mut ctx_a, mut ctx_b) = test_st_executor(8);

        let inputs = AES128
            .inputs()
            .iter()
            .enumerate()
            .map(|(id, value)| encoder.encode_by_type(id as u64, &value.value_type()))
            .collect::<Vec<_>>();
        let choices = vec![Value::from([42u8; 16]), Value::from([69u8; 16])];

        let (_, output_receiver) = futures::try_join!(
            sender.send(&mut ctx_a, inputs.clone()),
            receiver.receive(&mut ctx_b, choices.clone())
        )
        .unwrap();

        let expected = choices
            .into_iter()
            .zip(inputs)
            .map(|(choice, full)| full.select(choice).unwrap())
            .collect::<Vec<_>>();

        assert_eq!(output_receiver.encodings, expected);
    }
}
