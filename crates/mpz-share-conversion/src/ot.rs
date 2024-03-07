use async_trait::async_trait;

use mpz_core::Block;
use mpz_fields::{gf2_128::Gf2_128, p256::P256, Field};

/// A trait for sending field elements via oblivious transfer.
#[async_trait]
pub trait OTSendElement<F: Field>: Send + Sync {
    /// Sends elements to the receiver.
    async fn send(&self, id: &str, input: Vec<[F; 2]>) -> Result<(), mpz_ot::OTError>;
}

#[async_trait]
impl<T> OTSendElement<P256> for T
where
    T: mpz_ot::OTSenderShared<[[u8; 32]; 2]> + Send + Sync,
{
    async fn send(&self, id: &str, input: Vec<[P256; 2]>) -> Result<(), mpz_ot::OTError> {
        let bytes: Vec<[[u8; 32]; 2]> = input
            .into_iter()
            .map(|[a, b]| [a.into(), b.into()])
            .collect();

        self.send(id, &bytes).await
    }
}

#[async_trait]
impl<T> OTSendElement<Gf2_128> for T
where
    T: mpz_ot::OTSenderShared<[Block; 2]> + Send + Sync,
{
    async fn send(&self, id: &str, input: Vec<[Gf2_128; 2]>) -> Result<(), mpz_ot::OTError> {
        let blocks: Vec<_> = input
            .into_iter()
            .map(|[a, b]| [a.into(), b.into()])
            .collect();

        self.send(id, &blocks).await
    }
}

/// A trait for receiving field elements via oblivious transfer.
#[async_trait]
pub trait OTReceiveElement<F: Field>: Send + Sync {
    /// Receives elements from the sender.
    async fn receive(&self, id: &str, choice: Vec<bool>) -> Result<Vec<F>, mpz_ot::OTError>;
}

#[async_trait]
impl<T> OTReceiveElement<P256> for T
where
    T: mpz_ot::OTReceiverShared<bool, [u8; 32]> + Send + Sync,
{
    async fn receive(&self, id: &str, choice: Vec<bool>) -> Result<Vec<P256>, mpz_ot::OTError> {
        let bytes = self.receive(id, &choice).await?;

        bytes
            .into_iter()
            .map(|bytes| bytes.try_into())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| {
                mpz_ot::OTError::IOError(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "invalid P256 element",
                ))
            })
    }
}

#[async_trait]
impl<T> OTReceiveElement<Gf2_128> for T
where
    T: mpz_ot::OTReceiverShared<bool, Block> + Send + Sync,
{
    async fn receive(&self, id: &str, choice: Vec<bool>) -> Result<Vec<Gf2_128>, mpz_ot::OTError> {
        let blocks = self.receive(id, &choice).await?;

        Ok(blocks.into_iter().map(|block| block.into()).collect())
    }
}
