mod receiver;
mod sender;

pub use receiver::{DerandCOTReceiver, DerandCOTReceiverError};
pub use sender::{DerandCOTSender, DerandCOTSenderError};

#[cfg(test)]
mod tests {

    #[tokio::test]
    async fn test_derandomize_cot() {
        todo!()
    }
}
