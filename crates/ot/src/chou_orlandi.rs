//! [`CO15`](https://eprint.iacr.org/2015/267.pdf) Chou-Orlandi oblivious transfer protocol.

mod receiver;
mod sender;

pub use receiver::Receiver;
pub use sender::{Sender, SenderError};

#[cfg(test)]
mod tests {
    use crate::test::test_ot;

    use super::*;

    #[tokio::test]
    async fn test_chou_orlandi() {
        test_ot(Sender::new(), Receiver::new(), 8).await;
    }
}
