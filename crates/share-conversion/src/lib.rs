//! This crate provides additive-to-multiplicative (A2M) and
//! multiplicative-to-additive (M2A) share conversion protocols,
//! both with semi-honest security.

#![deny(missing_docs, unreachable_pub, unused_must_use)]
#![deny(unsafe_code)]
#![deny(clippy::all)]

#[cfg(any(test, feature = "test-utils"))]
pub mod ideal;
mod receiver;
mod sender;
#[cfg(test)]
mod test;

pub use mpz_share_conversion_core::{
    A2MOutput, AdditiveToMultiplicative, M2AOutput, MultiplicativeToAdditive, ShareConvert,
};
pub use receiver::{ReceiverError, ShareConversionReceiver};
pub use sender::{SenderError, ShareConversionSender};

#[cfg(test)]
mod tests {
    use super::*;
    use mpz_fields::{gf2_128::Gf2_128, p256::P256};
    use mpz_ole::ideal::ideal_role;
    use test::test_share_convert;

    #[tokio::test]
    async fn test_share_convert_p256() {
        let (role_sender, role_receiver) = ideal_role();

        let sender = ShareConversionSender::<_, P256>::new(role_sender);
        let receiver = ShareConversionReceiver::<_, P256>::new(role_receiver);

        test_share_convert(sender, receiver, 8).await;
    }

    #[tokio::test]
    async fn test_share_convert_gf2_128() {
        let (role_sender, role_receiver) = ideal_role();

        let sender = ShareConversionSender::<_, Gf2_128>::new(role_sender);
        let receiver = ShareConversionReceiver::<_, Gf2_128>::new(role_receiver);

        test_share_convert(sender, receiver, 8).await;
    }
}
