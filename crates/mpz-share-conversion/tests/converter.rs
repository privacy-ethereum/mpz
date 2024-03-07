use std::marker::PhantomData;

use rstest::*;

use mpz_ot::ideal::{ideal_ot_shared_pair, IdealSharedOTReceiver, IdealSharedOTSender};
use mpz_share_conversion::{
    AdditiveToMultiplicative, ConverterReceiver, ConverterSender, Field, Gf2_128,
    MultiplicativeToAdditive, OTReceiveElement, OTSendElement, ReceiverConfig, SenderConfig,
    ShareConversionReveal, ShareConversionVerify, P256,
};
use utils_aio::duplex::MemoryDuplex;

use rand::SeedableRng;
use rand_chacha::ChaCha12Rng;

#[rstest]
#[case::gf2(PhantomData::<Gf2_128>)]
#[case::p256(PhantomData::<P256>)]
#[tokio::test]
async fn test_converter<T: Field>(#[case] _pd: PhantomData<T>)
where
    IdealSharedOTSender: OTSendElement<T>,
    IdealSharedOTReceiver: OTReceiveElement<T>,
{
    let mut rng = ChaCha12Rng::seed_from_u64(0);

    let (ot_sender, ot_receiver) = ideal_ot_shared_pair();
    let (sender_channel, receiver_channel) = MemoryDuplex::new();

    let mut sender = ConverterSender::<T, _>::new(
        SenderConfig::builder().id("test").record().build().unwrap(),
        ot_sender,
        Box::new(sender_channel),
    );

    let mut receiver = ConverterReceiver::<T, _>::new(
        ReceiverConfig::builder()
            .id("test")
            .record()
            .build()
            .unwrap(),
        ot_receiver,
        Box::new(receiver_channel),
    );

    let sender_handle = sender.handle().unwrap();
    let receiver_handle = receiver.handle().unwrap();

    let a = T::rand(&mut rng);
    let b = T::rand(&mut rng);

    let (x, y) = tokio::join!(
        async { sender_handle.to_multiplicative(vec![a]).await.unwrap()[0] },
        async { receiver_handle.to_multiplicative(vec![b]).await.unwrap()[0] }
    );

    assert_eq!(a + b, x * y);

    let (x, y) = tokio::join!(
        async { sender_handle.to_additive(vec![a]).await.unwrap()[0] },
        async { receiver_handle.to_additive(vec![b]).await.unwrap()[0] }
    );

    assert_eq!(a * b, x + y);

    tokio::try_join!(sender.reveal(), receiver.verify()).unwrap();
}
