//! Implementation of OLE with errors based on random OT.

mod receiver;
mod sender;

pub use receiver::OLEReceiver;
pub use sender::OLESender;

#[cfg(test)]
mod tests {
    use crate::{
        rot::{OLEReceiver, OLESender},
        OLEReceiver as _, OLESender as _,
    };
    use mpz_common::executor::test_st_executor;
    use mpz_core::{prg::Prg, Block};
    use mpz_fields::{p256::P256, UniformRand};
    use mpz_ot::ideal::rot::ideal_rot;
    use rand::SeedableRng;

    #[tokio::test]
    async fn test_ole() {
        let count = 12;
        let mut rng = Prg::from_seed(Block::ZERO);

        let (rot_sender, rot_receiver) = ideal_rot();

        let mut ole_sender = OLESender::<_, P256>::new(rot_sender);
        let mut ole_receiver = OLEReceiver::<_, P256>::new(rot_receiver);

        let a_k: Vec<P256> = (0..count).map(|_| P256::rand(&mut rng)).collect();
        let b_k: Vec<P256> = (0..count).map(|_| P256::rand(&mut rng)).collect();

        let (mut ctx_sender, mut ctx_receiver) = test_st_executor(10);

        tokio::try_join!(
            ole_sender.preprocess(&mut ctx_sender, count),
            ole_receiver.preprocess(&mut ctx_receiver, count)
        )
        .unwrap();

        let (x_k, y_k) = tokio::try_join!(
            ole_sender.send(&mut ctx_sender, a_k.clone()),
            ole_receiver.receive(&mut ctx_receiver, b_k.clone())
        )
        .unwrap();

        assert_eq!(x_k.len(), count);
        assert_eq!(y_k.len(), count);
        a_k.iter()
            .zip(b_k)
            .zip(x_k)
            .zip(y_k)
            .for_each(|(((&a, b), x), y)| assert_eq!(y, a * b + x));
    }
}
