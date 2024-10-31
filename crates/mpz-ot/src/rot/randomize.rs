//! Adapter to convert an RCOT protocol to ROT.

mod receiver;
mod sender;

pub use receiver::RandomizeRCOTReceiver;
pub use sender::RandomizeRCOTSender;

#[cfg(test)]
mod tests {
<<<<<<< HEAD
    use rand::{Rng, SeedableRng, rngs::StdRng};
=======
    use rand::{rngs::StdRng, Rng, SeedableRng};
>>>>>>> b81b562 (feat: lazy ot (#186))

    use crate::{ideal::rcot::ideal_rcot, test::test_rot};

    use super::*;

    #[tokio::test]
    async fn test_randomize_rcot() {
        let mut rng = StdRng::seed_from_u64(0);
<<<<<<< HEAD
        let (sender, receiver) = ideal_rcot(rng.random(), rng.random());
=======
        let (sender, receiver) = ideal_rcot(rng.gen(), rng.gen());
>>>>>>> b81b562 (feat: lazy ot (#186))
        test_rot(
            RandomizeRCOTSender::new(sender),
            RandomizeRCOTReceiver::new(receiver),
            8,
        )
        .await
    }
}
