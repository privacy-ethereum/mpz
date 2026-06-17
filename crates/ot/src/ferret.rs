//! An implementation of the [`Ferret`](https://eprint.iacr.org/2020/924.pdf) protocol.

mod receiver;
mod sender;

pub use receiver::{Receiver, ReceiverError};
pub use sender::{Sender, SenderError};

pub use mpz_ot_core::ferret::{FerretConfig, FerretConfigBuilder, FerretConfigBuilderError};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ideal::rcot::ideal_rcot;
    use mpz_core::lpn::LpnParameters;
    use rand::{Rng, SeedableRng, rngs::StdRng};

    #[tokio::test]
    async fn test_ferret() {
        use crate::test::test_rcot;

        let mut rng = StdRng::seed_from_u64(0);
        let delta = rng.random();

        let (cot_sender, cot_receiver) = ideal_rcot(rng.random(), delta);

        let mut builder = FerretConfig::builder();

        // Disable passthrough so a small count still exercises the protocol.
        builder.direct_passthrough(false);
        builder.param_selector(|_, _| LpnParameters {
            n: 9600,
            k: 1024,
            t: 600,
        });

        let config = builder.build().unwrap();

        let sender = Sender::new(config.clone(), rng.random(), cot_sender);
        let receiver = Receiver::new(config, rng.random(), cot_receiver);

        test_rcot(sender, receiver, 20_000, 2).await;
    }

    #[tokio::test]
    async fn test_ferret_direct_passthrough() {
        use crate::test::test_rcot;

        let mut rng = StdRng::seed_from_u64(0);
        let delta = rng.random();

        let (cot_sender, cot_receiver) = ideal_rcot(rng.random(), delta);

        // Default config: a small demand is served straight from the base COT.
        let config = FerretConfig::default();

        let sender = Sender::new(config.clone(), rng.random(), cot_sender);
        let receiver = Receiver::new(config, rng.random(), cot_receiver);

        // Multiple alloc -> consume rounds, each served directly from the base
        // COT (count stays below the bootstrap cost).
        test_rcot(sender, receiver, 1_000, 5).await;
    }
}
