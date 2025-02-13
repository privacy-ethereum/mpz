//! An implementation of the [`Ferret`](https://eprint.iacr.org/2020/924.pdf) protocol.

mod receiver;
mod sender;

pub use receiver::{Receiver, ReceiverError};
pub use sender::{Sender, SenderError};

pub use mpz_core::lpn::LpnType;
pub use mpz_ot_core::ferret::{FerretConfig, FerretConfigBuilder, FerretConfigBuilderError};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ideal::rcot::ideal_rcot;
    use mpz_core::lpn::LpnParameters;
    use rand::{rngs::StdRng, Rng, SeedableRng};
    use rstest::*;

    #[rstest]
    #[case::uniform(LpnType::Uniform)]
    #[case::regular(LpnType::Regular)]
    #[tokio::test]
    async fn test_ferret(#[case] lpn_type: LpnType) {
        use crate::test::test_rcot;

        let mut rng = StdRng::seed_from_u64(0);
        let delta = rng.gen();

        let (cot_sender, cot_receiver) = ideal_rcot(rng.gen(), delta);

        let mut builder = FerretConfig::builder();

        builder.lpn_type(lpn_type);
        builder.param_selector(|_, _, _| LpnParameters {
            n: 9600,
            k: 1220,
            t: 600,
        });

        let config = builder.build().unwrap();

        let sender = Sender::new(config.clone(), rng.gen(), cot_sender);
        let receiver = Receiver::new(config, rng.gen(), cot_receiver);

        test_rcot(sender, receiver, 20_000, 2).await;
    }
}
