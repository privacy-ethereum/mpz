//! Adapter for using any type as the message type in a ROT protocol.

mod receiver;
mod sender;

pub use receiver::AnyReceiver;
pub use sender::AnySender;

#[cfg(test)]
mod tests {
    use rand::{distributions::Standard, prelude::Distribution, rngs::StdRng, Rng, SeedableRng};

    use super::*;
    use crate::{ideal::rot::ideal_rot, test::test_rot};

    #[derive(Clone, Copy, PartialEq)]
    struct Foo {
        foo: [u8; 32],
    }

    impl Distribution<Foo> for Standard {
        fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> Foo {
            Foo { foo: rng.gen() }
        }
    }

    #[tokio::test]
    async fn test_any_rot() {
        let mut rng = StdRng::seed_from_u64(0);
        let (sender, receiver) = ideal_rot(rng.gen());
        test_rot::<_, _, Foo>(AnySender::new(sender), AnyReceiver::new(receiver), 8).await
    }
}
