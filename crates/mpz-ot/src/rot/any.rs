//! Adapter for using any type as the message type in a ROT protocol.

mod receiver;
mod sender;

pub use receiver::AnyReceiver;
pub use sender::AnySender;

#[cfg(test)]
mod tests {
<<<<<<< HEAD
    use rand::{Rng, SeedableRng, distr::StandardUniform, prelude::Distribution, rngs::StdRng};
=======
    use rand::{distributions::Standard, prelude::Distribution, rngs::StdRng, Rng, SeedableRng};
>>>>>>> b81b562 (feat: lazy ot (#186))

    use super::*;
    use crate::{ideal::rot::ideal_rot, test::test_rot};

    #[derive(Clone, Copy, PartialEq)]
    struct Foo {
        foo: [u8; 32],
    }

<<<<<<< HEAD
    impl Distribution<Foo> for StandardUniform {
        fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> Foo {
            Foo { foo: rng.random() }
=======
    impl Distribution<Foo> for Standard {
        fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> Foo {
            Foo { foo: rng.gen() }
>>>>>>> b81b562 (feat: lazy ot (#186))
        }
    }

    #[tokio::test]
    async fn test_any_rot() {
        let mut rng = StdRng::seed_from_u64(0);
<<<<<<< HEAD
        let (sender, receiver) = ideal_rot(rng.random());
=======
        let (sender, receiver) = ideal_rot(rng.gen());
>>>>>>> b81b562 (feat: lazy ot (#186))
        test_rot::<_, _, Foo>(AnySender::new(sender), AnyReceiver::new(receiver), 8).await
    }
}
