//! Ideal functionality utilities.

use futures::channel::oneshot;
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use crate::{Context, ThreadId};

/// A 2-party functionality.
pub trait F2P {
    /// The input type for Alice.
    type InputA: Send + Sync + Unpin + std::fmt::Debug + 'static;
    /// The input type for Bob.
    type InputB: Send + Sync + Unpin + std::fmt::Debug + 'static;
    /// The output type for Alice.
    type OutputA: Send + Sync + Unpin + std::fmt::Debug + 'static;
    /// The output type for Bob.
    type OutputB: Send + Sync + Unpin + std::fmt::Debug + 'static;

    /// Executes the functionality.
    fn execute(
        &mut self,
        input_a: Self::InputA,
        input_b: Self::InputB,
    ) -> (Self::OutputA, Self::OutputB);
}

#[derive(Debug)]
struct Buffer<F: F2P> {
    alice: HashMap<ThreadId, (F::InputA, oneshot::Sender<F::OutputA>)>,
    bob: HashMap<ThreadId, (F::InputB, oneshot::Sender<F::OutputB>)>,
}

/// The ideal functionality from the perspective of Alice.
#[derive(Debug)]
pub struct Alice<F: F2P> {
    f: Arc<Mutex<F>>,
    buffer: Arc<Mutex<Buffer<F>>>,
}

impl<F: F2P> Clone for Alice<F> {
    fn clone(&self) -> Self {
        Self {
            f: self.f.clone(),
            buffer: self.buffer.clone(),
        }
    }
}

impl<F: F2P> Alice<F> {
    /// Executes the functionality.
    pub async fn execute<Ctx: Context>(&mut self, ctx: &mut Ctx, input: F::InputA) -> F::OutputA {
        // We have to scope this because rustc is dumb and doesn't understand that the lock is
        // dropped before the await.
        let receiver = {
            let mut buffer = self.buffer.lock().unwrap();
            if let Some((input_bob, ret_bob)) = buffer.bob.remove(ctx.id()) {
                let (output_alice, output_bob) = self.f.lock().unwrap().execute(input, input_bob);
                _ = ret_bob.send(output_bob);

                return output_alice;
            }

            let (sender, receiver) = oneshot::channel();
            buffer.alice.insert(ctx.id().clone(), (input, sender));

            receiver
        };

        receiver.await.unwrap()
    }
}

/// The ideal functionality from the perspective of Bob.
#[derive(Debug)]
pub struct Bob<F: F2P> {
    f: Arc<Mutex<F>>,
    buffer: Arc<Mutex<Buffer<F>>>,
}

impl<F: F2P> Clone for Bob<F> {
    fn clone(&self) -> Self {
        Self {
            f: self.f.clone(),
            buffer: self.buffer.clone(),
        }
    }
}

impl<F: F2P> Bob<F> {
    /// Executes the functionality.
    pub async fn execute<Ctx: Context>(&mut self, ctx: &mut Ctx, input: F::InputB) -> F::OutputB {
        // We have to scope this because rustc is dumb and doesn't understand that the lock is
        // dropped before the await.
        let receiver = {
            let mut buffer = self.buffer.lock().unwrap();
            if let Some((input_alice, ret_alice)) = buffer.alice.remove(ctx.id()) {
                let (output_alice, output_bob) = self.f.lock().unwrap().execute(input_alice, input);
                _ = ret_alice.send(output_alice);

                return output_bob;
            }

            let (sender, receiver) = oneshot::channel();
            buffer.bob.insert(ctx.id().clone(), (input, sender));

            receiver
        };

        receiver.await.unwrap()
    }
}

/// Creates an ideal 2-party functionality.
pub fn ideal_f2p<F: F2P>(f: F) -> (Alice<F>, Bob<F>) {
    let f = Arc::new(Mutex::new(f));
    let buffer = Arc::new(Mutex::new(Buffer {
        alice: HashMap::new(),
        bob: HashMap::new(),
    }));

    (
        Alice {
            f: f.clone(),
            buffer: buffer.clone(),
        },
        Bob { f, buffer },
    )
}

#[cfg(test)]
mod tests {
    use crate::executor::test_st_executor;

    use super::*;

    struct TestF;

    impl F2P for TestF {
        type InputA = u8;
        type InputB = u8;
        type OutputA = u8;
        type OutputB = u8;

        fn execute(
            &mut self,
            input_a: Self::InputA,
            input_b: Self::InputB,
        ) -> (Self::OutputA, Self::OutputB) {
            (input_a + input_b, input_a + input_b)
        }
    }

    #[test]
    fn test_ideal() {
        let (mut alice, mut bob) = ideal_f2p(TestF);
        let (mut ctx_a, mut ctx_b) = test_st_executor(8);

        let (output_alice, output_bob) = futures::executor::block_on(async {
            futures::join!(alice.execute(&mut ctx_a, 1), bob.execute(&mut ctx_b, 2))
        });

        assert_eq!(output_alice, 3);
        assert_eq!(output_bob, 3);
    }
}
