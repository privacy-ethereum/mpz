//! Ideal functionality utilities.

use futures::channel::oneshot;
use std::{
    any::Any,
    collections::HashMap,
    sync::{Arc, Mutex, MutexGuard},
};

use crate::{Context, ThreadId};

type BoxAny = Box<dyn Any + Send + 'static>;

#[derive(Debug, Default)]
struct Buffer {
    alice: HashMap<ThreadId, (BoxAny, oneshot::Sender<BoxAny>)>,
    bob: HashMap<ThreadId, (BoxAny, oneshot::Sender<BoxAny>)>,
}

/// The ideal functionality from the perspective of Alice.
#[derive(Debug, Default)]
pub struct Alice<F> {
    f: Arc<Mutex<F>>,
    buffer: Arc<Mutex<Buffer>>,
}

impl<F> Clone for Alice<F> {
    fn clone(&self) -> Self {
        Self {
            f: self.f.clone(),
            buffer: self.buffer.clone(),
        }
    }
}

impl<F> Alice<F> {
    /// Returns a lock to the ideal functionality.
    pub fn lock(&self) -> MutexGuard<'_, F> {
        self.f.lock().unwrap()
    }

    /// Calls the ideal functionality.
    pub async fn call<Ctx, C, IA, IB, OA, OB>(&mut self, ctx: &mut Ctx, input: IA, call: C) -> OA
    where
        Ctx: Context,
        C: FnOnce(&mut F, IA, IB) -> (OA, OB),
        IA: Send + 'static,
        IB: Send + 'static,
        OA: Send + 'static,
        OB: Send + 'static,
    {
        let receiver = {
            let mut buffer = self.buffer.lock().unwrap();
            if let Some((input_bob, ret_bob)) = buffer.bob.remove(ctx.id()) {
                let input_bob = *input_bob
                    .downcast()
                    .expect("alice received correct input type for bob");

                let (output_alice, output_bob) =
                    call(&mut self.f.lock().unwrap(), input, input_bob);

                _ = ret_bob.send(Box::new(output_bob));

                return output_alice;
            }

            let (sender, receiver) = oneshot::channel();
            buffer
                .alice
                .insert(ctx.id().clone(), (Box::new(input), sender));
            receiver
        };

        let output_alice = receiver.await.expect("bob did not drop the channel");
        *output_alice
            .downcast()
            .expect("bob sent correct output type for alice")
    }
}

/// The ideal functionality from the perspective of Bob.
#[derive(Debug, Default)]
pub struct Bob<F> {
    f: Arc<Mutex<F>>,
    buffer: Arc<Mutex<Buffer>>,
}

impl<F> Clone for Bob<F> {
    fn clone(&self) -> Self {
        Self {
            f: self.f.clone(),
            buffer: self.buffer.clone(),
        }
    }
}

impl<F> Bob<F> {
    /// Returns a lock to the ideal functionality.
    pub fn lock(&self) -> MutexGuard<'_, F> {
        self.f.lock().unwrap()
    }

    /// Calls the ideal functionality.
    pub async fn call<Ctx, C, IA, IB, OA, OB>(&mut self, ctx: &mut Ctx, input: IB, call: C) -> OB
    where
        Ctx: Context,
        C: FnOnce(&mut F, IA, IB) -> (OA, OB),
        IA: Send + 'static,
        IB: Send + 'static,
        OA: Send + 'static,
        OB: Send + 'static,
    {
        let receiver = {
            let mut buffer = self.buffer.lock().unwrap();
            if let Some((input_alice, ret_alice)) = buffer.alice.remove(ctx.id()) {
                let input_alice = *input_alice
                    .downcast()
                    .expect("bob received correct input type for alice");

                let (output_alice, output_bob) =
                    call(&mut self.f.lock().unwrap(), input_alice, input);

                _ = ret_alice.send(Box::new(output_alice));

                return output_bob;
            }

            let (sender, receiver) = oneshot::channel();
            buffer
                .bob
                .insert(ctx.id().clone(), (Box::new(input), sender));
            receiver
        };

        let output_bob = receiver.await.expect("alice did not drop the channel");
        *output_bob
            .downcast()
            .expect("alice sent correct output type for bob")
    }
}

/// Creates an ideal functionality, returning the perspectives of Alice and Bob.
pub fn ideal_f2p<F>(f: F) -> (Alice<F>, Bob<F>) {
    let f = Arc::new(Mutex::new(f));
    let buffer = Arc::new(Mutex::new(Buffer::default()));

    (
        Alice {
            f: f.clone(),
            buffer: buffer.clone(),
        },
        Bob { f, buffer },
    )
}

#[cfg(test)]
mod test {
    use crate::executor::test_st_executor;

    use super::*;

    #[test]
    fn test_ideal() {
        let (mut alice, mut bob) = ideal_f2p(());
        let (mut ctx_a, mut ctx_b) = test_st_executor(8);

        let (output_a, output_b) = futures::executor::block_on(async {
            futures::join!(
                alice.call(&mut ctx_a, 1u8, |&mut (), a: u8, b: u8| (a + b, a + b)),
                bob.call(&mut ctx_b, 2u8, |&mut (), a: u8, b: u8| (a + b, a + b)),
            )
        });

        assert_eq!(output_a, 3);
        assert_eq!(output_b, 3);
    }

    #[test]
    #[should_panic]
    fn test_ideal_wrong_input_type() {
        let (mut alice, mut bob) = ideal_f2p(());
        let (mut ctx_a, mut ctx_b) = test_st_executor(8);

        futures::executor::block_on(async {
            futures::join!(
                alice.call(&mut ctx_a, 1u16, |&mut (), a: u16, b: u16| (a + b, a + b)),
                bob.call(&mut ctx_b, 2u8, |&mut (), a: u8, b: u8| (a + b, a + b)),
            )
        });
    }
}
