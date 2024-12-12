use std::{
    collections::HashMap,
    pin::Pin,
    sync::{Arc, Mutex as StdMutex},
    task::{ready, Context as StdContext, Poll, Waker},
};

use futures::{Future, FutureExt, TryFutureExt};
use serio::{stream::IoStreamExt, IoDuplex, SinkExt};
use tokio::sync::Mutex;

use crate::sync::{SyncError, Ticket};

/// An async version of [`Syncer`](crate::sync::Syncer).
#[derive(Debug, Clone)]
pub struct AsyncSyncer(SyncerInner);

impl AsyncSyncer {
    /// Creates a new leader.
    pub fn new_leader() -> Self {
        Self(SyncerInner::Leader(Leader::default()))
    }

    /// Creates a new follower.
    pub fn new_follower() -> Self {
        Self(SyncerInner::Follower(Follower::default()))
    }

    /// Synchronizes the order of execution across logical threads.
    ///
    /// # Arguments
    ///
    /// * `io` - The I/O channel of the logical thread.
    /// * `fut` - The future to await.
    pub async fn sync<Io: IoDuplex + Unpin, Fut>(
        &self,
        io: &mut Io,
        fut: Fut,
    ) -> Result<Fut::Output, SyncError>
    where
        Fut: Future,
    {
        match &self.0 {
            SyncerInner::Leader(leader) => leader.sync(io, fut).await,
            SyncerInner::Follower(follower) => follower.sync(io, fut).await,
        }
    }
}

#[derive(Debug, Clone)]
enum SyncerInner {
    Leader(Leader),
    Follower(Follower),
}

#[derive(Debug, Default, Clone)]
struct Leader {
    tick: Arc<Mutex<Ticket>>,
}

impl Leader {
    async fn sync<Io: IoDuplex + Unpin, Fut>(
        &self,
        io: &mut Io,
        fut: Fut,
    ) -> Result<Fut::Output, SyncError>
    where
        Fut: Future,
    {
        let mut tick_lock = self.tick.lock().await;
        let (_, output) = futures::try_join!(
            io.send(tick_lock.increment_in_place())
                .map_err(SyncError::from),
            fut.map(Ok),
        )?;
        drop(tick_lock);

        Ok(output)
    }
}

#[derive(Debug, Default, Clone)]
struct Follower {
    queue: Arc<StdMutex<Queue>>,
}

impl Follower {
    async fn sync<Io: IoDuplex + Unpin, Fut>(
        &self,
        io: &mut Io,
        fut: Fut,
    ) -> Result<Fut::Output, SyncError>
    where
        Fut: Future,
    {
        let tick = io.expect_next().await?;
        Ok(Wait::new(&self.queue, tick, fut).await)
    }
}

#[derive(Debug, Default)]
struct Queue {
    // The current ticket.
    tick: Ticket,
    // Tasks waiting for their ticket to be accepted.
    waiting: HashMap<Ticket, Waker>,
}

impl Queue {
    // Wakes up the next waiting task.
    fn wake_next(&mut self) {
        if let Some(waker) = self.waiting.remove(&self.tick) {
            waker.wake();
        }
    }
}

pin_project_lite::pin_project! {
    #[derive(Debug)]
    #[must_use = "futures do nothing unless you `.await` or poll them"]
    struct Wait<'a, Fut> {
        queue: &'a StdMutex<Queue>,
        tick: Ticket,
        #[pin]
        fut: Fut,
    }
}

impl<'a, Fut> Wait<'a, Fut> {
    fn new(queue: &'a StdMutex<Queue>, tick: Ticket, fut: Fut) -> Self {
        Self { queue, tick, fut }
    }
}

impl<Fut> Future for Wait<'_, Fut>
where
    Fut: Future,
{
    type Output = Fut::Output;

    fn poll(self: Pin<&mut Self>, cx: &mut StdContext<'_>) -> Poll<Self::Output> {
        let mut queue_lock = self.queue.lock().unwrap();
        if queue_lock.tick == self.tick {
            let this = self.project();
            let output = ready!(this.fut.poll(cx));
            queue_lock.tick.increment_in_place();
            queue_lock.wake_next();
            Poll::Ready(output)
        } else {
            queue_lock.waiting.insert(self.tick, cx.waker().clone());
            Poll::Pending
        }
    }
}

#[cfg(test)]
mod tests {
    use futures::{executor::block_on, poll};
    use serio::channel::duplex;

    use super::*;

    #[test]
    fn test_syncer() {
        let (mut io_0a, mut io_0b) = duplex(1);
        let (mut io_1a, mut io_1b) = duplex(1);
        let (mut io_2a, mut io_2b) = duplex(1);

        let syncer_a = AsyncSyncer::new_leader();
        let syncer_b = AsyncSyncer::new_follower();

        let log_a = Arc::new(Mutex::new(Vec::new()));
        let log_b = Arc::new(Mutex::new(Vec::new()));

        block_on(async {
            syncer_a
                .sync(&mut io_0a, async {
                    let mut log = log_a.lock().await;
                    log.push(0);
                })
                .await
                .unwrap();
            syncer_a
                .sync(&mut io_1a, async {
                    let mut log = log_a.lock().await;
                    log.push(1);
                })
                .await
                .unwrap();
            syncer_a
                .sync(&mut io_2a, async {
                    let mut log = log_a.lock().await;
                    log.push(2);
                })
                .await
                .unwrap();
        });

        let mut fut_a = Box::pin(syncer_b.sync(&mut io_2b, async {
            let mut log = log_b.lock().await;
            log.push(2);
        }));

        let mut fut_b = Box::pin(syncer_b.sync(&mut io_0b, async {
            let mut log = log_b.lock().await;
            log.push(0);
        }));

        let mut fut_c = Box::pin(syncer_b.sync(&mut io_1b, async {
            let mut log = log_b.lock().await;
            log.push(1);
        }));

        block_on(async move {
            // Poll out of order.
            assert!(poll!(&mut fut_a).is_pending());
            assert!(poll!(&mut fut_c).is_pending());
            assert!(poll!(&mut fut_b).is_ready());
            assert!(poll!(&mut fut_c).is_ready());
            assert!(poll!(&mut fut_a).is_ready());
        });

        let log_a = Arc::into_inner(log_a).unwrap().into_inner();
        let log_b = Arc::into_inner(log_b).unwrap().into_inner();

        assert_eq!(log_a, log_b);
    }

    #[test]
    fn test_syncer_is_send() {
        let (mut io, _) = duplex(1);
        let syncer = AsyncSyncer::new_leader();

        fn is_send<T: Send>(_: T) {}

        is_send(syncer.sync(&mut io, async {}));
    }
}
