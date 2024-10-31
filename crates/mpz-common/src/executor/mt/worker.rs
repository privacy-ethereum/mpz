use std::future::Future;

use crossbeam_channel::{unbounded, Receiver, Sender};
use futures::{channel::oneshot, TryFutureExt};

use crate::{context::ErrorKind, ContextError, ThreadId};

type Job<Ctx> = Box<dyn FnOnce(&mut Ctx) + Send>;

pub(crate) struct Handle<Ctx> {
    id: ThreadId,
    sender: Sender<Job<Ctx>>,
}

impl<Ctx> Handle<Ctx> {
    /// Sends a job to the worker.
    pub(crate) fn send<F>(&self, job: F) -> Result<(), ContextError>
    where
        F: FnOnce(&mut Ctx) + Send + 'static,
    {
        self.sender.send(Box::new(job)).map_err(|_| {
            ContextError::new(
                ErrorKind::Thread,
                format!("failed to send job to worker {}", &self.id),
            )
        })
    }

    /// Sends a job to the worker and returns a future that resolves to the
    /// result of the job.
    pub(crate) fn send_with_return<F, R>(
        &self,
        job: F,
    ) -> Result<impl Future<Output = Result<R, ContextError>>, ContextError>
    where
        F: FnOnce(&mut Ctx) -> R + Send + 'static,
        R: Send + 'static,
    {
        let (sender, receive) = oneshot::channel();

        self.send(move |ctx| {
            let result = job(ctx);
            let _ = sender.send(result);
        })?;

        let id = self.id.clone();
        Ok(receive.map_err(move |_| {
            ContextError::new(
                ErrorKind::Thread,
                format!("failed to receive result from worker {id}"),
            )
        }))
    }
}

impl<Ctx> std::fmt::Debug for Handle<Ctx> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Handle").field("id", &self.id).finish()
    }
}

pub(crate) struct Worker<Ctx> {
    ctx: Ctx,
    queue: Receiver<Job<Ctx>>,
}

impl<Ctx> Worker<Ctx> {
    pub(crate) fn new(id: ThreadId, ctx: Ctx) -> (Self, Handle<Ctx>) {
        let (sender, receiver) = unbounded();
        let worker = Self {
            ctx,
            queue: receiver,
        };
        let handle = Handle { id, sender };
        (worker, handle)
    }

    pub(crate) fn run(mut self) {
        while let Ok(job) = self.queue.recv() {
            job(&mut self.ctx);
        }
    }
}
