use std::future::Future;

use crossbeam_channel::{unbounded, Receiver, Sender};
use futures::{channel::oneshot, TryFutureExt};

use crate::{context::ErrorKind, Context, ContextError, ThreadId};

type Job = Box<dyn FnOnce(&mut Context) + Send>;

pub(crate) struct Handle {
    id: ThreadId,
    sender: Sender<Job>,
}

impl Handle {
    /// Sends a job to the worker.
    pub(crate) fn send<F>(&self, job: F) -> Result<(), ContextError>
    where
        F: FnOnce(&mut Context) + Send + 'static,
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
        F: FnOnce(&mut Context) -> R + Send + 'static,
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

impl std::fmt::Debug for Handle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Handle").field("id", &self.id).finish()
    }
}

pub(crate) struct Worker {
    ctx: Context,
    queue: Receiver<Job>,
}

impl Worker {
    pub(crate) fn new(id: ThreadId, ctx: Context) -> (Self, Handle) {
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
