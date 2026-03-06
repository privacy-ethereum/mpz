use std::sync::{Arc, Mutex};

use crate::{Context, ContextError, ThreadId, context::ErrorKind};

use super::pool::TaskFn;

/// A lightweight handle to a logical worker thread.
///
/// Each handle is assigned to a specific pool thread (via its sender) and
/// holds a context that is moved into tasks and returned when they complete.
pub(crate) struct Handle {
    id: ThreadId,
    ctx_slot: Arc<Mutex<Option<Context>>>,
    sender: async_channel::Sender<TaskFn>,
}

impl Handle {
    /// Creates a new handle with the given context and pool thread sender.
    pub(crate) fn new(id: ThreadId, ctx: Context, sender: async_channel::Sender<TaskFn>) -> Self {
        Self {
            id,
            ctx_slot: Arc::new(Mutex::new(Some(ctx))),
            sender,
        }
    }

    /// Takes the context from this handle.
    pub(crate) fn take_ctx(&self) -> Result<Context, ContextError> {
        self.ctx_slot.lock().unwrap().take().ok_or_else(|| {
            ContextError::new(
                ErrorKind::Thread,
                format!(
                    "context not available for worker {} (concurrent use?)",
                    &self.id
                ),
            )
        })
    }

    /// Returns the context to this handle after a task completes.
    pub(crate) fn put_ctx(&self, ctx: Context) {
        self.ctx_slot.lock().unwrap().replace(ctx);
    }

    /// Returns a reference to the sender for dispatching tasks.
    pub(crate) fn sender(&self) -> &async_channel::Sender<TaskFn> {
        &self.sender
    }
}

impl std::fmt::Debug for Handle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Handle").field("id", &self.id).finish()
    }
}
