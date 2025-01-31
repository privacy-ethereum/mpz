use async_trait::async_trait;

use crate::Context;

/// A task that requires a context to run.
#[async_trait]
pub trait Task {
    /// Output of the task.
    type Output: Send + 'static;

    /// Runs the task to completion.
    async fn run(self, ctx: &mut Context) -> Self::Output;
}
