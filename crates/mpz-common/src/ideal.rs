//! Ideal functionality utilities.

use std::sync::Arc;
use tokio::sync::Barrier;

/// Creates a new call synchronizer between two parties.
pub fn call_sync() -> (CallSync, CallSync) {
    let barrier = Arc::new(Barrier::new(2));
    (
        CallSync {
            barrier: Arc::clone(&barrier),
        },
        CallSync { barrier },
    )
}

/// Synchronizes function calls between two parties.
#[derive(Debug)]
pub struct CallSync {
    barrier: Arc<Barrier>,
}

impl CallSync {
    /// Synchronizes a call.
    pub async fn call<F: FnMut() -> R, R>(&mut self, mut f: F) -> Option<R> {
        // Wait for both parties to call.
        let is_leader = self.barrier.wait().await.is_leader();

        let ret = if is_leader { Some(f()) } else { None };

        // Wait for the call to return.
        self.barrier.wait().await;

        ret
    }
}

#[cfg(test)]
mod test {
    use std::sync::Mutex;

    use super::*;

    #[tokio::test]
    async fn test_call_sync() {
        let x = Arc::new(Mutex::new(0));

        let (mut sync_0, mut sync_1) = call_sync();

        let add_one = || {
            *x.lock().unwrap() += 1;
        };

        futures::join!(sync_0.call(add_one.clone()), sync_1.call(add_one));

        assert_eq!(*x.lock().unwrap(), 1);
    }
}
