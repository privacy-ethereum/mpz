//! CPU backend shim.

use cfg_if::cfg_if;

cfg_if! {
    if #[cfg(feature = "force-st")] {
        pub use st::SingleThreadedBackend as CpuBackend;
    } else if #[cfg(feature = "rayon")] {
        pub use rayon_backend::RayonBackend as CpuBackend;
    } else {
        pub use st::SingleThreadedBackend as CpuBackend;
    }
}

#[cfg(any(feature = "force-st", not(feature = "rayon")))]
mod st {
    use futures::Future;

    /// A single-threaded CPU backend.
    #[derive(Debug)]
    pub struct SingleThreadedBackend;

    impl SingleThreadedBackend {
        /// Executes a future on the CPU backend.
        #[inline]
        pub fn blocking_async<F>(fut: F) -> impl Future<Output = F::Output> + Send
        where
            F: Future + Send + 'static,
            F::Output: Send,
        {
            fut
        }

        /// Executes a closure on the CPU backend.
        #[inline]
        pub async fn blocking<F, R>(f: F) -> R
        where
            F: FnOnce() -> R + Send + 'static,
            R: Send + 'static,
        {
            f()
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use pollster::block_on;

        #[test]
        fn test_st_backend_blocking() {
            let output = block_on(SingleThreadedBackend::blocking(|| 42));
            assert_eq!(output, 42);
        }

        #[test]
        fn test_st_backend_blocking_async() {
            let output = block_on(SingleThreadedBackend::blocking_async(async { 42 }));
            assert_eq!(output, 42);
        }
    }
}

#[cfg(all(feature = "rayon", not(feature = "force-st")))]
mod rayon_backend {
    use futures::{channel::oneshot, Future};
    use pollster::block_on;

    /// A Rayon CPU backend.
    #[derive(Debug)]
    pub struct RayonBackend;

    impl RayonBackend {
        /// Executes a future on the CPU backend.
        pub fn blocking_async<F>(fut: F) -> impl Future<Output = F::Output> + Send
        where
            F: Future + Send + 'static,
            F::Output: Send,
        {
            async move {
                let (sender, receiver) = oneshot::channel();
                rayon::spawn(move || {
                    let output = block_on(fut);
                    _ = sender.send(output);
                });
                receiver.await.expect("worker thread does not drop channel")
            }
        }

        /// Executes a closure on the CPU backend.
        pub async fn blocking<F, R>(f: F) -> R
        where
            F: FnOnce() -> R + Send + 'static,
            R: Send + 'static,
        {
            let (sender, receiver) = oneshot::channel();
            rayon::spawn(move || {
                _ = sender.send(f());
            });
            receiver.await.expect("worker thread does not drop channel")
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn test_rayon_backend_blocking() {
            let output = block_on(RayonBackend::blocking(|| 42));
            assert_eq!(output, 42);
        }

        #[test]
        fn test_rayon_backend_blocking_async() {
            let output = block_on(RayonBackend::blocking_async(async { 42 }));
            assert_eq!(output, 42);
        }
    }
}
