use std::{future::Future, pin::Pin};

use uid_mux::UidMux;

use crate::{io::Io, ThreadId};

pub(crate) trait Mux {
    /// Opens a new I/O channel for the given thread.
    fn open(
        &self,
        id: ThreadId,
    ) -> Pin<Box<dyn Future<Output = Result<Io, std::io::Error>> + Send>>;
}

impl<T> Mux for T
where
    T: UidMux<ThreadId> + Clone + Send + Sync + 'static,
    <T as UidMux<ThreadId>>::Error: std::error::Error + Send + Sync + 'static,
{
    fn open(
        &self,
        id: ThreadId,
    ) -> Pin<Box<dyn Future<Output = Result<Io, std::io::Error>> + Send>> {
        let mux = self.clone();
        Box::pin(async move {
            let io = mux
                .open(&id)
                .await
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

            Ok(Io::from_io(io))
        })
    }
}

#[cfg(any(test, feature = "test-utils"))]
mod test_utils {
    use super::*;
    use uid_mux::{test_utils::TestFramedMux, FramedUidMux};

    impl Mux for TestFramedMux {
        fn open(
            &self,
            id: ThreadId,
        ) -> Pin<Box<dyn Future<Output = Result<Io, std::io::Error>> + Send>> {
            let mux = self.clone();
            Box::pin(async move {
                let io = mux
                    .open_framed(&id)
                    .await
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

                Ok(Io::from_channel(io))
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uid_mux::yamux::YamuxCtrl;

    #[test]
    fn test_yamux_is_mux() {
        fn assert_mux<T: Mux>() {}
        assert_mux::<YamuxCtrl>();
    }
}
