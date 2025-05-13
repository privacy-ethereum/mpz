//! I/O types.

use std::{
    pin::Pin,
    task::{Context, Poll},
};

use bytes::{Bytes, BytesMut};
use futures::{AsyncRead, AsyncWrite};
use pin_project_lite::pin_project;
use serio::{Framed, Sink, Stream, channel::MemoryDuplex, codec::Bincode};
use tokio_util::{
    codec::{Framed as TokioFramed, LengthDelimitedCodec},
    compat::{Compat, FuturesAsyncReadCompatExt as _},
};

trait Duplex:
    futures::Stream<Item = Result<BytesMut, std::io::Error>>
    + futures::Sink<Bytes, Error = std::io::Error>
{
}

impl<T> Duplex for T where
    T: futures::Stream<Item = Result<BytesMut, std::io::Error>>
        + futures::Sink<Bytes, Error = std::io::Error>
{
}

trait FrameLimit {
    /// Sets a new maximum frame length.
    ///
    /// # Arguments
    ///
    /// * `frame_limit` - The new maximum frame length in bytes.
    fn set_frame_limit(&mut self, frame_limit: usize);

    /// Returns the current frame limit, if available.
    fn frame_limit(&self) -> Option<usize>;
}

impl<T> FrameLimit for TokioFramed<Compat<T>, LengthDelimitedCodec> {
    fn set_frame_limit(&mut self, frame_limit: usize) {
        self.codec_mut().set_max_frame_length(frame_limit);
    }

    fn frame_limit(&self) -> Option<usize> {
        let limit = self.codec().max_frame_length();
        Some(limit)
    }
}

trait DuplexFrameLimited: Duplex + FrameLimit {}

impl<T> DuplexFrameLimited for T where T: Duplex + FrameLimit {}

pin_project! {
    /// Wrapper around [`Io`] to temporarily set a frame limit.
    pub struct WithLimit<'a> {
        old_limit: Option<usize>,
        #[pin]
        io: &'a mut Io,
    }

    impl<'a> PinnedDrop for WithLimit<'a> {
        fn drop(mut this: Pin<&mut Self>) {
            let Some(old_limit) = this.old_limit else {
                return;
            };
            let Inner::Transport { ref mut framed } = this.io.inner else {
                return;
            };
            framed.inner_mut().set_frame_limit(old_limit);
        }
    }
}

impl WithLimit<'_> {
    #[cfg(test)]
    fn frame_limit(&self) -> Option<usize> {
        self.io.frame_limit()
    }
}

impl Stream for WithLimit<'_> {
    type Error = std::io::Error;

    fn poll_next<Item: serio::Deserialize>(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Item, Self::Error>>> {
        self.project().io.poll_next(cx)
    }
}

impl Sink for WithLimit<'_> {
    type Error = std::io::Error;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.project().io.poll_ready(cx)
    }

    fn start_send<Item: serio::Serialize>(
        self: Pin<&mut Self>,
        item: Item,
    ) -> Result<(), Self::Error> {
        self.project().io.start_send(item)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.project().io.poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.project().io.poll_close(cx)
    }
}

pin_project! {
    /// I/O channel.
    #[derive(Debug)]
    pub struct Io {
        #[pin]
        inner: Inner,
    }
}

impl Io {
    #[doc(hidden)]
    pub fn from_io<Io: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static>(io: Io) -> Self {
        let framed = Box::new(LengthDelimitedCodec::builder().new_framed(io.compat()));

        Self {
            inner: Inner::Transport {
                framed: Framed::new(framed, Bincode),
            },
        }
    }

    /// Adjusts the frame limit temporarily and returns a [`WithLimit`].
    ///
    /// # Arguments
    ///
    /// * `frame_limit` - The new maximum frame length in bytes.
    pub fn with_limit(&mut self, frame_limit: usize) -> WithLimit<'_> {
        let old_limit = match &self.inner {
            Inner::Transport { framed } => framed.inner().frame_limit(),
            Inner::Memory { channel: _ } => None,
        };

        if let Inner::Transport { ref mut framed } = self.inner {
            framed.inner_mut().set_frame_limit(frame_limit);
        };

        WithLimit {
            old_limit,
            io: self,
        }
    }

    #[cfg(any(test, feature = "test-utils"))]
    pub(crate) fn from_channel(duplex: MemoryDuplex) -> Self {
        Self {
            inner: Inner::Memory { channel: duplex },
        }
    }

    #[cfg(test)]
    fn frame_limit(&self) -> Option<usize> {
        match &self.inner {
            Inner::Transport { framed } => framed.inner().frame_limit(),
            Inner::Memory { channel: _ } => None,
        }
    }
}

pin_project! {
    #[project = InnerProj]
    enum Inner {
        /// I/O over a framed bytes transport.
        Transport { #[pin] framed: Framed<Box<dyn DuplexFrameLimited + Send + Sync + Unpin>, Bincode> },
        /// I/O over a memory channel.
        Memory { #[pin] channel: MemoryDuplex }
    }
}

impl std::fmt::Debug for Inner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Transport { .. } => f.debug_struct("Transport").finish_non_exhaustive(),
            Self::Memory { .. } => f.debug_struct("Memory").finish_non_exhaustive(),
        }
    }
}

impl Sink for Io {
    type Error = std::io::Error;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        match self.project().inner.project() {
            InnerProj::Transport { framed } => framed.poll_ready(cx),
            InnerProj::Memory { channel } => channel.poll_ready(cx),
        }
    }

    fn start_send<Item: serio::Serialize>(
        self: Pin<&mut Self>,
        item: Item,
    ) -> Result<(), Self::Error> {
        match self.project().inner.project() {
            InnerProj::Transport { framed } => framed.start_send(item),
            InnerProj::Memory { channel } => channel.start_send(item),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        match self.project().inner.project() {
            InnerProj::Transport { framed } => framed.poll_flush(cx),
            InnerProj::Memory { channel } => channel.poll_flush(cx),
        }
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        match self.project().inner.project() {
            InnerProj::Transport { framed } => framed.poll_close(cx),
            InnerProj::Memory { channel } => channel.poll_close(cx),
        }
    }
}

impl Stream for Io {
    type Error = std::io::Error;

    fn poll_next<Item: serio::Deserialize>(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Item, Self::Error>>> {
        match self.project().inner.project() {
            InnerProj::Transport { framed } => framed.poll_next(cx),
            InnerProj::Memory { channel } => channel.poll_next(cx),
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        match &self.inner {
            Inner::Transport { framed } => framed.size_hint(),
            Inner::Memory { channel } => channel.size_hint(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Io;
    use tokio_util::compat::TokioAsyncReadCompatExt;

    #[test]
    fn test_frame_limit() {
        let (a, b) = tokio::io::duplex(1024);

        let mut a = Io::from_io(a.compat());
        let mut b = Io::from_io(b.compat());

        let old_limit = a.frame_limit().unwrap();
        let new_limit = 2 * old_limit;

        {
            let a = a.with_limit(new_limit);
            let b = b.with_limit(new_limit);

            assert_eq!(a.frame_limit().unwrap(), new_limit);
            assert_eq!(b.frame_limit().unwrap(), new_limit);
        }

        assert_eq!(a.frame_limit().unwrap(), old_limit);
        assert_eq!(b.frame_limit().unwrap(), old_limit);
    }
}
