//! I/O types.

use std::{
    pin::Pin,
    task::{Context, Poll},
};

use bytes::{Bytes, BytesMut};
use futures::{AsyncRead, AsyncWrite};
use pin_project_lite::pin_project;
use serio::{channel::MemoryDuplex, codec::Bincode, Framed, Sink, Stream};
use tokio_util::{codec::LengthDelimitedCodec, compat::FuturesAsyncReadCompatExt as _};

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

    #[cfg(any(test, feature = "test-utils"))]
    pub(crate) fn from_channel(duplex: MemoryDuplex) -> Self {
        Self {
            inner: Inner::Memory { channel: duplex },
        }
    }
}

pin_project! {
    #[project = InnerProj]
    enum Inner {
        /// I/O over a framed bytes transport.
        Transport { #[pin] framed: Framed<Box<dyn Duplex + Send + Sync + Unpin>, Bincode> },
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
