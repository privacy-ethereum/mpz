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
    compat::FuturesAsyncReadCompatExt as _,
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

trait DuplexFrameLimited<T, U> {
    /// Sets a new maximum frame length and returns a [`WithFrameLimit`].
    ///
    /// # Arguments
    ///
    /// * `max_frame_len` - The new maximum frame length in bytes.
    fn with_max_frame_limit(&mut self, max_frame_len: usize) -> WithFrameLimit<'_, T>;
}

impl<T, U> DuplexFrameLimited<T, U> for Framed<TokioFramed<T, LengthDelimitedCodec>, U> {
    fn with_max_frame_limit(&mut self, max_frame_len: usize) -> WithFrameLimit<'_, T> {
        let old_frame_limit = self.inner().codec().max_frame_length();
        self.inner_mut()
            .codec_mut()
            .set_max_frame_length(max_frame_len);

        WithFrameLimit {
            old_frame_limit,
            framed: self.inner_mut(),
        }
    }
}

pin_project! {
    /// Wrapper around [`Framed`] to temporarily set a new maximum frame length.
    pub struct WithFrameLimit<'a, T> {
        old_frame_limit: usize,
        #[pin]
        framed: &'a mut TokioFramed<T, LengthDelimitedCodec>,
    }

    impl<'a, T> PinnedDrop for WithFrameLimit<'a, T> {
        fn drop(this: Pin<&mut Self>) {
            let frame_limit = this.old_frame_limit;
            this.project()
                .framed
                .codec_mut()
                .set_max_frame_length(frame_limit);
        }
    }
}

impl<T> futures::Stream for WithFrameLimit<'_, T>
where
    TokioFramed<T, LengthDelimitedCodec>:
        futures::Stream<Item = Result<BytesMut, std::io::Error>> + Unpin,
{
    type Item = Result<BytesMut, std::io::Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.project().framed.poll_next(cx)
    }
}

impl<T> futures::Sink<Bytes> for WithFrameLimit<'_, T>
where
    TokioFramed<T, LengthDelimitedCodec>: futures::Sink<Bytes, Error = std::io::Error> + Unpin,
{
    type Error = std::io::Error;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.project().framed.poll_ready(cx)
    }

    fn start_send(self: Pin<&mut Self>, item: Bytes) -> Result<(), Self::Error> {
        self.project().framed.start_send(item)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.project().framed.poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.project().framed.poll_close(cx)
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
