//! Future types.

use std::{
    future::Future,
    mem,
    pin::Pin,
    task::{ready, Context, Poll},
};

use futures::{channel::oneshot, FutureExt};
use pin_project_lite::pin_project;

/// Creates a new output future.
pub fn new_output<T>() -> (Sender<T>, MaybeDone<T>) {
    let (send, recv) = oneshot::channel();
    (Sender { send }, MaybeDone { recv })
}

/// A future output value.
///
/// This trait extends [`std::future::Future`] for values which can be received
/// outside of a task context.
pub trait Output: Future<Output = Result<Self::Ok, Canceled>> {
    /// Success type.
    type Ok;

    /// Attempts to receive the output outside of a task context, returning
    /// `None` if it is not ready.
    fn try_recv(&mut self) -> Result<Option<Self::Ok>, Canceled>;
}

/// An extension trait for [`Output`].
pub trait OutputExt: Output {
    /// Maps the output value to a different type.
    fn map<F, O>(self, f: F) -> Map<Self, F>
    where
        Self: Sized,
        F: FnOnce(Self::Ok) -> O,
    {
        Map::new(self, f)
    }
}

impl<T> OutputExt for T where T: Output {}

/// Output canceled error.
#[derive(Debug, thiserror::Error)]
#[error("output canceled")]
pub struct Canceled {
    _private: (),
}

/// Sender of an output value.
#[derive(Debug)]
pub struct Sender<T> {
    send: oneshot::Sender<T>,
}

impl<T> Sender<T> {
    /// Sends an output value.
    pub fn send(self, value: T) {
        let _ = self.send.send(value);
    }
}

/// An output value that may be ready.
#[derive(Debug)]
#[must_use = "futures do nothing unless you `.await` or poll them"]
pub struct MaybeDone<T> {
    recv: oneshot::Receiver<T>,
}

impl<T> Output for MaybeDone<T> {
    type Ok = T;

    fn try_recv(&mut self) -> Result<Option<Self::Ok>, Canceled> {
        match self.recv.try_recv() {
            Ok(Some(value)) => Ok(Some(value)),
            Ok(None) => Ok(None),
            Err(oneshot::Canceled) => Err(Canceled { _private: () }),
        }
    }
}

impl<T> Future for MaybeDone<T> {
    type Output = Result<T, Canceled>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.recv
            .poll_unpin(cx)
            .map_err(|_| Canceled { _private: () })
    }
}

pin_project! {
    /// Maps an output value to a different type.
    ///
    /// Returned by [`OutputExt::map`].
    #[derive(Debug)]
    pub struct Map<I, F> {
        #[pin]
        inner: MapInner<I, F>,
    }
}

impl<I, F> Map<I, F> {
    fn new(inner: I, f: F) -> Self {
        Self {
            inner: MapInner::Incomplete { inner, f },
        }
    }
}

impl<I, F, O> Output for Map<I, F>
where
    I: Output,
    F: FnOnce(I::Ok) -> O,
{
    type Ok = O;

    fn try_recv(&mut self) -> Result<Option<Self::Ok>, Canceled> {
        self.inner.try_recv()
    }
}

impl<I, F, O> Future for Map<I, F>
where
    I: Output,
    F: FnOnce(I::Ok) -> O,
{
    type Output = Result<O, Canceled>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.project().inner.poll(cx)
    }
}

pin_project! {
    /// Maps an output value to a different type.
    ///
    /// Returned by [`OutputExt::map`].
    #[derive(Debug)]
    #[project = MapProj]
    #[project_replace = MapProjReplace]
    #[must_use = "futures do nothing unless you `.await` or poll them"]
    enum MapInner<I, F> {
        Incomplete {
            #[pin]
            inner: I,
            f: F,
        },
        Done,
    }
}

impl<I, F, O> Output for MapInner<I, F>
where
    I: Output,
    F: FnOnce(I::Ok) -> O,
{
    type Ok = O;

    fn try_recv(&mut self) -> Result<Option<Self::Ok>, Canceled> {
        let this = mem::replace(self, MapInner::Done);
        match this {
            MapInner::Incomplete { mut inner, f } => inner.try_recv().map(|res| res.map(f)),
            MapInner::Done => Err(Canceled { _private: () }),
        }
    }
}

impl<I, F, O> Future for MapInner<I, F>
where
    I: Output,
    F: FnOnce(I::Ok) -> O,
{
    type Output = Result<O, Canceled>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.as_mut().project() {
            MapProj::Incomplete { inner, .. } => {
                let output = ready!(inner.poll(cx));
                match self.project_replace(Self::Done) {
                    MapProjReplace::Incomplete { f, .. } => Poll::Ready(output.map(f)),
                    MapProjReplace::Done => unreachable!(),
                }
            }
            MapProj::Done => {
                panic!("Map must not be polled after it returned `Poll::Ready`")
            }
        }
    }
}
