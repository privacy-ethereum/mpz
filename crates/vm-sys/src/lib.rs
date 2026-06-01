//! Guest-side bindings for the VCI (verifiable-compute interface).
//!
//! A program compiled to wasm and run inside the VC VM links against this crate
//! to invoke the VM's VCI host calls, imported from the `vc` module. The VCI
//! operation is [`reveal`](Reveal::reveal): disclosing a value the program holds
//! — concrete or symbolic — so that it becomes public. It is two-phase:
//! `reveal` returns a handle immediately and the handle's `wait` blocks for the
//! result, which lets a program batch and pipeline reveals.
//!
//! Reveal is defined for the four wasm value types (`i32`, `i64`, `f32`, `f64`)
//! and for byte slices (`&[u8]`). On non-wasm targets the bindings compile to
//! clear-execution no-ops — every value is already public — so the same program
//! runs natively.

#[cfg(target_arch = "wasm32")]
mod sys;
#[cfg(target_arch = "wasm32")]
use sys as imp;

#[cfg(not(target_arch = "wasm32"))]
mod trampoline;
#[cfg(not(target_arch = "wasm32"))]
use trampoline as imp;

/// A value that can be revealed through the VCI.
///
/// Implemented for the four wasm value types (`i32`, `i64`, `f32`, `f64`) and
/// for byte slices (`&[u8]`). Call [`reveal`](Self::reveal) to start a
/// disclosure, then `wait` on the returned handle for the public result.
pub trait Reveal: sealed::Sealed {
    /// The pending-reveal handle this produces; resolve it with its `wait`.
    type Output;

    /// Requests that this value be revealed, returning a handle immediately.
    fn reveal(self) -> Self::Output;
}

/// Reveals `v`, returning a handle resolved with its `wait`.
pub fn reveal<T: Reveal>(v: T) -> T::Output {
    v.reveal()
}

/// A pending reveal of a scalar value of type `T`.
///
/// Produced by [`Reveal::reveal`] on a scalar; resolve it with
/// [`wait`](Self::wait).
pub struct Pending<T: Scalar> {
    handle: i32,
    submitted: T,
}

impl<T: Scalar> Pending<T> {
    /// Blocks until the reveal completes, then returns the now-public value.
    pub fn wait(self) -> T {
        T::wait_handle(self.handle, self.submitted)
    }
}

/// The scalar reveal value types: `i32`, `i64`, `f32`, `f64`. Sealed.
pub trait Scalar: Copy + sealed::Sealed {
    #[doc(hidden)]
    fn wait_handle(handle: i32, submitted: Self) -> Self;
}

macro_rules! impl_scalar {
    ($ty:ty, $request:ident, $wait:ident) => {
        impl Reveal for $ty {
            type Output = Pending<$ty>;
            fn reveal(self) -> Pending<$ty> {
                let handle = unsafe { imp::$request(self) };
                Pending {
                    handle,
                    submitted: self,
                }
            }
        }

        impl Scalar for $ty {
            fn wait_handle(handle: i32, submitted: Self) -> Self {
                // On wasm the host returns the revealed value; natively every
                // value is already public, so the submitted value is returned.
                #[cfg(target_arch = "wasm32")]
                {
                    let _ = submitted;
                    unsafe { imp::$wait(handle) }
                }
                #[cfg(not(target_arch = "wasm32"))]
                {
                    unsafe { imp::$wait(handle) };
                    submitted
                }
            }
        }
    };
}

impl_scalar!(i32, reveal_i32, reveal_i32_wait);
impl_scalar!(i64, reveal_i64, reveal_i64_wait);
impl_scalar!(f32, reveal_f32, reveal_f32_wait);
impl_scalar!(f64, reveal_f64, reveal_f64_wait);

/// A pending reveal of a byte region.
///
/// Borrows the region until the reveal completes, so it cannot be reallocated or
/// mutated while in flight. The disclosure is in place; [`wait`](Self::wait)
/// hands the region back.
pub struct PendingBytes<'a> {
    handle: i32,
    bytes: &'a [u8],
}

impl<'a> PendingBytes<'a> {
    /// Blocks until the region is public, then returns it.
    pub fn wait(self) -> &'a [u8] {
        unsafe { imp::reveal_bytes_wait(self.handle) };
        self.bytes
    }
}

impl<'a> Reveal for &'a [u8] {
    type Output = PendingBytes<'a>;

    /// Reveals the bytes of this slice in place.
    ///
    /// Exactly these bytes are disclosed, so the slice must cover only the data
    /// meant to be public — a slice spanning struct padding or unused buffer
    /// capacity leaks whatever those bytes hold.
    ///
    /// The bytes may still be read before the reveal completes, but until then
    /// they remain symbolic: computing on them costs as if private, and using
    /// one to drive control flow or indexing blocks like any other private
    /// value.
    fn reveal(self) -> PendingBytes<'a> {
        let handle = unsafe { imp::reveal_bytes(self.as_ptr() as i32, self.len() as i32) };
        PendingBytes {
            handle,
            bytes: self,
        }
    }
}

mod sealed {
    pub trait Sealed {}
    impl Sealed for i32 {}
    impl Sealed for i64 {}
    impl Sealed for f32 {}
    impl Sealed for f64 {}
    impl Sealed for &[u8] {}
}
