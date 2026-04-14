#[cfg(target_arch = "wasm32")]
mod sys;
#[cfg(target_arch = "wasm32")]
use sys as imp;

#[cfg(not(target_arch = "wasm32"))]
mod trampoline;
#[cfg(not(target_arch = "wasm32"))]
use trampoline as imp;

pub mod allocator;

use std::{mem, mem::MaybeUninit};

pub trait DecodeExt: Copy {
    fn decode(self) -> Decode<Self> {
        Decode::new(self)
    }
}

impl<T> DecodeExt for T where T: Copy {}

pub struct Decode<T> {
    handle: i32,
    value: Box<T>,
}

impl<T: Copy> Decode<T> {
    pub fn new(v: T) -> Self {
        let value = Box::new(v);
        let ptr = value.as_ref() as *const T as *const u8;
        let len = mem::size_of::<T>() as u32;
        let handle = unsafe { imp::decode(ptr, len) };
        Decode { handle, value }
    }

    pub fn wait(self) -> T {
        unsafe { imp::decode_wait(self.handle) };
        *self.value
    }
}

pub fn decode<T: Copy>(v: T) -> Decode<T> {
    Decode::new(v)
}

/// Creates a symbolic value of any Sized type.
pub fn symbolic<T: Sized>() -> T {
    let mut val = MaybeUninit::<T>::uninit();
    unsafe {
        let ptr = val.as_mut_ptr();
        imp::symbolic(ptr as *mut u8, mem::size_of::<T>() as u32);
        // Force an actual memory load to trigger the symbolic load in the trace
        core::ptr::read_volatile(ptr)
    }
}

/// Creates a symbolic Box containing a symbolic value.
pub fn symbolic_box<T: Sized>() -> Box<T> {
    Box::new(symbolic::<T>())
}

/// Enters preprocessing mode.
pub fn preprocess_enter() {
    unsafe { imp::preprocess_enter() }
}

/// Exits preprocessing mode and returns a handle to the preprocessed trace.
pub fn preprocess_exit() -> u32 {
    unsafe { imp::preprocess_exit() }
}

/// Begins execution of a preprocessed function.
pub fn call_enter(handle: u32) {
    unsafe { imp::call_enter(handle) }
}

/// Provides an argument to the preprocessed function.
pub fn call_arg<T: Sized>(value: &T) {
    unsafe {
        imp::call_arg(value as *const T as *const u8, mem::size_of::<T>() as u32);
    }
}

/// Returns the size of the result from the preprocessed function.
pub fn call_result_size() -> u32 {
    unsafe { imp::call_result_size() }
}

/// Exits the preprocessed function call, writing the result to the given value.
pub fn call_exit<T: Sized>(output: &mut T) {
    unsafe {
        imp::call_exit(output as *mut T as *mut u8, mem::size_of::<T>() as u32);
    }
}

/// Exits the preprocessed function call, writing the result to the given
/// buffer.
pub fn call_exit_into(output: &mut [u8]) {
    unsafe {
        imp::call_exit(output.as_mut_ptr(), output.len() as u32);
    }
}

/// Preprocesses a closure, returning a `FnOnce` closure with the same
/// signature.
///
/// During preprocessing:
/// - Enters preprocessing mode
/// - Creates symbolic values for each parameter
/// - Executes the body to capture the trace
/// - Exits preprocessing mode with a handle
///
/// The returned closure, when called:
/// - Begins execution with the stored handle
/// - Passes each argument to the host
/// - Retrieves and returns the result
///
/// # Example
///
/// ```ignore
/// let multiply = preprocess!(|a: i32, b: i32| -> i32 {
///     a * b * 42  // 42 folded at preprocess time
/// });
/// let result: i32 = multiply(secret_a, secret_b);
/// ```
#[macro_export]
macro_rules! preprocess {
    // With explicit return type
    (|$($param:ident : $ty:ty),*| -> $ret:ty $body:block) => {{
        $crate::preprocess_enter();
        $(let $param = $crate::symbolic::<$ty>();)*
        // Use black_box to prevent optimizer from removing the computation
        let _result: $ret = ::core::hint::black_box($body);
        let handle = $crate::preprocess_exit();

        move |$($param: $ty),*| -> $ret {
            $crate::call_enter(handle);
            $($crate::call_arg(&$param);)*
            let mut result = ::core::mem::MaybeUninit::<$ret>::uninit();
            unsafe {
                $crate::call_exit(&mut *result.as_mut_ptr());
                result.assume_init()
            }
        }
    }};

    // Without return type (returns ())
    (|$($param:ident : $ty:ty),*| $body:block) => {{
        $crate::preprocess_enter();
        $(let $param = $crate::symbolic::<$ty>();)*
        let _: () = $body;
        let handle = $crate::preprocess_exit();

        move |$($param: $ty),*| {
            $crate::call_enter(handle);
            $($crate::call_arg(&$param);)*
            $crate::call_exit_unit();
        }
    }};
}

/// Exits the preprocessed function call with no return value.
pub fn call_exit_unit() {
    unsafe {
        imp::call_exit(core::ptr::null_mut(), 0);
    }
}
