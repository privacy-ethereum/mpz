//! Custom allocator that notifies the host of memory allocations.

use std::alloc::{GlobalAlloc, Layout, System};

/// An allocator that wraps the system allocator and notifies the host
/// of all allocations and deallocations.
pub struct MpzAllocator;

#[cfg(target_arch = "wasm32")]
use crate::sys;

#[cfg(not(target_arch = "wasm32"))]
use crate::trampoline as sys;

unsafe impl GlobalAlloc for MpzAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        unsafe {
            let ptr = System.alloc(layout);
            if !ptr.is_null() {
                sys::alloc(ptr, layout.size() as u32);
            }
            ptr
        }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe {
            sys::free(ptr, layout.size() as u32);
            System.dealloc(ptr, layout);
        }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        unsafe {
            let ptr = System.alloc_zeroed(layout);
            if !ptr.is_null() {
                sys::alloc(ptr, layout.size() as u32);
            }
            ptr
        }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        unsafe {
            sys::free(ptr, layout.size() as u32);
            let new_ptr = System.realloc(ptr, layout, new_size);
            if !new_ptr.is_null() {
                sys::alloc(new_ptr, new_size as u32);
            }
            new_ptr
        }
    }
}
