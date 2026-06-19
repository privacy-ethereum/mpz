//! Non-wasm target: clear-execution stubs. Every value is already public, so a
//! reveal is a no-op. The `_wait` results are unused — the caller returns the
//! value it submitted.

pub unsafe fn reveal_i32(_value: i32) -> i32 {
    -1
}
pub unsafe fn reveal_i64(_value: i64) -> i32 {
    -1
}
pub unsafe fn reveal_f32(_value: f32) -> i32 {
    -1
}
pub unsafe fn reveal_f64(_value: f64) -> i32 {
    -1
}

pub unsafe fn reveal_i32_wait(_handle: i32) -> i32 {
    0
}
pub unsafe fn reveal_i64_wait(_handle: i32) -> i64 {
    0
}
pub unsafe fn reveal_f32_wait(_handle: i32) -> f32 {
    0.0
}
pub unsafe fn reveal_f64_wait(_handle: i32) -> f64 {
    0.0
}

pub unsafe fn reveal_bytes(_ptr: i32, _len: i32) -> i32 {
    -1
}
pub unsafe fn reveal_bytes_wait(_handle: i32) {}

/// Clear-execution SHA-256 compression: compresses the block at `block_ptr`
/// into the state at `state_ptr`, in place. Unlike the reveal stubs this is not
/// a no-op — it computes the same value the host precompile would (via the
/// `sha2` crate), so a guest run natively produces the correct state.
///
/// # Safety
/// `state_ptr` must address 8 readable+writable `u32` words and `block_ptr` 64
/// readable bytes, which [`sha256_compress`](crate::sha256_compress) guarantees
/// from its `&mut [u32; 8]` / `&[u8; 64]` arguments.
pub unsafe fn sha256_compress(state_ptr: i32, block_ptr: i32) {
    let state = unsafe { &mut *(state_ptr as usize as *mut [u32; 8]) };
    let block = unsafe { &*(block_ptr as usize as *const [u8; 64]) };
    sha2::compress256(state, &[(*block).into()]);
}
