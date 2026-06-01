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
