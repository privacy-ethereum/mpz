//! wasm32 target: the VCI reveal operations imported from the host `vc` module.
//!
//! `reveal_<ty>(value) -> handle` initiates disclosure and returns immediately;
//! `reveal_<ty>_wait(handle) -> value` blocks until it completes.

#[link(wasm_import_module = "vc")]
unsafe extern "C" {
    pub fn reveal_i32(value: i32) -> i32;
    pub fn reveal_i64(value: i64) -> i32;
    pub fn reveal_f32(value: f32) -> i32;
    pub fn reveal_f64(value: f64) -> i32;

    pub fn reveal_i32_wait(handle: i32) -> i32;
    pub fn reveal_i64_wait(handle: i32) -> i64;
    pub fn reveal_f32_wait(handle: i32) -> f32;
    pub fn reveal_f64_wait(handle: i32) -> f64;

    /// Requests that the `len` bytes at `ptr` in linear memory be revealed in
    /// place; returns a handle.
    pub fn reveal_bytes(ptr: i32, len: i32) -> i32;
    /// Blocks until the byte reveal for `handle` completes.
    pub fn reveal_bytes_wait(handle: i32);
}

// wasm32 target: the SHA-256 compression precompile, imported from the host
// `precompile` module.
#[link(wasm_import_module = "precompile")]
unsafe extern "C" {
    /// Compresses the 64-byte block at `block_ptr` into the 32-byte state at
    /// `state_ptr`, in place: `*state = sha256_compress(*block, *state)`.
    pub fn sha256_compress(state_ptr: i32, block_ptr: i32);
}
