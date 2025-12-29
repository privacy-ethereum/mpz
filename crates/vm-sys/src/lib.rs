//! WASM interface definitions for the MPZ VM system.
//!
//! This crate defines the interface that WASM modules can import when
//! running in the MPZ VM. These are extern declarations without implementations.

#[link(wasm_import_module = "mpz")]
unsafe extern "C" {
    /// Decodes an `i32` value from encoded to clear.
    pub unsafe fn decode_i32(v: i32) -> i32;

    /// Decodes an `i64` value from encoded to clear.
    pub unsafe fn decode_i64(v: i64) -> i64;
}
