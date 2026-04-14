// Unified decode interface - in trampoline mode, values are already clear
// so decode is a no-op (returns sentinel -1)
pub unsafe fn decode(_ptr: *const u8, _len: u32) -> i32 {
    -1 // sentinel for "already clear"
}

pub unsafe fn decode_wait(_handle: i32) {}

// Memory region tracking - no-op in trampoline mode
pub unsafe fn alloc(_ptr: *const u8, _len: u32) {}
pub unsafe fn free(_ptr: *const u8, _len: u32) {}

// Preprocessing - no-op stubs in trampoline mode
pub unsafe fn preprocess_enter() {}
pub unsafe fn preprocess_exit() -> u32 {
    0
}

pub unsafe fn symbolic(_ptr: *mut u8, _len: u32) {}

// Execute preprocessed function - no-op stubs
pub unsafe fn call_enter(_handle: u32) {}
pub unsafe fn call_arg(_ptr: *const u8, _len: u32) {}
pub unsafe fn call_result_size() -> u32 {
    0
}
pub unsafe fn call_exit(_ptr: *mut u8, _len: u32) {}
