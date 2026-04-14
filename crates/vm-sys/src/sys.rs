#[link(wasm_import_module = "mpz")]
unsafe extern "C" {
    // Unified decode interface - works with any value size
    pub fn decode(ptr: *const u8, len: u32) -> i32;
    pub fn decode_wait(handle: i32);

    // Memory region tracking (called by custom allocator)
    pub fn alloc(ptr: *const u8, len: u32);
    pub fn free(ptr: *const u8, len: u32);

    // Preprocessing lifecycle
    pub fn preprocess_enter();
    pub fn preprocess_exit() -> u32;

    // Create symbolic values
    pub fn symbolic(ptr: *mut u8, len: u32);

    // Execute preprocessed function
    pub fn call_enter(handle: u32);
    pub fn call_arg(ptr: *const u8, len: u32);
    pub fn call_result_size() -> u32;
    pub fn call_exit(ptr: *mut u8, len: u32);
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn cabi_realloc(
    old_ptr: *mut u8,
    old_len: usize,
    align: usize,
    new_len: usize,
) -> *mut u8 {
    unsafe {
        let layout = std::alloc::Layout::from_size_align_unchecked(new_len, align);
        if old_len == 0 {
            std::alloc::alloc(layout)
        } else {
            let old_layout = std::alloc::Layout::from_size_align_unchecked(old_len, align);
            std::alloc::realloc(old_ptr, old_layout, new_len)
        }
    }
}
