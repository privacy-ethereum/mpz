//! Test functions compiled to WASM for vm-core-new interpreter tests.

use aes::cipher::{BlockCipherEncrypt, KeyInit};
use mpz_vm_sys::{DecodeExt, preprocess};
use serde::Deserialize;

/// Adds two i32 values.
#[unsafe(no_mangle)]
pub extern "C" fn add_i32(a: i32, b: i32) -> i32 {
    a + b
}

/// Adds two i64 values.
#[unsafe(no_mangle)]
pub extern "C" fn add_i64(a: i64, b: i64) -> i64 {
    a + b
}

/// Subtracts two i32 values.
#[unsafe(no_mangle)]
pub extern "C" fn sub_i32(a: i32, b: i32) -> i32 {
    a - b
}

/// Multiplies two i32 values.
#[unsafe(no_mangle)]
pub extern "C" fn mul_i32(a: i32, b: i32) -> i32 {
    a * b
}

/// Computes factorial of n (i32).
#[unsafe(no_mangle)]
pub extern "C" fn factorial(n: i32) -> i32 {
    if n <= 1 { 1 } else { n * factorial(n - 1) }
}

/// Computes nth fibonacci number (i32).
#[unsafe(no_mangle)]
pub extern "C" fn fibonacci(n: i32) -> i32 {
    if n <= 1 {
        n
    } else {
        fibonacci(n - 1) + fibonacci(n - 2)
    }
}

/// Simple loop: sum 0 to n-1.
#[unsafe(no_mangle)]
pub extern "C" fn sum_to_n(n: i32) -> i32 {
    let mut sum = 0;
    let mut i = 0;
    while i < n {
        sum += i;
        i += 1;
    }
    sum
}

/// Returns the larger of two i32 values.
#[unsafe(no_mangle)]
pub extern "C" fn max_i32(a: i32, b: i32) -> i32 {
    if a > b { a } else { b }
}

/// Computes a simple conditional expression.
#[unsafe(no_mangle)]
pub extern "C" fn conditional(a: i32, b: i32, c: i32) -> i32 {
    if c != 0 { a } else { b }
}

#[unsafe(no_mangle)]
pub extern "C" fn preprocess(a: i32) {
    let f = preprocess!(|a: i32| -> i32 { a.pow(10) });
    let out = f(a).decode().wait();
    assert_eq!(out, a.pow(10).decode().wait());
}

/// Multiplies `a` by `b^n`.
#[unsafe(no_mangle)]
pub extern "C" fn mul_exp(a: i32, b: i32, n: i32) -> i32 {
    let out = a * b.pow(n as u32);
    (out as u128).decode().wait() as i32
}

/// Computes AES.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn aes(key: *mut u8, msg: *mut u8) {
    let key: [u8; 16] = unsafe { core::ptr::read(key as *const [u8; 16]) };
    let msg: [u8; 16] = unsafe { core::ptr::read(msg as *const [u8; 16]) };

    aes_inner(key, msg);
}

fn aes_inner(key: [u8; 16], mut msg: [u8; 16]) {
    let aes = aes::Aes128::new_from_slice(&key).unwrap();
    aes.encrypt_block((&mut msg).into());
    let msg = msg.decode().wait();
    println!("{:?}", msg);
    assert_eq!(
        msg,
        [
            23, 214, 20, 243, 121, 169, 53, 144, 119, 233, 85, 119, 253, 49, 194, 10
        ]
    );
}

/// Test println! from guest code.
#[unsafe(no_mangle)]
pub extern "C" fn test_print() {
    println!("Hello from guest code!");
}

/// Simple memory load test - reads 4 bytes from pointer and returns sum.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sum_bytes(ptr: *const u8) -> i32 {
    let a = *ptr;
    let b = *ptr.add(1);
    let c = *ptr.add(2);
    let d = *ptr.add(3);
    let sum = (a as i32) + (b as i32) + (c as i32) + (d as i32);
    sum.decode().wait()
}

/// Load 16 bytes and compute a checksum with many local operations.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn checksum16(ptr: *const u8) -> i32 {
    // Load 16 bytes
    let b: [u8; 16] = core::ptr::read(ptr as *const [u8; 16]);

    // Do some computation with lots of local variables
    let mut sum: i32 = 0;
    for i in 0..16 {
        sum = sum.wrapping_add(b[i] as i32);
        sum = sum ^ ((b[i] as i32) << (i % 8));
    }
    sum.decode().wait()
}

/// XOR two 16-byte arrays and return sum of result.
/// This simulates AES having key from one party and msg from another.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xor_and_sum(a_ptr: *const u8, b_ptr: *const u8) -> i32 {
    let a: [u8; 16] = core::ptr::read(a_ptr as *const [u8; 16]);
    let b: [u8; 16] = core::ptr::read(b_ptr as *const [u8; 16]);

    let mut sum: i32 = 0;
    for i in 0..16 {
        sum = sum.wrapping_add((a[i] ^ b[i]) as i32);
    }
    sum.decode().wait()
}

/// Test i64 operations: load two i64 values and XOR them.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xor_i64(a_ptr: *const u64, b_ptr: *const u64) -> i64 {
    let a: u64 = core::ptr::read(a_ptr);
    let b: u64 = core::ptr::read(b_ptr);
    let result = a ^ b;
    (result as i64).decode().wait()
}

/// Test store then load: XOR two values, store result, load it back.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn store_load_i64(a_ptr: *mut u64, b_ptr: *const u64) -> i64 {
    let a: u64 = core::ptr::read(a_ptr);
    let b: u64 = core::ptr::read(b_ptr);
    let result = a ^ b;
    // Store result back to a_ptr
    core::ptr::write(a_ptr, result);
    // Load it back
    let loaded: u64 = core::ptr::read(a_ptr);
    (loaded as i64).decode().wait()
}

/// Multiple rounds of XOR operations like AES.
/// workspace is 16 u64 values (128 bytes).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn multi_round(workspace: *mut u64, rounds: i32) -> i64 {
    let ws: &mut [u64; 16] = &mut *(workspace as *mut [u64; 16]);

    for _ in 0..rounds {
        // Simple round function: XOR adjacent pairs and rotate
        let t0 = ws[0] ^ ws[1];
        let t1 = ws[2] ^ ws[3];
        let t2 = ws[4] ^ ws[5];
        let t3 = ws[6] ^ ws[7];
        let t4 = ws[8] ^ ws[9];
        let t5 = ws[10] ^ ws[11];
        let t6 = ws[12] ^ ws[13];
        let t7 = ws[14] ^ ws[15];

        ws[0] = t7;
        ws[1] = t0;
        ws[2] = t1;
        ws[3] = t2;
        ws[4] = t3;
        ws[5] = t4;
        ws[6] = t5;
        ws[7] = t6;
        ws[8] = t0 ^ t1;
        ws[9] = t1 ^ t2;
        ws[10] = t2 ^ t3;
        ws[11] = t3 ^ t4;
        ws[12] = t4 ^ t5;
        ws[13] = t5 ^ t6;
        ws[14] = t6 ^ t7;
        ws[15] = t7 ^ t0;
    }

    // Return checksum
    let mut sum: u64 = 0;
    for i in 0..16 {
        sum = sum.wrapping_add(ws[i]);
    }
    (sum as i64).decode().wait()
}

/// Load two i64 values directly (not byte-by-byte), XOR with constant, store
/// back. This mimics AES's i64 load/store pattern.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn i64_load_store(data_ptr: *mut u64) -> i64 {
    // Load two i64 values
    let v0: u64 = *data_ptr;
    let v1: u64 = *data_ptr.add(1);

    // XOR with constants like bitsliced AES
    let r0 = v0 ^ 0x5555555555555555u64;
    let r1 = v1 ^ 0x0f0f0f0f0f0f0f0fu64;

    // Store results back
    *data_ptr = r0;
    *data_ptr.add(1) = r1;

    // Return checksum
    let sum = r0.wrapping_add(r1);
    (sum as i64).decode().wait()
}

/// Like AES - load from input, store to workspace, load workspace, compute,
/// store output. input_ptr: 16 bytes input
/// workspace_ptr: 128 bytes workspace
/// output_ptr: 16 bytes output
#[unsafe(no_mangle)]
pub unsafe extern "C" fn multi_workspace(
    input_ptr: *const u64,
    workspace_ptr: *mut u64,
    output_ptr: *mut u64,
) -> i64 {
    // Load input (2 x u64 = 16 bytes)
    let in0: u64 = *input_ptr;
    let in1: u64 = *input_ptr.add(1);

    // Store to workspace with mixing
    let ws = core::slice::from_raw_parts_mut(workspace_ptr, 16);
    ws[0] = in0;
    ws[1] = in1;
    ws[2] = in0 ^ 0x5555555555555555u64;
    ws[3] = in1 ^ 0x5555555555555555u64;
    ws[4] = in0 ^ 0x0f0f0f0f0f0f0f0fu64;
    ws[5] = in1 ^ 0x0f0f0f0f0f0f0f0fu64;
    ws[6] = in0 ^ in1;
    ws[7] = (in0 ^ in1) ^ 0x5555555555555555u64;

    // Load back from workspace and compute more
    for i in 8..16 {
        ws[i] = ws[i - 8] ^ ws[i - 4];
    }

    // Compute output from workspace
    let out0 = ws[12] ^ ws[14];
    let out1 = ws[13] ^ ws[15];

    // Store to output
    *output_ptr = out0;
    *output_ptr.add(1) = out1;

    // Return sum for verification
    let sum = out0.wrapping_add(out1);
    (sum as i64).decode().wait()
}

#[derive(Deserialize)]
struct ApiResponse<'a> {
    users: Vec<User<'a>>,
    pagination: Pagination,
    filters: Filters<'a>,
    api_version: &'a str,
    request_id: &'a str,
}

#[derive(Deserialize)]
struct User<'a> {
    id: u32,
    name: &'a str,
    email: &'a str,
    age: u32,
    active: bool,
    roles: Vec<&'a str>,
    address: Address<'a>,
    preferences: Preferences<'a>,
    scores: Vec<u32>,
    metadata: Metadata<'a>,
}

#[derive(Deserialize)]
struct Address<'a> {
    street: &'a str,
    city: &'a str,
    state: &'a str,
    zip: &'a str,
    country: &'a str,
}

#[derive(Deserialize)]
struct Preferences<'a> {
    theme: &'a str,
    language: &'a str,
    notifications: Notifications,
    timezone: &'a str,
}

#[derive(Deserialize)]
struct Notifications {
    email: bool,
    sms: bool,
    push: bool,
}

#[derive(Deserialize)]
struct Pagination {
    page: u32,
    per_page: u32,
    total: u32,
    total_pages: u32,
}

#[derive(Deserialize)]
struct Filters<'a> {
    active_only: bool,
    min_age: Option<u32>,
    max_age: Option<u32>,
    roles: Vec<&'a str>,
    sort_by: &'a str,
    sort_order: &'a str,
}

#[derive(Deserialize)]
struct Metadata<'a> {
    created_at: &'a str,
    updated_at: &'a str,
    login_count: u32,
    last_ip: &'a str,
}

fn parse_json(json: &[u8]) {
    let response = serde_json::from_slice::<ApiResponse>(json).unwrap();
    assert!(!response.users.is_empty());
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn json_parse(json_ptr: u32, json_len: u32) -> u32 {
    let json = core::slice::from_raw_parts(json_ptr as *const u8, json_len as usize);
    parse_json(json);
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test() {
        let aes = aes::Aes128::new_from_slice(&[1; 16]).unwrap();
        let mut msg = [2; 16].into();
        aes.encrypt_block(&mut msg);
        panic!("{:?}", msg);
    }

    #[test]
    fn test_json_parse_fixture() {
        let json = include_bytes!("../fixtures/sample.json");
        parse_json(json);
    }
}
