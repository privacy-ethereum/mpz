//! Test functions compiled to WASM for vm-core-new interpreter tests.

use aes::cipher::{BlockCipherEncrypt, KeyInit};

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

/// Multiplies `a` by `b^n`.
#[unsafe(no_mangle)]
pub extern "C" fn mul_exp(a: i32, b: i32, n: i32) -> i32 {
    unsafe { decode_i32_wait(decode_i32(a * b.pow(n as u32))) }
}

/// Computes AES.
#[unsafe(no_mangle)]
pub extern "C" fn aes(key: u8, msg: u8) {
    let aes = aes::Aes128::new_from_slice(&[key; 16]).unwrap();
    let mut msg = [msg; 16].into();
    aes.encrypt_block(&mut msg);
    let msg = msg.0.map(|b| unsafe { decode_i32(b as i32) });
    let msg = msg.map(|b| unsafe { decode_i32_wait(b) } as u8);
    assert_eq!(
        msg,
        [
            23, 214, 20, 243, 121, 169, 53, 144, 119, 233, 85, 119, 253, 49, 194, 10
        ]
    );
}

#[link(wasm_import_module = "mpz")]
unsafe extern "C" {
    /// Returns a handle to a decoded i32 value.
    fn decode_i32(v: i32) -> i32;

    /// Blocks on the provided i32 handle, returning the value when available.
    fn decode_i32_wait(handle: i32) -> i32;
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
}
