//! A minimal SHA-256 guest for the zk-vm benchmark.
//!
//! Memory is handed out through [`cabi_realloc`], the WebAssembly Component
//! Model's canonical reallocation export: the host calls
//! `cabi_realloc(0, 0, align, len)` to allocate the message buffer, writes the
//! message there, then calls [`hash`] with that pointer and the message length.
//! The guest computes SHA-256, allocates a 32-byte output buffer through
//! `cabi_realloc`, writes the digest there, reveals it through the VCI so the
//! verifier learns it, and returns the digest's address. SHA-256 uses only
//! operations the VM supports (`rotate_right` lowers to `i32.rotr`, etc.).

use std::alloc::Layout;

const H0: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

#[link(wasm_import_module = "vc")]
extern "C" {
    fn reveal_bytes(ptr: i32, len: i32) -> i32;
    fn reveal_bytes_wait(handle: i32);
}

/// The Component Model canonical `realloc`:
/// `cabi_realloc(old_ptr, old_size, align, new_size) -> ptr`.
///
/// Delegates to the default global (system) allocator: a fresh block
/// (`old_ptr == 0`) is an [`std::alloc::alloc`], otherwise a
/// [`std::alloc::realloc`] of the existing block.
#[no_mangle]
pub extern "C" fn cabi_realloc(old_ptr: i32, old_size: i32, align: i32, new_size: i32) -> i32 {
    let align = (align as usize).max(1);
    let new_size = new_size as usize;
    unsafe {
        if old_ptr == 0 {
            let layout = Layout::from_size_align_unchecked(new_size, align);
            std::alloc::alloc(layout) as i32
        } else {
            let old_layout = Layout::from_size_align_unchecked(old_size as usize, align);
            std::alloc::realloc(old_ptr as *mut u8, old_layout, new_size) as i32
        }
    }
}

/// Hashes the `len` bytes at `ptr`, writes the 32-byte digest into a buffer
/// freshly allocated through [`cabi_realloc`], reveals it, and returns the
/// digest's address.
#[no_mangle]
pub extern "C" fn hash(ptr: i32, len: i32) -> i32 {
    let digest_ptr = cabi_realloc(0, 0, 1, 32);
    sha256(ptr as *const u8, len as usize, digest_ptr as *mut u8);
    unsafe {
        let handle = reveal_bytes(digest_ptr, 32);
        reveal_bytes_wait(handle);
    }
    digest_ptr
}

fn sha256(msg: *const u8, len: usize, out: *mut u8) {
    let mut h = H0;
    let bitlen = (len as u64).wrapping_mul(8);
    // Padded length: message + 0x80 + zeros + 8-byte length, rounded to 64.
    let mut total = len + 9;
    if total % 64 != 0 {
        total += 64 - (total % 64);
    }

    let mut block = [0u8; 64];
    let mut pos = 0;
    while pos < total {
        let mut i = 0;
        while i < 64 {
            let idx = pos + i;
            block[i] = if idx < len {
                unsafe { *msg.add(idx) }
            } else if idx == len {
                0x80
            } else if idx + 8 >= total {
                let shift = (total - 1 - idx) * 8;
                (bitlen >> shift) as u8
            } else {
                0
            };
            i += 1;
        }
        compress(&mut h, &block);
        pos += 64;
    }

    let mut i = 0;
    while i < 8 {
        let be = h[i].to_be_bytes();
        let mut j = 0;
        while j < 4 {
            unsafe {
                *out.add(i * 4 + j) = be[j];
            }
            j += 1;
        }
        i += 1;
    }
}

fn compress(h: &mut [u32; 8], block: &[u8; 64]) {
    let mut w = [0u32; 64];
    let mut t = 0;
    while t < 16 {
        w[t] = u32::from_be_bytes([
            block[4 * t],
            block[4 * t + 1],
            block[4 * t + 2],
            block[4 * t + 3],
        ]);
        t += 1;
    }
    while t < 64 {
        let s0 = w[t - 15].rotate_right(7) ^ w[t - 15].rotate_right(18) ^ (w[t - 15] >> 3);
        let s1 = w[t - 2].rotate_right(17) ^ w[t - 2].rotate_right(19) ^ (w[t - 2] >> 10);
        w[t] = w[t - 16]
            .wrapping_add(s0)
            .wrapping_add(w[t - 7])
            .wrapping_add(s1);
        t += 1;
    }

    let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh) =
        (h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);
    let mut t = 0;
    while t < 64 {
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ ((!e) & g);
        let t1 = hh
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(K[t])
            .wrapping_add(w[t]);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let t2 = s0.wrapping_add(maj);
        hh = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
        t += 1;
    }

    h[0] = h[0].wrapping_add(a);
    h[1] = h[1].wrapping_add(b);
    h[2] = h[2].wrapping_add(c);
    h[3] = h[3].wrapping_add(d);
    h[4] = h[4].wrapping_add(e);
    h[5] = h[5].wrapping_add(f);
    h[6] = h[6].wrapping_add(g);
    h[7] = h[7].wrapping_add(hh);
}
