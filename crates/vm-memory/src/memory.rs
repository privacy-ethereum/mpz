//! Sparse byte-addressed linear memory plus typed accessors that
//! implement the WASM load/store instructions whose semantics are
//! pure wire routing — i.e. byte concat/slice with zero- or
//! sign-extension. None of these operations introduce nonlinear
//! gates: zero-extension fills with the memory's public-0 bit,
//! sign-extension replicates the high bit of the loaded byte, and
//! concat/slice are just bit shuffling.
//!
//! The memory stores the public-0 and public-1 [`Bit`]s supplied at
//! construction; the caller owns the protocol encoding of those wires.
//!
//! Method names mirror the WASM mnemonics:
//!
//! - `load_i32`, `load_i64`, `load_f32`, `load_f64`
//! - `load_i32_8u`/`load_i32_8s`, `load_i32_16u`/`load_i32_16s`
//! - `load_i64_8u`/`load_i64_8s`, `load_i64_16u`/`load_i64_16s`,
//!   `load_i64_32u`/`load_i64_32s`
//! - `store_i32`, `store_i64`, `store_f32`, `store_f64`
//! - `store_i32_8`, `store_i32_16`
//! - `store_i64_8`, `store_i64_16`, `store_i64_32`

use std::collections::HashMap;

use mpz_fields::gf2_128::Gf2_128;

use crate::auth::{Bit, Byte, Wire, F32, F64, I32, I64};

/// Sparse byte-addressed linear memory keyed by absolute byte address,
/// storing one [`Byte<W>`] per tainted address. Carries the public-0 and
/// public-1 [`Bit<W>`]s used to fill extensions and encode public bytes.
#[derive(Debug)]
pub struct LinearMemory<W = Gf2_128> {
    inner: HashMap<u32, Byte<W>>,
    zero: Bit<W>,
    one: Bit<W>,
}

impl<W: Wire> LinearMemory<W> {
    /// Create an empty memory whose public-0 and public-1 wires are
    /// `zero` and `one`.
    pub fn new(zero: Bit<W>, one: Bit<W>) -> Self {
        Self {
            inner: HashMap::new(),
            zero,
            one,
        }
    }

    /// Set (or overwrite) the byte at the absolute address `addr`.
    pub fn set_byte(&mut self, addr: u32, byte: Byte<W>) {
        self.inner.insert(addr, byte);
    }

    /// Borrow the byte at `addr`, if any.
    pub fn get_byte(&self, addr: u32) -> Option<&Byte<W>> {
        self.inner.get(&addr)
    }

    /// Store `val` as a public byte at `addr`, encoding each bit with the
    /// memory's public-0/public-1 wires (LSB first).
    pub fn set_public_byte(&mut self, addr: u32, val: u8) {
        self.inner.insert(addr, self.public_byte(val));
    }

    /// Build (without storing) a public byte holding `val`, encoding each bit
    /// with the memory's public-0/public-1 wires (LSB first).
    fn public_byte(&self, val: u8) -> Byte<W> {
        Byte::new(core::array::from_fn(|i| {
            if (val >> i) & 1 != 0 {
                self.one
            } else {
                self.zero
            }
        }))
    }
}

// ============================================================
// WASM load/store semantics for AuthByte memory.
// ============================================================
//
// All operations below are pure wire routing — no `Context` is
// needed, no nonlinear gates are emitted. Loads return `None` if
// any required byte is absent.

impl<W: Wire> LinearMemory<W> {
    /// `i32.load`: 4 little-endian bytes → [`I32`].
    pub fn load_i32(&self, addr: u32) -> Option<I32<W>> {
        self.load_i32_mixed(addr, 0, !0)
    }

    /// `i64.load`: 8 little-endian bytes → [`I64`].
    pub fn load_i64(&self, addr: u32) -> Option<I64<W>> {
        self.load_i64_mixed(addr, 0, !0)
    }

    /// `f32.load`: 4 little-endian bytes → [`F32`].
    pub fn load_f32(&self, addr: u32) -> Option<F32<W>> {
        Some(F32::from_le_bytes(self.read_bytes::<4>(addr, 0, !0)?))
    }

    /// `f64.load`: 8 little-endian bytes → [`F64`].
    pub fn load_f64(&self, addr: u32) -> Option<F64<W>> {
        Some(F64::from_le_bytes(self.read_bytes::<8>(addr, 0, !0)?))
    }

    /// `i32.load8_u`: 1 byte → [`I32`], zero-extended.
    pub fn load_i32_8u(&self, addr: u32) -> Option<I32<W>> {
        self.load_i32_8u_mixed(addr, 0, !0)
    }

    /// `i32.load8_s`: 1 byte → [`I32`], sign-extended.
    pub fn load_i32_8s(&self, addr: u32) -> Option<I32<W>> {
        self.load_i32_8s_mixed(addr, 0, !0)
    }

    /// `i32.load16_u`: 2 bytes → [`I32`], zero-extended.
    pub fn load_i32_16u(&self, addr: u32) -> Option<I32<W>> {
        self.load_i32_16u_mixed(addr, 0, !0)
    }

    /// `i32.load16_s`: 2 bytes → [`I32`], sign-extended.
    pub fn load_i32_16s(&self, addr: u32) -> Option<I32<W>> {
        self.load_i32_16s_mixed(addr, 0, !0)
    }

    /// `i64.load8_u`: 1 byte → [`I64`], zero-extended.
    pub fn load_i64_8u(&self, addr: u32) -> Option<I64<W>> {
        self.load_i64_8u_mixed(addr, 0, !0)
    }

    /// `i64.load8_s`: 1 byte → [`I64`], sign-extended.
    pub fn load_i64_8s(&self, addr: u32) -> Option<I64<W>> {
        self.load_i64_8s_mixed(addr, 0, !0)
    }

    /// `i64.load16_u`: 2 bytes → [`I64`], zero-extended.
    pub fn load_i64_16u(&self, addr: u32) -> Option<I64<W>> {
        self.load_i64_16u_mixed(addr, 0, !0)
    }

    /// `i64.load16_s`: 2 bytes → [`I64`], sign-extended.
    pub fn load_i64_16s(&self, addr: u32) -> Option<I64<W>> {
        self.load_i64_16s_mixed(addr, 0, !0)
    }

    /// `i64.load32_u`: 4 bytes → [`I64`], zero-extended.
    pub fn load_i64_32u(&self, addr: u32) -> Option<I64<W>> {
        self.load_i64_32u_mixed(addr, 0, !0)
    }

    /// `i64.load32_s`: 4 bytes → [`I64`], sign-extended.
    pub fn load_i64_32s(&self, addr: u32) -> Option<I64<W>> {
        self.load_i64_32s_mixed(addr, 0, !0)
    }

    // Mixed loads: bytes with bit `i` set in `symbolic_mask` come from committed
    // memory; the rest are public bytes taken from `concrete` (LSB-first), built
    // transiently. Mirror the committed loads above one-for-one.

    /// Mixed `i32.load`.
    pub fn load_i32_mixed(&self, addr: u32, concrete: u64, symbolic_mask: u8) -> Option<I32<W>> {
        Some(I32::from_le_bytes(self.read_bytes::<4>(addr, concrete, symbolic_mask)?))
    }

    /// Mixed `i64.load`.
    pub fn load_i64_mixed(&self, addr: u32, concrete: u64, symbolic_mask: u8) -> Option<I64<W>> {
        Some(I64::from_le_bytes(self.read_bytes::<8>(addr, concrete, symbolic_mask)?))
    }

    /// Mixed `i32.load8_u`.
    pub fn load_i32_8u_mixed(&self, addr: u32, concrete: u64, symbolic_mask: u8) -> Option<I32<W>> {
        Some(I32(self.load_extended::<32>(addr, 1, ExtendKind::Zero, concrete, symbolic_mask)?))
    }

    /// Mixed `i32.load8_s`.
    pub fn load_i32_8s_mixed(&self, addr: u32, concrete: u64, symbolic_mask: u8) -> Option<I32<W>> {
        Some(I32(self.load_extended::<32>(addr, 1, ExtendKind::Sign, concrete, symbolic_mask)?))
    }

    /// Mixed `i32.load16_u`.
    pub fn load_i32_16u_mixed(&self, addr: u32, concrete: u64, symbolic_mask: u8) -> Option<I32<W>> {
        Some(I32(self.load_extended::<32>(addr, 2, ExtendKind::Zero, concrete, symbolic_mask)?))
    }

    /// Mixed `i32.load16_s`.
    pub fn load_i32_16s_mixed(&self, addr: u32, concrete: u64, symbolic_mask: u8) -> Option<I32<W>> {
        Some(I32(self.load_extended::<32>(addr, 2, ExtendKind::Sign, concrete, symbolic_mask)?))
    }

    /// Mixed `i64.load8_u`.
    pub fn load_i64_8u_mixed(&self, addr: u32, concrete: u64, symbolic_mask: u8) -> Option<I64<W>> {
        Some(I64(self.load_extended::<64>(addr, 1, ExtendKind::Zero, concrete, symbolic_mask)?))
    }

    /// Mixed `i64.load8_s`.
    pub fn load_i64_8s_mixed(&self, addr: u32, concrete: u64, symbolic_mask: u8) -> Option<I64<W>> {
        Some(I64(self.load_extended::<64>(addr, 1, ExtendKind::Sign, concrete, symbolic_mask)?))
    }

    /// Mixed `i64.load16_u`.
    pub fn load_i64_16u_mixed(&self, addr: u32, concrete: u64, symbolic_mask: u8) -> Option<I64<W>> {
        Some(I64(self.load_extended::<64>(addr, 2, ExtendKind::Zero, concrete, symbolic_mask)?))
    }

    /// Mixed `i64.load16_s`.
    pub fn load_i64_16s_mixed(&self, addr: u32, concrete: u64, symbolic_mask: u8) -> Option<I64<W>> {
        Some(I64(self.load_extended::<64>(addr, 2, ExtendKind::Sign, concrete, symbolic_mask)?))
    }

    /// Mixed `i64.load32_u`.
    pub fn load_i64_32u_mixed(&self, addr: u32, concrete: u64, symbolic_mask: u8) -> Option<I64<W>> {
        Some(I64(self.load_extended::<64>(addr, 4, ExtendKind::Zero, concrete, symbolic_mask)?))
    }

    /// Mixed `i64.load32_s`.
    pub fn load_i64_32s_mixed(&self, addr: u32, concrete: u64, symbolic_mask: u8) -> Option<I64<W>> {
        Some(I64(self.load_extended::<64>(addr, 4, ExtendKind::Sign, concrete, symbolic_mask)?))
    }

    /// `i32.store`: 4 little-endian bytes.
    pub fn store_i32(&mut self, addr: u32, value: &I32<W>) {
        self.write_bytes(addr, &value.to_le_bytes());
    }

    /// `i64.store`: 8 little-endian bytes.
    pub fn store_i64(&mut self, addr: u32, value: &I64<W>) {
        self.write_bytes(addr, &value.to_le_bytes());
    }

    /// `f32.store`: 4 little-endian bytes.
    pub fn store_f32(&mut self, addr: u32, value: &F32<W>) {
        self.write_bytes(addr, &value.to_le_bytes());
    }

    /// `f64.store`: 8 little-endian bytes.
    pub fn store_f64(&mut self, addr: u32, value: &F64<W>) {
        self.write_bytes(addr, &value.to_le_bytes());
    }

    /// `i32.store8`: low byte of an [`I32`].
    pub fn store_i32_8(&mut self, addr: u32, value: &I32<W>) {
        self.write_bytes(addr, &value.to_le_bytes()[..1]);
    }

    /// `i32.store16`: low 2 bytes of an [`I32`].
    pub fn store_i32_16(&mut self, addr: u32, value: &I32<W>) {
        self.write_bytes(addr, &value.to_le_bytes()[..2]);
    }

    /// `i64.store8`: low byte of an [`I64`].
    pub fn store_i64_8(&mut self, addr: u32, value: &I64<W>) {
        self.write_bytes(addr, &value.to_le_bytes()[..1]);
    }

    /// `i64.store16`: low 2 bytes of an [`I64`].
    pub fn store_i64_16(&mut self, addr: u32, value: &I64<W>) {
        self.write_bytes(addr, &value.to_le_bytes()[..2]);
    }

    /// `i64.store32`: low 4 bytes of an [`I64`].
    pub fn store_i64_32(&mut self, addr: u32, value: &I64<W>) {
        self.write_bytes(addr, &value.to_le_bytes()[..4]);
    }

    // -- internals --

    /// Byte `i` of a load starting at `addr`: read from committed memory when
    /// bit `i` of `symbolic_mask` is set, otherwise built as a transient public
    /// byte from `concrete` (no map insertion). Returns `None` for an absent
    /// committed byte.
    fn mixed_byte(
        &self,
        addr: u32,
        i: usize,
        concrete: u64,
        symbolic_mask: u8,
    ) -> Option<Byte<W>> {
        if symbolic_mask & (1 << i) != 0 {
            self.inner.get(&(addr + i as u32)).copied()
        } else {
            Some(self.public_byte((concrete >> (i * 8)) as u8))
        }
    }

    /// Read `N` consecutive bytes starting at `addr`, each committed or public
    /// per `symbolic_mask` (see [`Self::mixed_byte`]). Returns `None` if a
    /// committed byte is absent.
    fn read_bytes<const N: usize>(
        &self,
        addr: u32,
        concrete: u64,
        symbolic_mask: u8,
    ) -> Option<[Byte<W>; N]> {
        let mut out = [self.public_byte(0); N];
        for (i, slot) in out.iter_mut().enumerate() {
            *slot = self.mixed_byte(addr, i, concrete, symbolic_mask)?;
        }
        Some(out)
    }

    /// Read `n_bytes` consecutive bytes starting at `addr` (each committed or
    /// public per `symbolic_mask`) and extend to `[Bit; N]` per `kind`.
    /// Zero-extension fills with the public-0 bit; sign-extension replicates the
    /// high bit of the last byte (bit 7 of the byte at `addr + n_bytes - 1`).
    fn load_extended<const N: usize>(
        &self,
        addr: u32,
        n_bytes: u32,
        kind: ExtendKind,
        concrete: u64,
        symbolic_mask: u8,
    ) -> Option<[Bit<W>; N]> {
        let payload = (n_bytes as usize) * 8;
        debug_assert!(payload <= N);
        let mut out = [self.zero; N];
        for i in 0..n_bytes as usize {
            let byte = self.mixed_byte(addr, i, concrete, symbolic_mask)?;
            out[i * 8..(i + 1) * 8].copy_from_slice(byte.bits());
        }
        let fill = match kind {
            ExtendKind::Zero => self.zero,
            ExtendKind::Sign => out[payload - 1],
        };
        for slot in out[payload..].iter_mut() {
            *slot = fill;
        }
        Some(out)
    }

    /// Write `bytes.len()` consecutive bytes starting at `addr`.
    fn write_bytes(&mut self, addr: u32, bytes: &[Byte<W>]) {
        for (i, byte) in bytes.iter().enumerate() {
            self.inner.insert(addr + i as u32, *byte);
        }
    }
}

#[derive(Clone, Copy)]
enum ExtendKind {
    Zero,
    Sign,
}

#[cfg(test)]
mod tests {
    use super::*;

    // Public-0/1 wires for the tests; any two distinct values work.
    const ZERO: Bit = Bit(Gf2_128::new(0));
    const ONE: Bit = Bit(Gf2_128::new(1));

    fn mem() -> LinearMemory {
        LinearMemory::new(ZERO, ONE)
    }

    #[test]
    fn set_and_get_byte() {
        let mut m = mem();
        assert!(m.get_byte(0x100).is_none());
        m.set_public_byte(0x100, 0xab);
        assert_eq!(byte_to_u8(m.get_byte(0x100).unwrap()), 0xab);
        m.set_public_byte(0x100, 0xcd);
        assert_eq!(byte_to_u8(m.get_byte(0x100).unwrap()), 0xcd);
    }

    #[test]
    fn keeps_addresses_independent() {
        let mut m = mem();
        m.set_public_byte(0, 1);
        m.set_public_byte(1, 2);
        m.set_public_byte(0xff_ff_ff_ff, 3);
        assert_eq!(byte_to_u8(m.get_byte(0).unwrap()), 1);
        assert_eq!(byte_to_u8(m.get_byte(1).unwrap()), 2);
        assert_eq!(byte_to_u8(m.get_byte(0xff_ff_ff_ff).unwrap()), 3);
    }

    // -- helpers: decode public-bit bytes back to integers --

    fn byte_to_u8(byte: &Byte) -> u8 {
        let mut v = 0u8;
        for (i, b) in byte.bits().iter().enumerate() {
            if *b == ONE {
                v |= 1 << i;
            } else {
                assert_eq!(*b, ZERO);
            }
        }
        v
    }

    fn bits_to_u32(bits: &[Bit]) -> u32 {
        assert_eq!(bits.len(), 32);
        let mut v = 0u32;
        for (i, b) in bits.iter().enumerate() {
            if *b == ONE {
                v |= 1 << i;
            } else {
                assert_eq!(*b, ZERO);
            }
        }
        v
    }

    fn bits_to_u64(bits: &[Bit]) -> u64 {
        assert_eq!(bits.len(), 64);
        let mut v = 0u64;
        for (i, b) in bits.iter().enumerate() {
            if *b == ONE {
                v |= 1 << i;
            } else {
                assert_eq!(*b, ZERO);
            }
        }
        v
    }

    fn write_le_bytes(m: &mut LinearMemory, addr: u32, bytes: &[u8]) {
        for (i, b) in bytes.iter().enumerate() {
            m.set_public_byte(addr + i as u32, *b);
        }
    }

    #[test]
    fn load_i32_concatenates_bytes_little_endian() {
        let mut m = mem();
        write_le_bytes(&mut m, 100, &[0x78, 0x56, 0x34, 0x12]);
        let v = m.load_i32(100).unwrap();
        assert_eq!(bits_to_u32(v.bits()), 0x1234_5678);
    }

    #[test]
    fn load_i32_mixed_combines_committed_and_public() {
        let mut m = mem();
        // Low two bytes are committed in the map; high two are public, supplied
        // inline via `concrete` with their mask bits clear.
        write_le_bytes(&mut m, 0, &[0x78, 0x56]);
        let v = m.load_i32_mixed(0, 0x1234_0000, 0b0000_0011).unwrap();
        assert_eq!(bits_to_u32(v.bits()), 0x1234_5678);
    }

    #[test]
    fn load_i32_returns_none_on_missing_byte() {
        let mut m = mem();
        write_le_bytes(&mut m, 0, &[1, 2, 3]); // only 3 of 4 bytes
        assert!(m.load_i32(0).is_none());
    }

    #[test]
    fn load_f32_has_same_wire_shape_as_i32() {
        let mut m = mem();
        write_le_bytes(&mut m, 0, &[0xaa, 0xbb, 0xcc, 0xdd]);
        let i = m.load_i32(0).unwrap();
        let f = m.load_f32(0).unwrap();
        assert_eq!(bits_to_u32(i.bits()), bits_to_u32(f.bits()));
    }

    #[test]
    fn load_i64_concatenates_bytes_little_endian() {
        let mut m = mem();
        write_le_bytes(&mut m, 0, &[0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01]);
        let v = m.load_i64(0).unwrap();
        assert_eq!(bits_to_u64(v.bits()), 0x0123_4567_89ab_cdef);
    }

    #[test]
    fn load_i32_8u_zero_extends() {
        let mut m = mem();
        write_le_bytes(&mut m, 0, &[0xff]);
        let v = m.load_i32_8u(0).unwrap();
        assert_eq!(bits_to_u32(v.bits()), 0x0000_00ff);
    }

    #[test]
    fn load_i32_8s_sign_extends_when_high_bit_set() {
        let mut m = mem();
        write_le_bytes(&mut m, 0, &[0xff]);
        let v = m.load_i32_8s(0).unwrap();
        assert_eq!(bits_to_u32(v.bits()), 0xffff_ffff);
    }

    #[test]
    fn load_i32_8s_zero_extends_when_high_bit_clear() {
        let mut m = mem();
        write_le_bytes(&mut m, 0, &[0x7f]);
        let v = m.load_i32_8s(0).unwrap();
        assert_eq!(bits_to_u32(v.bits()), 0x0000_007f);
    }

    #[test]
    fn load_i32_16s_sign_extends_from_bit_15() {
        let mut m = mem();
        write_le_bytes(&mut m, 0, &[0x00, 0x80]); // 0x8000, high bit set
        let v = m.load_i32_16s(0).unwrap();
        assert_eq!(bits_to_u32(v.bits()), 0xffff_8000);
    }

    #[test]
    fn load_i64_32s_sign_extends_from_bit_31() {
        let mut m = mem();
        write_le_bytes(&mut m, 0, &[0x00, 0x00, 0x00, 0x80]);
        let v = m.load_i64_32s(0).unwrap();
        assert_eq!(bits_to_u64(v.bits()), 0xffff_ffff_8000_0000);
    }

    #[test]
    fn load_i64_32u_zero_extends() {
        let mut m = mem();
        write_le_bytes(&mut m, 0, &[0xff, 0xff, 0xff, 0xff]);
        let v = m.load_i64_32u(0).unwrap();
        assert_eq!(bits_to_u64(v.bits()), 0x0000_0000_ffff_ffff);
    }

    #[test]
    fn store_i32_then_load_round_trips() {
        let mut m = mem();
        write_le_bytes(&mut m, 0, &[0x78, 0x56, 0x34, 0x12]);
        let v = m.load_i32(0).unwrap();
        m.store_i32(100, &v);
        let back = m.load_i32(100).unwrap();
        assert_eq!(bits_to_u32(back.bits()), 0x1234_5678);
        for (i, want) in [0x78u8, 0x56, 0x34, 0x12].into_iter().enumerate() {
            let byte = m.get_byte(100 + i as u32).unwrap();
            assert_eq!(byte_to_u8(byte), want);
        }
    }

    #[test]
    fn store_i32_8_writes_only_the_low_byte() {
        let mut m = mem();
        write_le_bytes(&mut m, 0, &[0x78, 0x56, 0x34, 0x12]);
        let v = m.load_i32(0).unwrap();
        m.store_i32_8(50, &v);
        assert_eq!(byte_to_u8(m.get_byte(50).unwrap()), 0x78);
        assert!(m.get_byte(51).is_none());
    }

    #[test]
    fn store_i32_16_writes_low_two_bytes_le() {
        let mut m = mem();
        write_le_bytes(&mut m, 0, &[0x78, 0x56, 0x34, 0x12]);
        let v = m.load_i32(0).unwrap();
        m.store_i32_16(50, &v);
        assert_eq!(byte_to_u8(m.get_byte(50).unwrap()), 0x78);
        assert_eq!(byte_to_u8(m.get_byte(51).unwrap()), 0x56);
        assert!(m.get_byte(52).is_none());
    }

    #[test]
    fn store_i64_32_writes_low_four_bytes_le() {
        let mut m = mem();
        write_le_bytes(&mut m, 0, &[0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01]);
        let v = m.load_i64(0).unwrap();
        m.store_i64_32(100, &v);
        assert_eq!(byte_to_u8(m.get_byte(100).unwrap()), 0xef);
        assert_eq!(byte_to_u8(m.get_byte(101).unwrap()), 0xcd);
        assert_eq!(byte_to_u8(m.get_byte(102).unwrap()), 0xab);
        assert_eq!(byte_to_u8(m.get_byte(103).unwrap()), 0x89);
        assert!(m.get_byte(104).is_none());
    }
}
