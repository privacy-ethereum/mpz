//! IT-MAC authenticated values, generic over the wire representation `W`.
//!
//! [`Bit`] wraps a single wire of type `W`. The default and only
//! protocol instantiation is `W = Gf2_128`, where on the prover a `Bit`
//! is a MAC and on the verifier the matching authentication key, using
//! the LSB-of-MAC pointer-bit convention (the LSB of the inner
//! `Gf2_128` carries the authenticated bit value).
//!
//! The wire type only has to satisfy [`Wire`] — a purely structural
//! bound (copy, addition, and the zerocopy traits needed to view a
//! `[Bit<W>]` as a raw `[W]`). Everything protocol-specific — the
//! [`MAC_ZERO`]/[`MAC_ONE`] constants, the pointer-bit accessor, the
//! `u128` constructor, and the `Default` encoding of a public-zero wire
//! — lives only on the concrete `Bit<Gf2_128>` instantiation.
//!
//! [`I32`], [`I64`], [`F32`], [`F64`] are width-pinned newtype wrappers
//! around bit arrays — one per WASM primitive type — carrying the
//! conversions between flat bit storage and the byte representation used
//! by linear memory (`from_le_bytes` / `to_le_bytes`), and converting
//! into the typed [`AuthValue`] enum when the type tag matters.
//!
//! These are pure generic containers over the wire type `W`: nothing here
//! encodes the IT-MAC pointer-bit convention or the public-0/1 wire
//! values. Callers that need those supply them explicitly (see
//! [`LinearMemory::new`](crate::LinearMemory::new)).

use mpz_fields::gf2_128::Gf2_128;
use mpz_vm_ir::ValType;
use thiserror::Error;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

/// Structural requirements on a wire type: it must be `Copy` and
/// zerocopy-castable so a `[Bit<W>]` can be viewed as a raw `[W]` at the
/// boundary with crates that work in raw wires. Blanket-implemented for
/// every conforming type.
pub trait Wire: Copy + FromBytes + IntoBytes + Immutable + KnownLayout {}

impl<W> Wire for W where W: Copy + FromBytes + IntoBytes + Immutable + KnownLayout {}

/// Per-bit authenticated value over wire type `W`. `repr(transparent)`
/// over `W` with the matching zerocopy derives, so an array of `Bit<W>`s
/// can be cast to an array of `W`s (and vice versa).
#[repr(transparent)]
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    zerocopy::FromBytes,
    zerocopy::IntoBytes,
    zerocopy::Immutable,
    zerocopy::KnownLayout,
)]
pub struct Bit<W = Gf2_128>(pub W);

impl<W: Wire> Bit<W> {
    /// View a slice of `Bit<W>` as raw `W` without copying, for handing
    /// wires to crates that operate on raw `W` directly. `Bit<W>` is
    /// `repr(transparent)` over `W`, so the cast is layout-preserving and
    /// infallible.
    pub(crate) fn cast_slice(bits: &[Bit<W>]) -> &[W] {
        <[W]>::ref_from_bytes(bits.as_bytes()).expect("Bit is repr(transparent) over W")
    }

    /// Inverse of [`Bit::cast_slice`]: view raw `W` wires as `Bit<W>`s.
    pub(crate) fn wrap_slice(raw: &[W]) -> &[Bit<W>] {
        <[Bit<W>]>::ref_from_bytes(raw.as_bytes()).expect("Bit is repr(transparent) over W")
    }
}

impl<W> From<W> for Bit<W> {
    fn from(w: W) -> Self {
        Self(w)
    }
}

/// One memory byte's worth of [`Bit`]s, indexed least-significant bit
/// first.
///
/// `Byte` is the unit of linear-memory storage: every WASM load/store
/// touches some integral number of `Byte`s. The LSB-first indexing of
/// the underlying `[Bit; 8]` matches the little-endian layout used by
/// [`I32::from_le_bytes`] and friends, so concatenating `n` `Byte`s
/// produces a value whose bit `i` is bit `i % 8` of byte `i / 8`.
#[repr(transparent)]
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    zerocopy::FromBytes,
    zerocopy::IntoBytes,
    zerocopy::Immutable,
    zerocopy::KnownLayout,
)]
pub struct Byte<W = Gf2_128>(pub [Bit<W>; 8]);

impl<W> Byte<W> {
    /// Construct from a flat `[Bit; 8]` (LSB first).
    pub const fn new(bits: [Bit<W>; 8]) -> Self {
        Self(bits)
    }

    /// Borrow the underlying `[Bit; 8]`.
    pub fn bits(&self) -> &[Bit<W>; 8] {
        &self.0
    }

    /// Mutable access to the underlying `[Bit; 8]`.
    pub fn bits_mut(&mut self) -> &mut [Bit<W>; 8] {
        &mut self.0
    }
}

impl<W> AsRef<[Bit<W>]> for Byte<W> {
    fn as_ref(&self) -> &[Bit<W>] {
        &self.0
    }
}

/// Width-pinned [`Bit`] bundle for one WASM primitive type, generic over
/// the wire `W`.
///
/// Defines the newtype, its constructor, accessors, and the
/// little-endian byte conversions used when crossing the
/// register/linear-memory boundary. `from_le_bytes` packs `BYTES`
/// [`Byte`]s (each indexed LSB-first) into a flat `[Bit; BITS]`;
/// `to_le_bytes` is the inverse. These are pure wire routing — no
/// `Context` is involved.
macro_rules! wasm_value {
    ($name:ident, $bits:literal, $bytes:literal, $ty:expr) => {
        #[doc = concat!("Authenticated WASM `", stringify!($name), "` value (",
                                stringify!($bits), " bits / ", stringify!($bytes), " bytes).")]
        #[repr(transparent)]
        #[derive(
            Debug,
            Clone,
            Copy,
            zerocopy::FromBytes,
            zerocopy::IntoBytes,
            zerocopy::Immutable,
            zerocopy::KnownLayout,
        )]
        pub struct $name<W = Gf2_128>(pub [Bit<W>; $bits]);

        impl<W: Wire> $name<W> {
            /// Bit-width of this value type.
            pub const WIDTH: usize = $bits;
            /// Byte-width of this value type.
            pub const BYTES: usize = $bytes;
            /// WASM `ValType` tag.
            pub const TY: ValType = $ty;

            /// Construct from a flat bit array.
            pub fn new(bits: [Bit<W>; $bits]) -> Self {
                Self(bits)
            }

            /// Borrow the underlying bit array.
            pub fn bits(&self) -> &[Bit<W>; $bits] {
                &self.0
            }

            /// Pack `BYTES` little-endian [`Byte`]s into a value.
            /// Byte `i` occupies bits `[i*8, i*8 + 8)`.
            pub fn from_le_bytes(bytes: [Byte<W>; $bytes]) -> Self {
                Self(core::array::from_fn(|i| bytes[i / 8].bits()[i % 8]))
            }

            /// Slice the value into `BYTES` little-endian [`Byte`]s.
            /// Inverse of [`Self::from_le_bytes`].
            pub fn to_le_bytes(&self) -> [Byte<W>; $bytes] {
                core::array::from_fn(|i| Byte::new(core::array::from_fn(|j| self.0[i * 8 + j])))
            }

            /// View the value's bits as a raw `W` wire array, for handing
            /// to a `Context` that operates on raw `W`. The inverse is
            /// `From<[W; WIDTH]>`.
            pub fn to_wires(&self) -> [W; $bits] {
                Bit::cast_slice(&self.0)
                    .try_into()
                    .expect("slice is WIDTH wide")
            }
        }

        impl<W: Wire> From<$name<W>> for AuthValue<W> {
            fn from(v: $name<W>) -> Self {
                AuthValue::$name(v)
            }
        }

        impl<W: Wire> From<[W; $bits]> for $name<W> {
            fn from(wires: [W; $bits]) -> Self {
                Self(Bit::wrap_slice(&wires).try_into().expect("slice is WIDTH wide"))
            }
        }
    };
}

wasm_value!(I32, 32, 4, ValType::I32);
wasm_value!(I64, 64, 8, ValType::I64);
wasm_value!(F32, 32, 4, ValType::F32);
wasm_value!(F64, 64, 8, ValType::F64);

/// Authenticated register value: a typed bundle of [`Bit`]s mirroring
/// [`mpz_vm_core::value::Value`]. The variant pins both the bit-width
/// and the WASM type the bits represent.
#[derive(Debug, Clone)]
pub enum AuthValue<W = Gf2_128> {
    I32(I32<W>),
    I64(I64<W>),
    F32(F32<W>),
    F64(F64<W>),
}

/// Width-mismatch raised by [`AuthValue::from_bits`].
#[derive(Debug, Error)]
#[error("AuthValue::from_bits({ty:?}): expected {want} bits, got {got}")]
pub struct AuthValueWidth {
    pub ty: ValType,
    pub want: usize,
    pub got: usize,
}

/// Wrong-variant error from the typed `AuthValue::try_*` accessors.
#[derive(Debug, Error)]
#[error("AuthValue is {got:?}, expected {expected:?}")]
pub struct AuthValueType {
    pub expected: ValType,
    pub got: ValType,
}

impl<W: Wire> AuthValue<W> {
    /// WASM type of the underlying value.
    pub fn ty(&self) -> ValType {
        match self {
            AuthValue::I32(_) => ValType::I32,
            AuthValue::I64(_) => ValType::I64,
            AuthValue::F32(_) => ValType::F32,
            AuthValue::F64(_) => ValType::F64,
        }
    }

    /// Bit-width of the underlying value.
    pub fn width(&self) -> usize {
        match self {
            AuthValue::I32(_) | AuthValue::F32(_) => 32,
            AuthValue::I64(_) | AuthValue::F64(_) => 64,
        }
    }

    /// Per-bit authenticated bits as a flat slice.
    pub fn bits(&self) -> &[Bit<W>] {
        match self {
            AuthValue::I32(v) => v.bits(),
            AuthValue::I64(v) => v.bits(),
            AuthValue::F32(v) => v.bits(),
            AuthValue::F64(v) => v.bits(),
        }
    }

    /// Build from a flat per-bit slice. Errors if `bits.len()` doesn't
    /// match `ty`'s width.
    pub fn from_bits(ty: ValType, bits: &[Bit<W>]) -> Result<Self, AuthValueWidth> {
        let want = ty_width(ty);
        if bits.len() != want {
            return Err(AuthValueWidth {
                ty,
                want,
                got: bits.len(),
            });
        }
        Ok(match ty {
            ValType::I32 => AuthValue::I32(I32(bits.try_into().expect("checked"))),
            ValType::I64 => AuthValue::I64(I64(bits.try_into().expect("checked"))),
            ValType::F32 => AuthValue::F32(F32(bits.try_into().expect("checked"))),
            ValType::F64 => AuthValue::F64(F64(bits.try_into().expect("checked"))),
        })
    }

    /// Borrow the inner [`I32`], or `AuthValueType` if the variant
    /// differs.
    pub fn try_as_i32(&self) -> Result<&I32<W>, AuthValueType> {
        match self {
            AuthValue::I32(v) => Ok(v),
            _ => Err(AuthValueType {
                expected: ValType::I32,
                got: self.ty(),
            }),
        }
    }

    /// Consume into the inner [`I32`], or `AuthValueType` if the variant
    /// differs.
    pub fn try_into_i32(self) -> Result<I32<W>, AuthValueType> {
        let got = self.ty();
        match self {
            AuthValue::I32(v) => Ok(v),
            _ => Err(AuthValueType {
                expected: ValType::I32,
                got,
            }),
        }
    }

    /// Borrow the inner [`I64`], or `AuthValueType` if the variant
    /// differs.
    pub fn try_as_i64(&self) -> Result<&I64<W>, AuthValueType> {
        match self {
            AuthValue::I64(v) => Ok(v),
            _ => Err(AuthValueType {
                expected: ValType::I64,
                got: self.ty(),
            }),
        }
    }

    /// Consume into the inner [`I64`], or `AuthValueType` if the variant
    /// differs.
    pub fn try_into_i64(self) -> Result<I64<W>, AuthValueType> {
        let got = self.ty();
        match self {
            AuthValue::I64(v) => Ok(v),
            _ => Err(AuthValueType {
                expected: ValType::I64,
                got,
            }),
        }
    }
}

#[inline]
fn ty_width(ty: ValType) -> usize {
    match ty {
        ValType::I32 | ValType::F32 => 32,
        ValType::I64 | ValType::F64 => 64,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bit(i: u128) -> Bit {
        Bit(Gf2_128::new(i))
    }

    #[test]
    fn auth_value_round_trips_through_from_bits() {
        let bits: Vec<Bit> = (0..32).map(|i| bit(i as u128)).collect();
        let av = AuthValue::from_bits(ValType::I32, &bits).unwrap();
        assert_eq!(av.ty(), ValType::I32);
        assert_eq!(av.width(), 32);
        assert_eq!(av.bits(), bits.as_slice());
    }

    #[test]
    fn from_bits_rejects_width_mismatch() {
        let bits = vec![bit(0); 31];
        assert!(AuthValue::from_bits(ValType::I32, &bits).is_err());
        let bits = vec![bit(0); 64];
        assert!(AuthValue::from_bits(ValType::I32, &bits).is_err());
    }

    #[test]
    fn each_variant_reports_correct_width() {
        for (ty, w) in [
            (ValType::I32, 32),
            (ValType::I64, 64),
            (ValType::F32, 32),
            (ValType::F64, 64),
        ] {
            let bits = vec![bit(0); w];
            let av = AuthValue::from_bits(ty, &bits).unwrap();
            assert_eq!(av.ty(), ty);
            assert_eq!(av.width(), w);
            assert_eq!(av.bits().len(), w);
        }
    }

    #[test]
    fn cast_slice_round_trips() {
        let bits: Vec<Bit> = (0..8).map(|i| bit(i as u128)).collect();
        let raw = Bit::cast_slice(&bits);
        assert_eq!(raw.len(), bits.len());
        for (b, g) in bits.iter().zip(raw) {
            assert_eq!(&b.0, g);
        }
        assert_eq!(Bit::wrap_slice(raw), bits.as_slice());
    }

    // -------- newtype tests --------

    #[test]
    fn i32_le_bytes_round_trip() {
        let mut bytes = [Byte::new([bit(0); 8]); 4];
        for (i, byte) in bytes.iter_mut().enumerate() {
            for (j, b) in byte.bits_mut().iter_mut().enumerate() {
                *b = bit(((i * 8 + j) as u128) + 1);
            }
        }
        let v = I32::from_le_bytes(bytes);
        assert_eq!(v.to_le_bytes(), bytes);
    }

    #[test]
    fn i64_le_bytes_round_trip() {
        let mut bytes = [Byte::new([bit(0); 8]); 8];
        for (i, byte) in bytes.iter_mut().enumerate() {
            for (j, b) in byte.bits_mut().iter_mut().enumerate() {
                *b = bit(((i * 8 + j) as u128) + 1);
            }
        }
        let v = I64::from_le_bytes(bytes);
        assert_eq!(v.to_le_bytes(), bytes);
    }

    #[test]
    fn newtype_into_auth_value_keeps_bits() {
        let bits = [bit(1); 32];
        let v = I32::new(bits);
        let av: AuthValue = v.into();
        assert_eq!(av.ty(), ValType::I32);
        assert_eq!(av.bits(), &bits);
    }

    #[test]
    fn type_constants_match_ty() {
        assert_eq!(I32::<Gf2_128>::TY, ValType::I32);
        assert_eq!(I64::<Gf2_128>::TY, ValType::I64);
        assert_eq!(F32::<Gf2_128>::TY, ValType::F32);
        assert_eq!(F64::<Gf2_128>::TY, ValType::F64);
        assert_eq!(I32::<Gf2_128>::WIDTH, 32);
        assert_eq!(I64::<Gf2_128>::WIDTH, 64);
        assert_eq!(F32::<Gf2_128>::BYTES, 4);
        assert_eq!(F64::<Gf2_128>::BYTES, 8);
    }
}
