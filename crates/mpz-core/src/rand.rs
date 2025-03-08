//! Rand utilities.

/// Rand 0.9 compatibility trait.
pub trait Rand0_8Compat {
    /// Wraps `self` in a compatibility wrapper that implements `0.9` traits.
    fn compat(self) -> Rand0_8CompatWrapper<Self>;
}

/// Rand 0.9 compatibility wrapper.
pub struct Rand0_8CompatWrapper<R: ?Sized>(R);
