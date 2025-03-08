//! Rand utilities.

/// Rand 0.8 compatibility trait.
pub trait Rand0_8CompatExt {
    /// Wraps `self` in a compatibility wrapper that implements `0.8` traits.
    fn compat(self) -> Rand0_8CompatWrapper<Self>
    where
        Self: Sized,
    {
        Rand0_8CompatWrapper(self)
    }

    /// Wraps `self` in a compatibility wrapper that implements `0.8` traits.
    fn compat_by_ref(&mut self) -> Rand0_8CompatWrapper<&mut Self>
    where
        Self: Sized,
    {
        Rand0_8CompatWrapper(self)
    }
}

impl<T> Rand0_8CompatExt for T where T: ?Sized {}

/// Rand 0.9 compatibility wrapper.
pub struct Rand0_8CompatWrapper<R: ?Sized>(R);

impl<R> Rand0_8CompatWrapper<R> {
    /// Creates a new compatibility wrapper.
    pub fn new(inner: R) -> Self {
        Self(inner)
    }

    /// Returns the inner value.
    pub fn into_inner(self) -> R {
        self.0
    }
}

impl<R> rand_core_06::RngCore for Rand0_8CompatWrapper<R>
where
    R: rand_core::RngCore + ?Sized,
{
    fn next_u32(&mut self) -> u32 {
        self.0.next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        self.0.next_u64()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.fill_bytes(dest)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core_06::Error> {
        self.0.fill_bytes(dest);
        Ok(())
    }
}

impl<R> rand_core_06::CryptoRng for Rand0_8CompatWrapper<R> where R: rand_core::CryptoRng + ?Sized {}
