use std::sync::Arc;

use mpz_circuits::circuits::xor;
use mpz_memory_core::{Memory, MemoryExt, MemoryType, Repr, View, ViewExt};

use crate::{Call, Callable, CallableExt, VmError};

/// Extension trait for applying one-time pads.
pub trait OneTimePad<T: MemoryType>:
    Memory<T, Error = VmError> + View<T, Error = VmError> + Callable<T>
{
    /// Masks the value with the provided one-time pad.
    ///
    /// # Arguments
    ///
    /// * `value` - The value to mask.
    /// * `otp` - The one-time pad to mask the value.
    fn mask_private<R>(&mut self, value: R, otp: R::Clear) -> Result<R, VmError>
    where
        R: Repr<T> + Copy,
    {
        let size = value.to_raw().len();
        let otp_ref = R::from_raw(self.alloc_raw(size)?);
        self.mark_private(otp_ref)?;
        self.assign(otp_ref, otp)?;
        self.commit(otp_ref)?;

        let masked: R = self.call(
            Call::builder(Arc::new(xor(size)))
                .arg(value)
                .arg(otp_ref)
                .build()
                .expect("call should be valid"),
        )?;

        Ok(masked)
    }

    /// Masks the value blinded.
    ///
    /// # Arguments
    ///
    /// * `value` - The value to mask.
    fn mask_blind<R>(&mut self, value: R) -> Result<R, VmError>
    where
        R: Repr<T> + Copy,
    {
        let size = value.to_raw().len();
        let otp_ref = R::from_raw(self.alloc_raw(size)?);
        self.mark_blind(otp_ref)?;
        self.commit(otp_ref)?;

        let masked: R = self.call(
            Call::builder(Arc::new(xor(size)))
                .arg(value)
                .arg(otp_ref)
                .build()
                .expect("call should be valid"),
        )?;

        Ok(masked)
    }
}

impl<T, U> OneTimePad<U> for T
where
    T: ?Sized + Memory<U, Error = VmError> + View<U, Error = VmError> + Callable<U>,
    U: MemoryType,
{
}

#[cfg(test)]
mod tests {
    use mpz_memory_core::{
        Vector,
        binary::{Binary, U8},
    };

    use super::*;

    // Compile-time API conformance check for OneTimePad::mask_private over U8 and
    // Vector<U8>. Intentionally not a runtime test; ensures the generic bounds
    // and signatures remain valid.
    fn compile_check_otp() {
        fn single<Vm: OneTimePad<Binary>>(vm: &mut Vm, value: U8) {
            vm.mask_private(value, 0u8).unwrap();
        }

        fn vec<Vm: OneTimePad<Binary>>(vm: &mut Vm, value: Vector<U8>) {
            vm.mask_private(value, vec![0u8; 2]).unwrap();
        }
    }
}
