use std::sync::Arc;

use mpz_circuits::{Circuit, CircuitBuilder};
use mpz_memory_core::{
    DecodeFutureTyped, Memory, MemoryExt, MemoryType, Repr, StaticSize, View, ViewExt,
};

use crate::{Call, Callable, CallableExt, VmError};

/// Extension trait for decoding.
pub trait DecodeExt<T: MemoryType>:
    Memory<T, Error = VmError> + View<T, Error = VmError> + Callable<T>
{
    /// Decodes the value privately.
    ///
    /// Returns a future which will resolve to the masked value when it is
    /// ready.
    ///
    /// # Arguments
    ///
    /// * `value` - The value to decode.
    /// * `otp` - The one-time pad to mask the value.
    fn decode_private<R>(
        &mut self,
        value: R,
        otp: R::Clear,
    ) -> Result<DecodeFutureTyped<T::Raw, R::Clear>, VmError>
    where
        R: Repr<T> + StaticSize<T> + Copy,
    {
        let otp_ref = self.alloc::<R>()?;
        self.mark_private(otp_ref)?;
        self.assign(otp_ref, otp)?;
        self.commit(otp_ref)?;

        let masked: R = self.call(
            Call::new(build_otp(R::SIZE))
                .arg(value)
                .arg(otp_ref)
                .build()
                .expect("call should be valid"),
        )?;

        self.decode(masked)
    }

    /// Decodes the value blindly.
    ///
    /// Returns a future which will resolve to the masked value when it is
    /// ready.
    ///
    /// # Arguments
    ///
    /// * `value` - The value to decode.
    fn decode_blind<R>(&mut self, value: R) -> Result<DecodeFutureTyped<T::Raw, R::Clear>, VmError>
    where
        R: Repr<T> + StaticSize<T> + Copy,
    {
        let otp_ref = self.alloc::<R>()?;
        self.mark_blind(otp_ref)?;
        self.commit(otp_ref)?;

        let masked: R = self.call(
            Call::new(build_otp(R::SIZE))
                .arg(value)
                .arg(otp_ref)
                .build()
                .expect("call should be valid"),
        )?;

        self.decode(masked)
    }
}

impl<T, U> DecodeExt<U> for T
where
    T: Memory<U, Error = VmError> + View<U, Error = VmError> + Callable<U>,
    U: MemoryType,
{
}

/// Builds a circuit for applying one-time pads.
fn build_otp(size: usize) -> Arc<Circuit> {
    let builder = CircuitBuilder::new();

    for _ in 0..size {
        let input = builder.add_input::<bool>();
        let otp = builder.add_input::<bool>();
        builder.add_output(input ^ otp);
    }

    let circ = builder.build().expect("circuit should be valid");

    Arc::new(circ)
}
