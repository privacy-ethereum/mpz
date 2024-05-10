//! Implementation of protocol COPEe <https://eprint.iacr.org/2016/505> page 10.
//!
//! We use this construction to implement batch OLE instead of VOLE, which means that we do not use PRGs,
//! i.e. Extend can only be called once.
//!
//! Note that this is an OLE with errors implementation.

mod receiver;
mod sender;

pub use receiver::COPEeReceiver;
pub use sender::COPEeSender;

use mpz_fields::Field;

/// Workaround because of feature `generic_const_exprs` not available in stable.
///
/// This is used to check at compile-time that the correct const-generic implementation is used for
/// a specific field.
struct Check<const N: usize, F: Field>(std::marker::PhantomData<F>);

impl<const N: usize, F: Field> Check<N, F> {
    const IS_BITSIZE_CORRECT: () = assert!(
        N as u32 == F::BIT_SIZE / 8,
        "Wrong bit size used for field. You need to use `F::BIT_SIZE` for N."
    );
}

#[cfg(test)]
mod tests {
    use itybity::ToBits;
    use mpz_fields::{p256::P256, UniformRand};
    use mpz_ot_core::ideal::rot::IdealROT;
    use rand::thread_rng;

    use super::{COPEeReceiver, COPEeSender};

    #[test]
    fn test_cope() {
        let count = 12;
        let mut rng = thread_rng();

        let xk: Vec<P256> = (0..count).map(|_| P256::rand(&mut rng)).collect();
        let delta_k: Vec<P256> = (0..count).map(|_| P256::rand(&mut rng)).collect();

        let mut random_ot = IdealROT::default();
        let (sender_msg, receiver_msg) =
            random_ot.random_with_choices(delta_k.iter_lsb0().collect());

        let ti01: Vec<[[u8; 32]; 2]> = sender_msg.msgs;
        let t_delta_i: Vec<[u8; 32]> = receiver_msg.msgs;

        let sender = COPEeSender::<32, P256>::default();
        let receiver = COPEeReceiver::<32, P256>::default();

        let (ui, t0k) = sender.generate(&ti01, &xk).unwrap();

        let qk = receiver.generate(&delta_k, &t_delta_i, &ui).unwrap();

        for (((&x, delta), t), q) in xk.iter().zip(delta_k).zip(t0k).zip(qk) {
            assert_eq!(q, x * delta + t)
        }
    }
}
