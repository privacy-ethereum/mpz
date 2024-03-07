//! Provides an implementation of ROLEe based on random OT.
//!
//! This module implements the "Random OLE" protocol in <https://github.com/tlsnotary/docs-mdbook/blob/main/research/ole-flavors.typ>.

mod evaluator;
mod provider;

pub use evaluator::ROLEeEvaluator;
pub use provider::ROLEeProvider;

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
    use mpz_core::{prg::Prg, Block};
    use mpz_fields::{p256::P256, Field};
    use mpz_ot_core::ideal::ideal_rot::IdealROT;
    use rand::{RngCore, SeedableRng};

    use super::{ROLEeEvaluator, ROLEeProvider};

    #[test]
    fn test_role_ot_core() {
        let count = 12;

        let mut random_ot = IdealROT::default();

        let (sender_msg, receiver_msg) = random_ot.extend(count * P256::BIT_SIZE as usize);

        let ti01: Vec<[[u8; 32]; 2]> = sender_msg
            .qs
            .iter()
            .map(|&[a, b]| [prg(a), prg(b)])
            .collect();
        let fi: Vec<bool> = receiver_msg.rs;
        let tfi: Vec<[u8; 32]> = receiver_msg.ts.iter().map(|&c| prg(c)).collect();

        let provider = ROLEeProvider::<32, P256>::default();
        let evaluator = ROLEeEvaluator::<32, P256>::default();

        let (ck, ek) = provider.sample_c_and_e(count);
        let (ui, t0i) = provider.create_correlation(&ti01, &ck).unwrap();

        let dk = evaluator.sample_d(count);

        let (ak, xk) = provider.generate_output(&t0i, &ck, &dk, &ek).unwrap();
        let (bk, yk) = evaluator.generate_output(&fi, &tfi, &ui, &dk, &ek).unwrap();

        for (((&a, x), b), y) in ak.iter().zip(xk).zip(bk).zip(yk) {
            assert_eq!(y, a * b + x)
        }
    }

    fn prg<const N: usize>(block: Block) -> [u8; N] {
        let mut prg = Prg::from_seed(block);

        let mut out = [0_u8; N];
        prg.fill_bytes(&mut out);

        out
    }
}
