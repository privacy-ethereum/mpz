use super::Check;
use crate::OLECoreError;
use itybity::IntoBitIterator;
use mpz_share_conversion_core::Field;
use rand::thread_rng;
use std::marker::PhantomData;

#[derive(Debug)]
pub struct ROLEeEvaluator<const N: usize, F>(PhantomData<F>);

impl<const N: usize, F: Field> ROLEeEvaluator<N, F> {
    pub fn new() -> Self {
        // Check that the right N is used depending on the needed bit size of the field.
        let _: () = Check::<N, F>::IS_BITSIZE_CORRECT;

        Self(PhantomData)
    }

    pub fn sample_d_(&self, count: usize) -> Vec<F> {
        let mut rng = thread_rng();
        (0..count).map(|_| F::rand(&mut rng)).collect()
    }

    pub fn generate_output(
        &self,
        fi: &[bool],
        tfi: &[[u8; N]],
        ui: &[F],
        dk: &[F],
        ek: &[F],
    ) -> Result<(Vec<F>, Vec<F>), OLECoreError> {
        let fk: Vec<F> = fi
            .chunks(F::BIT_SIZE as usize)
            .map(|f| F::from_lsb0_iter(f.into_iter_lsb0()))
            .collect();

        let bk: Vec<F> = fk.iter().zip(ek).map(|(&f, &e)| f + e).collect();

        let yk: Vec<F> = fi
            .chunks(F::BIT_SIZE as usize)
            .zip(tfi.chunks(F::BIT_SIZE as usize))
            .zip(ui.chunks(F::BIT_SIZE as usize))
            .zip(dk)
            .map(|(((f, t), u), &d)| {
                f.iter()
                    .zip(t)
                    .zip(u)
                    .enumerate()
                    .fold(F::zero(), |acc, (i, ((&f, t), &u))| {
                        let f = if f { F::one() } else { F::zero() };
                        acc + F::two_pow(i as u32)
                            * (f * (u + d) + F::from_lsb0_iter(t.into_iter_lsb0()))
                    })
            })
            .collect();

        Ok((bk, yk))
    }
}

impl<const N: usize, F: Field> Default for ROLEeEvaluator<N, F> {
    fn default() -> Self {
        Self::new()
    }
}
