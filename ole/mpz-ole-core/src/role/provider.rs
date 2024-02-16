use itybity::IntoBitIterator;
use mpz_share_conversion_core::Field;
use rand::thread_rng;
use std::marker::PhantomData;

use super::Check;

#[derive(Debug)]
pub struct ROLEeProvider<const N: usize, F>(PhantomData<F>);

impl<const N: usize, F: Field> ROLEeProvider<N, F> {
    pub fn new() -> Self {
        // Check that the right N is used depending on the needed bit size of the field.
        let _: () = Check::<N, F>::IS_BITSIZE_CORRECT;

        Self(PhantomData)
    }

    pub fn sample_c_and_e(&self, count: usize) -> (Vec<F>, Vec<F>) {
        let mut rng = thread_rng();

        let ck = (0..count).map(|_| F::rand(&mut rng)).collect();
        let ek = (0..count).map(|_| F::rand(&mut rng)).collect();

        (ck, ek)
    }

    pub fn create_correlation(&self, ti01: &[[[u8; N]; 2]], ck: &[F]) -> (Vec<F>, Vec<F>) {
        if ti01.len() % ck.len() != 0 {
            panic!(
                "Number of field elements {} does not divide number of OT messages {}.",
                ti01.len(),
                ck.len()
            );
        }

        let (ui, t0i): (Vec<F>, Vec<F>) = ti01
            .chunks(F::BIT_SIZE as usize)
            .zip(ck.iter().copied())
            .flat_map(|(chunk, c)| {
                chunk.iter().map(move |[t0, t1]| {
                    let t0 = F::from_lsb0_iter(t0.into_iter_lsb0());
                    let t1 = F::from_lsb0_iter(t1.into_iter_lsb0());
                    (t0 + -t1 + c, t0)
                })
            })
            .unzip();

        (ui, t0i)
    }

    pub fn generate_output(&self, t0i: &[F], ck: &[F], dk: &[F], ek: &[F]) -> (Vec<F>, Vec<F>) {
        if t0i.len() % ck.len() != 0 {
            panic!(
                "Number of field elements {} does not divide number of OT messages {}.",
                t0i.len(),
                ck.len()
            );
        }

        if ck.len() != dk.len() || dk.len() != ek.len() {
            panic!(
                "Vectors of field elements have unequal length: ck: {}, dk: {}, ek: {}.",
                ck.len(),
                dk.len(),
                ek.len(),
            );
        }

        let t0k: Vec<F> = t0i
            .chunks(F::BIT_SIZE as usize)
            .map(|chunk| {
                chunk
                    .iter()
                    .enumerate()
                    .fold(F::zero(), |acc, (k, &el)| acc + F::two_pow(k as u32) * el)
            })
            .collect();

        let ak: Vec<F> = ck
            .iter()
            .copied()
            .zip(dk.iter().copied())
            .map(|(c, d)| c + d)
            .collect();

        let xk: Vec<F> = t0k
            .iter()
            .zip(ak.iter().copied())
            .zip(ek.iter().copied())
            .map(|((&t, a), k)| t + -(a * k))
            .collect();

        (ak, xk)
    }
}

impl<const N: usize, F: Field> Default for ROLEeProvider<N, F> {
    fn default() -> Self {
        Self::new()
    }
}
