//! This module provides an ideal ROLE functionality.

use mpz_fields::Field;
use rand::{rngs::ThreadRng, thread_rng};

/// The ROLE functionality
pub struct ROLEFunctionality<F> {
    rng: ThreadRng,
    ak: Vec<F>,
    bk: Vec<F>,
    xk: Vec<F>,
    yk: Vec<F>,
}

impl<F: Field> ROLEFunctionality<F> {
    /// Creates a new [`ROLEFunctionality`].
    pub fn new() -> Self {
        Self {
            rng: thread_rng(),
            ak: vec![],
            bk: vec![],
            xk: vec![],
            yk: vec![],
        }
    }

    /// Generates the ROLE provider's output `(ak, xk)`.
    pub fn provide_random(&mut self, count: usize) -> (Vec<F>, Vec<F>) {
        if self.xk.is_empty() {
            self.set(count);
        }

        let ak = std::mem::take(&mut self.ak);
        let xk = std::mem::take(&mut self.xk);

        (ak, xk)
    }

    /// Generates the ROLE evaluator's output `(bk, yk)`.
    pub fn evaluate_random(&mut self, count: usize) -> (Vec<F>, Vec<F>) {
        if self.yk.is_empty() {
            self.set(count);
        }

        let bk = std::mem::take(&mut self.bk);
        let yk = std::mem::take(&mut self.yk);

        (bk, yk)
    }

    fn set(&mut self, count: usize) {
        let ak: Vec<F> = (0..count).map(|_| F::rand(&mut self.rng)).collect();
        let bk: Vec<F> = (0..count).map(|_| F::rand(&mut self.rng)).collect();
        let xk: Vec<F> = (0..count).map(|_| F::rand(&mut self.rng)).collect();
        let yk: Vec<F> = xk
            .iter()
            .zip(ak.iter())
            .zip(bk.iter())
            .map(|((&x, &a), &b)| a * b + x)
            .collect();

        self.ak = ak;
        self.bk = bk;
        self.xk = xk;
        self.yk = yk;
    }
}

impl<F: Field> Default for ROLEFunctionality<F> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::ROLEFunctionality;
    use mpz_fields::p256::P256;

    #[test]
    fn test_role_functionality() {
        let count = 12;
        let mut role: ROLEFunctionality<P256> = ROLEFunctionality::default();

        let (ak, xk) = role.provide_random(count);
        let (bk, yk) = role.evaluate_random(count);

        yk.iter()
            .zip(xk.iter())
            .zip(ak.iter())
            .zip(bk.iter())
            .for_each(|(((&y, &x), &a), &b)| assert_eq!(y, a * b + x));
    }
}
