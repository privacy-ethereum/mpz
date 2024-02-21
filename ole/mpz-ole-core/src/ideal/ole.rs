//! This module provides an ideal OLE functionality.

use mpz_share_conversion_core::Field;
use rand::{rngs::ThreadRng, thread_rng};

/// The OLE functionality
pub struct OLEFunctionality<F> {
    rng: ThreadRng,
    ak: Vec<F>,
    bk: Vec<F>,
    xk: Vec<F>,
    yk: Vec<F>,
}

impl<F: Field> OLEFunctionality<F> {
    /// Creates a new [`OLEFunctionality`].
    pub fn new() -> Self {
        Self {
            rng: thread_rng(),
            ak: vec![],
            bk: vec![],
            xk: vec![],
            yk: vec![],
        }
    }

    /// Sets the OLE provider's input `ak`.
    pub fn provider_input(&mut self, ak: Vec<F>) {
        self.ak = ak;
    }

    /// Sets the OLE evaluator's input `bk`.
    pub fn evaluator_input(&mut self, bk: Vec<F>) {
        self.bk = bk;
    }

    /// Generates the OLE provider's output `xk`.
    pub fn provide(&mut self) -> Vec<F> {
        if self.xk.is_empty() && !self.ak.is_empty() && !self.bk.is_empty() {
            self.set_xk_yk();
        }

        std::mem::take(&mut self.xk)
    }

    /// Generates the OLE evaluator's output `yk`.
    pub fn evaluate(&mut self) -> Vec<F> {
        if self.yk.is_empty() && !self.ak.is_empty() && !self.bk.is_empty() {
            self.set_xk_yk();
        }

        std::mem::take(&mut self.yk)
    }

    fn set_xk_yk(&mut self) {
        assert_eq!(
            self.ak.len(),
            self.bk.len(),
            "Vectors of field elements have unequal length."
        );

        let xk: Vec<F> = (0..self.ak.len()).map(|_| F::rand(&mut self.rng)).collect();
        self.xk = xk;

        let yk: Vec<F> = self
            .xk
            .iter()
            .zip(self.ak.iter())
            .zip(self.bk.iter())
            .map(|((&x, &a), &b)| a * b + x)
            .collect();
        self.yk = yk;
    }
}

impl<F: Field> Default for OLEFunctionality<F> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::OLEFunctionality;
    use mpz_core::{prg::Prg, Block};
    use mpz_share_conversion_core::fields::{p256::P256, UniformRand};
    use rand::SeedableRng;

    #[test]
    fn test_ole_functionality() {
        let count = 12;
        let mut ole: OLEFunctionality<P256> = OLEFunctionality::default();
        let mut rng = Prg::from_seed(Block::ZERO);

        let ak: Vec<P256> = (0..count).map(|_| P256::rand(&mut rng)).collect();
        let bk: Vec<P256> = (0..count).map(|_| P256::rand(&mut rng)).collect();

        ole.provider_input(ak.clone());
        ole.evaluator_input(bk.clone());

        let xk = ole.provide();
        let yk = ole.evaluate();

        yk.iter()
            .zip(xk.iter())
            .zip(ak.iter())
            .zip(bk.iter())
            .for_each(|(((&y, &x), &a), &b)| assert_eq!(y, a * b + x));
    }
}
