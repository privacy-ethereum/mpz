//! Ideal functionality for Oblivious Linear Function Evaluation (OLE).

use mpz_fields::Field;
use rand::{rngs::ThreadRng, thread_rng};

/// The OLE functionality.
pub struct IdealOLE(ThreadRng);

impl IdealOLE {
    /// Creates a new functionality.
    pub fn new() -> Self {
        Self(thread_rng())
    }

    /// Generates OLEs.
    pub fn generate<F: Field>(
        &mut self,
        sender_input: &[F],
        receiver_input: &[F],
    ) -> (Vec<F>, Vec<F>) {
        assert_eq!(
            sender_input.len(),
            receiver_input.len(),
            "Vectors of field elements should have equal length."
        );

        let sender_output: Vec<F> = (0..sender_input.len())
            .map(|_| F::rand(&mut self.0))
            .collect();

        let receiver_output: Vec<F> = sender_input
            .iter()
            .zip(receiver_input)
            .zip(sender_output.iter().copied())
            .map(|((&a, &b), x)| a * b + x)
            .collect();

        (sender_output, receiver_output)
    }
}

impl Default for IdealOLE {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use crate::ideal::IdealOLE;
    use mpz_core::{prg::Prg, Block};
    use mpz_fields::{p256::P256, UniformRand};
    use rand::SeedableRng;

    #[test]
    fn test_ole_functionality() {
        let count = 12;
        let mut ole = IdealOLE::default();
        let mut rng = Prg::from_seed(Block::ZERO);

        let ak: Vec<P256> = (0..count).map(|_| P256::rand(&mut rng)).collect();
        let bk: Vec<P256> = (0..count).map(|_| P256::rand(&mut rng)).collect();

        let (xk, yk) = ole.generate(&ak, &bk);

        yk.iter()
            .zip(xk)
            .zip(ak)
            .zip(bk)
            .for_each(|(((&y, x), a), b)| assert_eq!(y, a * b + x));
    }
}
