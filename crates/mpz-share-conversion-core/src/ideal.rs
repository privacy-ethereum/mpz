//! Ideal functionalities for share conversion.

use mpz_fields::Field;
use rand::{rngs::ThreadRng, thread_rng};

/// The M2A functionality.
pub struct IdealM2A(ThreadRng);

impl IdealM2A {
    /// Creates a new functionality.
    pub fn new() -> Self {
        Self(thread_rng())
    }

    /// Generates additive shares from multiplicative shares.
    pub fn generate<F: Field>(
        &mut self,
        sender_input: Vec<F>,
        receiver_input: Vec<F>,
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
            .map(|((&si, &ri), so)| si * ri + -so)
            .collect();

        (sender_output, receiver_output)
    }
}

impl Default for IdealM2A {
    fn default() -> Self {
        Self::new()
    }
}

/// The A2M functionality.
pub struct IdealA2M(ThreadRng);

impl IdealA2M {
    /// Creates a new functionality.
    pub fn new() -> Self {
        Self(thread_rng())
    }

    /// Generates multiplicative shares from additive shares.
    pub fn generate<F: Field>(
        &mut self,
        sender_input: Vec<F>,
        receiver_input: Vec<F>,
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
            .map(|((&si, &ri), so)| (si + ri) * so.inverse())
            .collect();

        (sender_output, receiver_output)
    }
}

impl Default for IdealA2M {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use crate::ideal::{IdealA2M, IdealM2A};
    use mpz_core::{prg::Prg, Block};
    use mpz_fields::{p256::P256, UniformRand};
    use rand::SeedableRng;

    #[test]
    fn test_m2a_functionality() {
        let count = 12;
        let mut m2a = IdealM2A::default();
        let mut rng = Prg::from_seed(Block::ZERO);

        let sender_input: Vec<P256> = (0..count).map(|_| P256::rand(&mut rng)).collect();
        let receiver_input: Vec<P256> = (0..count).map(|_| P256::rand(&mut rng)).collect();

        let (sender_output, receiver_output) = m2a.generate(&sender_input, &receiver_input);

        sender_input
            .iter()
            .zip(receiver_input)
            .zip(sender_output)
            .zip(receiver_output)
            .for_each(|(((&si, ri), so), ro)| assert_eq!(si * ri, so + ro));
    }

    #[test]
    fn test_a2m_functionality() {
        let count = 12;
        let mut m2a = IdealA2M::default();
        let mut rng = Prg::from_seed(Block::ZERO);

        let sender_input: Vec<P256> = (0..count).map(|_| P256::rand(&mut rng)).collect();
        let receiver_input: Vec<P256> = (0..count).map(|_| P256::rand(&mut rng)).collect();

        let (sender_output, receiver_output) = m2a.generate(&sender_input, &receiver_input);

        sender_input
            .iter()
            .zip(receiver_input)
            .zip(sender_output)
            .zip(receiver_output)
            .for_each(|(((&si, ri), so), ro)| assert_eq!(si + ri, so * ro));
    }
}
