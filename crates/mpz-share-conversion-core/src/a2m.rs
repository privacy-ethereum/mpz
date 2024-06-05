//! A2M conversion protocol.
//!
//! Let `A` be an element of some finite field with `A = x + y`, where `x` is only known to Alice
//! and `y` is only known to Bob. A is unknown to both parties and it is their goal that each of
//! them ends up with a multiplicative share of A. So both parties start with `x` and `y` and want to
//! end up with `a` and `b`, where `A = x + y = a * b`.
//!
//! This module implements the A2M protocol from <https://eprint.iacr.org/2023/964>, page 40,
//! figure 16, 4.

use crate::{ErrorKind, ShareConversionError};
use mpz_fields::Field;

/// Converts additive sender shares into multiplicative shares.
///
/// # Arguments
///
/// * `input` - The sender's input field elements.
/// * `ole_input` - The input from an OLE sender.
/// * `ole_output` - The output from an OLE sender.
///
/// # Returns
///
/// * The multiplicative shares of the sender.
/// * The masks which have to be sent to the receiver.
pub fn a2m_convert_sender<F: Field>(
    input: Vec<F>,
    mut ole_input: Vec<F>,
    ole_output: Vec<F>,
) -> Result<(Vec<F>, A2MMasks<F>), ShareConversionError> {
    if input.len() != ole_output.len() || ole_input.len() != ole_output.len() {
        return Err(ShareConversionError::new(
            ErrorKind::UnequalLength,
            format!(
                "Vectors have unequal length: {}, {}, {}",
                input.len(),
                ole_input.len(),
                ole_output.len()
            ),
        ));
    }

    let masks: Vec<F> = input
        .iter()
        .zip(ole_input.iter().copied())
        .zip(ole_output)
        .map(|((&i, r), o)| i * r + -o)
        .collect();

    ole_input.iter_mut().for_each(|r| *r = r.inverse());

    Ok((ole_input, A2MMasks(masks)))
}

/// Converts the A2M sender's masks into multiplicative receiver shares.
///
/// # Arguments
///
/// * `masks` - The masks received from the sender.
/// * `ole_output` - The output from an OLE receiver.
///
/// # Returns
///
/// * The multiplicative shares of the receiver.
pub fn a2m_convert_receiver<F: Field>(
    masks: A2MMasks<F>,
    ole_output: Vec<F>,
) -> Result<Vec<F>, ShareConversionError> {
    let masks = masks.0;

    if masks.len() != ole_output.len() {
        return Err(ShareConversionError::new(
            ErrorKind::UnequalLength,
            format!(
                "Vectors have unequal length: {} != {}",
                masks.len(),
                ole_output.len()
            ),
        ));
    }

    let output = masks.iter().zip(ole_output).map(|(&m, o)| m + o).collect();
    Ok(output)
}

/// The masks created by the sender.
pub struct A2MMasks<F>(pub(crate) Vec<F>);

#[cfg(test)]
mod tests {
    use mpz_core::{prg::Prg, Block};
    use mpz_fields::{p256::P256, UniformRand};
    use mpz_ole_core::ideal::IdealOLE;
    use rand::SeedableRng;

    use crate::{a2m_convert_receiver, a2m_convert_sender};

    #[test]
    fn test_a2m() {
        let count = 12;
        let mut rng = Prg::from_seed(Block::ZERO);
        let mut ole = IdealOLE::default();

        let ole_sender_input: Vec<P256> = (0..count).map(|_| P256::rand(&mut rng)).collect();
        let ole_receiver_input: Vec<P256> = (0..count).map(|_| P256::rand(&mut rng)).collect();

        let (ole_sender_output, ole_receiver_output) =
            ole.generate(&ole_sender_input, &ole_receiver_input);

        let sender_input: Vec<P256> = (0..count).map(|_| P256::rand(&mut rng)).collect();
        let receiver_input: Vec<P256> = ole_receiver_input;

        let (sender_output, masks) =
            a2m_convert_sender(sender_input.clone(), ole_sender_input, ole_sender_output).unwrap();
        let receiver_output = a2m_convert_receiver(masks, ole_receiver_output).unwrap();

        sender_input
            .iter()
            .zip(receiver_input)
            .zip(sender_output)
            .zip(receiver_output)
            .for_each(|(((&x, y), a), b)| assert_eq!(x + y, a * b));
    }
}
