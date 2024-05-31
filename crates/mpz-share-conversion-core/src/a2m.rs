//! A2M conversion protocol.
//!
//! Let `A` be an element of some finite field with `A = x + y`, where `x` is only known to Alice
//! and `y` is only known to Bob. A is unknown to both parties and it is their goal that each of
//! them ends up with a multiplicative share of A. So both parties start with `x` and `y` and want to
//! end up with `a` and `b`, where `A = x + y = a * b`.

use mpz_fields::Field;
use rand::thread_rng;

use crate::{ShareConversionError, ShareConversionErrorKind};

pub fn a2m_convert_sender<F: Field>(
    input: Vec<F>,
    ole_output: Vec<F>,
) -> Result<(Vec<F>, A2MMasks<F>), ShareConversionError> {
    if input.len() != ole_output.len() {
        return Err(ShareConversionError::new(
            ShareConversionErrorKind::UnequalLength,
            format!(
                "Vectors have unequal length: {} != {}",
                input.len(),
                ole_output.len()
            ),
        ));
    }

    let mut rng = thread_rng();
    let mut random: Vec<F> = (0..input.len()).map(|_| F::rand(&mut rng)).collect();

    let masks: Vec<F> = input
        .iter()
        .zip(random.iter().copied())
        .zip(ole_output)
        .map(|((&i, r), o)| i * r + o)
        .collect();

    random.iter_mut().for_each(|r| *r = r.inverse());

    Ok((random, A2MMasks(masks)))
}

pub fn a2m_convert_receiver<F: Field>(
    masks: A2MMasks<F>,
    ole_output: Vec<F>,
) -> Result<Vec<F>, ShareConversionError> {
    let masks = masks.0;

    if masks.len() != ole_output.len() {
        return Err(ShareConversionError::new(
            ShareConversionErrorKind::UnequalLength,
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

/// The masks created by the sender and sent to the receiver.
pub struct A2MMasks<F>(pub(crate) Vec<F>);
