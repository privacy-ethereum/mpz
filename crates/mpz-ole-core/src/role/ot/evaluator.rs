use super::Check;
use crate::OLECoreError;
use itybity::IntoBitIterator;
use mpz_fields::Field;
use rand::thread_rng;
use std::marker::PhantomData;

/// An evaluator for ROLE with errors.
pub struct ROLEeEvaluator<const N: usize, F>(PhantomData<F>);

impl<const N: usize, F: Field> ROLEeEvaluator<N, F> {
    /// Creates a new [`ROLEeEvaluator`].
    pub fn new() -> Self {
        // Check that the right N is used depending on the needed bit size of the field.
        let _: () = Check::<N, F>::IS_BITSIZE_CORRECT;

        Self(PhantomData)
    }

    /// Randomly samples the field element `d` `count`-times.
    ///
    /// # Arguments
    ///
    /// * `count` - The batch size, i.e. how many `d`s to sample.
    ///
    /// # Returns
    ///
    /// * `dk` - The evaluator's input to the random OLEe.
    pub fn sample_d(&self, count: usize) -> Vec<F> {
        let mut rng = thread_rng();
        (0..count).map(|_| F::rand(&mut rng)).collect()
    }

    /// Generates the evaluator's ROLEe input and output.
    ///
    /// # Arguments
    ///
    /// * `fi` - The evaluator's random OT choices.
    /// * `tfi` - The evaluator's random OT messages.
    /// * `ui` - The correlations, sent by the provider.
    /// * `dk` - The evaluator's input to the random OLEe.
    /// * `ek` - The provider's input to the random OLEe.
    ///
    /// # Returns
    ///
    /// * `bk` - The evaluator's final ROLEe input factors.
    /// * `yk` - The evaluator's final ROLEe output summands.
    pub fn generate_output(
        &self,
        fi: &[bool],
        tfi: &[[u8; N]],
        ui: &[F],
        dk: &[F],
        ek: &[F],
    ) -> Result<(Vec<F>, Vec<F>), OLECoreError> {
        check_input(fi, tfi, ui, dk, ek)?;

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

// Some consistency checks.
fn check_input<const N: usize, F: Field>(
    fi: &[bool],
    tfi: &[[u8; N]],
    ui: &[F],
    dk: &[F],
    ek: &[F],
) -> Result<(), OLECoreError> {
    if fi.len() != tfi.len() || tfi.len() != ui.len() {
        return Err(OLECoreError::LengthMismatch(format!(
                "Number of choices {}, received OT messages {} and received correlations {} are not equal.",
                fi.len(),
                tfi.len(),
                ui.len(),
            )));
    }

    if dk.len() != ek.len() {
        return Err(OLECoreError::LengthMismatch(format!(
            "Vectors of field elements have unequal length: dk: {}, ek: {}.",
            dk.len(),
            ek.len(),
        )));
    }

    if dk.len() * F::BIT_SIZE as usize != tfi.len() {
        return Err(OLECoreError::LengthMismatch(format!(
            "Number of field elements {} does not divide number of OT messages {}.",
            dk.len(),
            tfi.len(),
        )));
    }

    Ok(())
}

impl<const N: usize, F: Field> Default for ROLEeEvaluator<N, F> {
    fn default() -> Self {
        Self::new()
    }
}
