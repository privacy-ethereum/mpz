//! RAM protocol strategy traits.

use mpz_fields::{Field, gf2::Gf2};
use mpz_poly_proof_core::ExtensionField;

use super::clock::{AdditiveClock, MultiplicativeClock, ProverClock, VerifierClock};
use crate::{
    strategy::{Char2, Char2Strategy, IntegerLike, PrimeFieldStrategy, VersionStrategy},
    wire::{ProverWire, VerifierWire},
};

/// Strategy shared by both parties.
pub trait CommonStrategy<F: Field>: VersionStrategy<F>
where
    F: ExtensionField<Self::S>,
{
    /// Whether mux-multiplication protocol should register the
    /// boolean-check circuit.
    const BOOLEAN_CHECK_ENABLED: bool;
}

/// Prover-side extension of [`CommonStrategy`].
pub trait ProverStrategy<F: Field>: CommonStrategy<F>
where
    F: ExtensionField<Self::S>,
{
    /// Prover-side wire form.
    type Wire;
    /// Clock strategy.
    type Clock: ProverClock<Self::S, F>;

    /// Returns the wire encoding `a − b` under the strategy's
    /// encoding. Result width matches the inputs.
    ///
    /// # Panics
    ///
    /// Panics if `a.len() != b.len()`.
    fn sub_wires(a: &Self::Wire, b: &Self::Wire) -> Self::Wire;

    /// Returns the wire encoding `a + b` under the strategy's
    /// encoding. Result width matches the inputs.
    ///
    /// # Panics
    ///
    /// Panics if `a.len() != b.len()`.
    fn add_wires(a: &Self::Wire, b: &Self::Wire) -> Self::Wire;
}

/// Verifier-side extension of [`CommonStrategy`].
pub trait VerifierStrategy<F: Field>: CommonStrategy<F>
where
    F: ExtensionField<Self::S>,
{
    /// Verifier-side wire form.
    type Wire;
    /// Clock strategy.
    type Clock: VerifierClock<Self::S, F>;

    /// Returns the key wire encoding `a − b` (per-slot field
    /// subtraction). Result width matches the inputs.
    ///
    /// # Panics
    ///
    /// Panics if `a.len() != b.len()`.
    fn sub_wires(a: &Self::Wire, b: &Self::Wire) -> Self::Wire;

    /// Returns the key wire encoding `a + b` (per-slot field
    /// addition). Result width matches the inputs.
    ///
    /// # Panics
    ///
    /// Panics if `a.len() != b.len()`.
    fn add_wires(a: &Self::Wire, b: &Self::Wire) -> Self::Wire;
}

impl<F> CommonStrategy<F> for Char2Strategy<F>
where
    F: Field + Char2 + ExtensionField<Gf2>,
{
    const BOOLEAN_CHECK_ENABLED: bool = false;
}

impl<F> ProverStrategy<F> for Char2Strategy<F>
where
    F: Field + Char2 + ExtensionField<Gf2>,
{
    type Wire = ProverWire<Gf2, F>;
    type Clock = MultiplicativeClock;

    fn sub_wires(a: &Self::Wire, b: &Self::Wire) -> Self::Wire {
        assert_eq!(
            a.len(),
            b.len(),
            "sub_wires/add_wires: a.len()={} != b.len()={}",
            a.len(),
            b.len()
        );
        ProverWire::new(
            a.value()
                .iter()
                .zip(b.value().iter())
                .map(|(x, y)| *x - *y)
                .collect(),
            a.mac()
                .iter()
                .zip(b.mac().iter())
                .map(|(x, y)| *x - *y)
                .collect(),
        )
    }

    fn add_wires(a: &Self::Wire, b: &Self::Wire) -> Self::Wire {
        assert_eq!(
            a.len(),
            b.len(),
            "sub_wires/add_wires: a.len()={} != b.len()={}",
            a.len(),
            b.len()
        );
        ProverWire::new(
            a.value()
                .iter()
                .zip(b.value().iter())
                .map(|(x, y)| *x + *y)
                .collect(),
            a.mac()
                .iter()
                .zip(b.mac().iter())
                .map(|(x, y)| *x + *y)
                .collect(),
        )
    }
}

impl<F> VerifierStrategy<F> for Char2Strategy<F>
where
    F: Field + Char2 + ExtensionField<Gf2>,
{
    type Wire = VerifierWire<F>;
    type Clock = MultiplicativeClock;

    fn sub_wires(a: &Self::Wire, b: &Self::Wire) -> Self::Wire {
        assert_eq!(
            a.len(),
            b.len(),
            "sub_wires/add_wires: a.len()={} != b.len()={}",
            a.len(),
            b.len()
        );
        VerifierWire::new(
            a.key
                .iter()
                .zip(b.key.iter())
                .map(|(x, y)| *x - *y)
                .collect(),
        )
    }

    fn add_wires(a: &Self::Wire, b: &Self::Wire) -> Self::Wire {
        assert_eq!(
            a.len(),
            b.len(),
            "sub_wires/add_wires: a.len()={} != b.len()={}",
            a.len(),
            b.len()
        );
        VerifierWire::new(
            a.key
                .iter()
                .zip(b.key.iter())
                .map(|(x, y)| *x + *y)
                .collect(),
        )
    }
}

impl<F> CommonStrategy<F> for PrimeFieldStrategy<F>
where
    F: ExtensionField<F> + IntegerLike,
{
    const BOOLEAN_CHECK_ENABLED: bool = true;
}

impl<F> ProverStrategy<F> for PrimeFieldStrategy<F>
where
    F: ExtensionField<F> + IntegerLike,
{
    type Wire = ProverWire<F, F>;
    type Clock = AdditiveClock<F>;

    fn sub_wires(a: &Self::Wire, b: &Self::Wire) -> Self::Wire {
        assert_eq!(
            a.len(),
            b.len(),
            "sub_wires: a.len()={} != b.len()={}",
            a.len(),
            b.len(),
        );
        ProverWire::new(
            (a.value()[0] - b.value()[0]).into(),
            (a.mac()[0] - b.mac()[0]).into(),
        )
    }

    fn add_wires(a: &Self::Wire, b: &Self::Wire) -> Self::Wire {
        assert_eq!(
            a.len(),
            b.len(),
            "add_wires: a.len()={} != b.len()={}",
            a.len(),
            b.len(),
        );
        ProverWire::new(
            (a.value()[0] + b.value()[0]).into(),
            (a.mac()[0] + b.mac()[0]).into(),
        )
    }
}

impl<F> VerifierStrategy<F> for PrimeFieldStrategy<F>
where
    F: ExtensionField<F> + IntegerLike,
{
    type Wire = VerifierWire<F>;
    type Clock = AdditiveClock<F>;

    fn sub_wires(a: &Self::Wire, b: &Self::Wire) -> Self::Wire {
        assert_eq!(
            a.len(),
            b.len(),
            "sub_wires: a.len()={} != b.len()={}",
            a.len(),
            b.len(),
        );
        VerifierWire::new((a.key[0] - b.key[0]).into())
    }

    fn add_wires(a: &Self::Wire, b: &Self::Wire) -> Self::Wire {
        assert_eq!(
            a.len(),
            b.len(),
            "add_wires: a.len()={} != b.len()={}",
            a.len(),
            b.len(),
        );
        VerifierWire::new((a.key[0] + b.key[0]).into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mpz_fields::gf2_64::Gf2_64;

    use crate::wire::Bundle;

    #[test]
    fn char2_sub_wires_is_elementwise_xor() {
        // Element-wise. Gf2 sub == XOR; Gf2_64 sub == XOR (char-2).
        let a = ProverWire::<Gf2, Gf2_64>::new(
            Bundle::new(vec![Gf2(true), Gf2(false), Gf2(true)]),
            Bundle::new(vec![Gf2_64(0xa), Gf2_64(0xb), Gf2_64(0xc)]),
        );
        let b = ProverWire::<Gf2, Gf2_64>::new(
            Bundle::new(vec![Gf2(true), Gf2(true), Gf2(false)]),
            Bundle::new(vec![Gf2_64(0x1), Gf2_64(0x2), Gf2_64(0x3)]),
        );
        let out = <Char2Strategy<Gf2_64> as ProverStrategy<Gf2_64>>::sub_wires(&a, &b);
        assert_eq!(
            **out.value(),
            [Gf2(false), Gf2(true), Gf2(true)],
            "value side ≠ a XOR b"
        );
        assert_eq!(
            **out.mac(),
            [Gf2_64(0xb), Gf2_64(0x9), Gf2_64(0xf)],
            "mac side ≠ a XOR b",
        );
    }

    #[test]
    fn char2_add_equals_sub_in_char2() {
        // In any char-2 field, `+` and `−` collapse — sub_wires and
        // add_wires must produce identical results.
        let a = ProverWire::<Gf2, Gf2_64>::new(
            Bundle::new(vec![Gf2(true), Gf2(false)]),
            Bundle::new(vec![Gf2_64(0x1234), Gf2_64(0x5678)]),
        );
        let b = ProverWire::<Gf2, Gf2_64>::new(
            Bundle::new(vec![Gf2(false), Gf2(true)]),
            Bundle::new(vec![Gf2_64(0x9abc), Gf2_64(0xdef0)]),
        );
        let sub = <Char2Strategy<Gf2_64> as ProverStrategy<Gf2_64>>::sub_wires(&a, &b);
        let add = <Char2Strategy<Gf2_64> as ProverStrategy<Gf2_64>>::add_wires(&a, &b);
        assert_eq!(**sub.value(), **add.value());
        assert_eq!(**sub.mac(), **add.mac());
    }
}
