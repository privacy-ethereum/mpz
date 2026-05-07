//! Subfield embedding trait and implementations.

use std::fmt::Debug;

use mpz_fields::{Field, gf2_64::Gf2_64};

/// A subfield element that can be embedded into extension field `E`.
///
/// # Mathematical invariant
///
/// Implementors must ensure the type genuinely represents a subfield of
/// `E`. For F_{p^a} ⊂ F_{p^b}, this requires that `a` divides `b`.
pub trait SubfieldOf<E: Field>: Copy + Clone + Debug + PartialEq + Send + Sync + 'static {
    /// Embed this subfield element into the extension field.
    fn embed(self) -> E;

    /// Compute `self · e` in the extension field.
    ///
    /// Default implementation: `self.embed() * e`. Subfield types with
    /// a cheaper multiplication should override this to avoid the full
    /// extension field multiply.
    #[inline]
    fn scalar_mul(self, e: E) -> E {
        self.embed() * e
    }

    /// True if this element is the additive identity of the subfield.
    #[inline]
    fn is_zero(self) -> bool {
        self.embed() == E::zero()
    }
}

// ---------------------------------------------------------------------------
// SubfieldOf implementations for Gf2_64
// ---------------------------------------------------------------------------

impl SubfieldOf<Gf2_64> for bool {
    #[inline]
    fn embed(self) -> Gf2_64 {
        if self { Gf2_64::ONE } else { Gf2_64::ZERO }
    }

    #[inline]
    fn scalar_mul(self, e: Gf2_64) -> Gf2_64 {
        // Branchless: mask is all-1s if self, all-0s otherwise.
        let mask = (self as u64).wrapping_neg();
        Gf2_64(e.0 & mask)
    }

    #[inline]
    fn is_zero(self) -> bool {
        !self
    }
}

/// Every field is trivially a subfield of itself.
impl<E: Field> SubfieldOf<E> for E {
    #[inline]
    fn embed(self) -> E {
        self
    }
}
