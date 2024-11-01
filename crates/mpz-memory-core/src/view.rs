use serde::{Deserialize, Serialize};
use utils::range::{Difference, Disjoint, Subset};

use crate::{Range, RangeSet, Slice};

/// A view of memory.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct View {
    len: usize,
    uninit: RangeSet,
    public: RangeSet,
    private: RangeSet,
    blind: RangeSet,
    visible: RangeSet,
}

impl View {
    /// Creates a new view.
    pub fn new() -> Self {
        Self::default()
    }

    /// Allocates memory.
    pub fn alloc(&mut self, len: usize) {
        let end = self.len;
        self.len += len;
        self.uninit |= end..end + len;
    }

    /// Returns the public ranges.
    pub fn public(&self) -> &RangeSet {
        &self.public
    }

    /// Returns the private ranges.
    pub fn private(&self) -> &RangeSet {
        &self.private
    }

    /// Returns the blind ranges.
    pub fn blind(&self) -> &RangeSet {
        &self.blind
    }

    /// Returns the visible ranges.
    pub fn visible(&self) -> &RangeSet {
        &self.visible
    }

    /// Returns `true` if all data in the slice is set.
    pub fn is_set(&self, slice: Slice) -> bool {
        slice.to_range().is_disjoint(&self.uninit)
    }

    /// Returns `true` if any data in the slice is set.
    pub fn is_set_any(&self, slice: Slice) -> bool {
        !slice.to_range().difference(&self.uninit).is_empty()
    }

    /// Returns `true` if all data in the slice is visible.
    pub fn is_visible(&self, slice: Slice) -> bool {
        slice.to_range().is_subset(&self.visible)
    }

    /// Returns `true` if any data in the slice is visible.
    pub fn is_visible_any(&self, slice: Slice) -> bool {
        !slice.to_range().is_disjoint(&self.visible)
    }

    /// Returns `true` if all data in the slice is public.
    pub fn is_public(&self, slice: Slice) -> bool {
        slice.to_range().is_subset(&self.public)
    }

    /// Returns `true` if any data in the slice is public.
    pub fn is_public_any(&self, slice: Slice) -> bool {
        !slice.to_range().is_disjoint(&self.public)
    }

    /// Returns `true` if all data in the slice is private.
    pub fn is_private(&self, slice: Slice) -> bool {
        slice.to_range().is_subset(&self.private)
    }

    /// Returns `true` if any data in the slice is private.
    pub fn is_private_any(&self, slice: Slice) -> bool {
        !slice.to_range().is_disjoint(&self.private)
    }

    /// Returns `true` if all data in the slice is blind.
    pub fn is_blind(&self, slice: Slice) -> bool {
        slice.to_range().is_subset(&self.blind)
    }

    /// Returns `true` if any data in the slice is blind.
    pub fn is_blind_any(&self, slice: Slice) -> bool {
        !slice.to_range().is_disjoint(&self.blind)
    }

    /// Sets the slice as public.
    pub fn set_public(&mut self, slice: Slice) {
        let range = slice.to_range();
        self.public |= &range;
        self.visible |= &range;
        self.uninit -= &range;
        self.private -= &range;
        self.blind -= &range;
    }

    /// Sets the slice as private.
    pub fn set_private(&mut self, slice: Slice) {
        let range = slice.to_range();
        self.private |= &range;
        self.visible |= &range;
        self.uninit -= &range;
        self.public -= &range;
        self.blind -= &range;
    }

    /// Sets the slice as blind.
    pub fn set_blind(&mut self, slice: Slice) {
        let range = slice.to_range();
        self.blind |= &range;
        self.visible -= &range;
        self.uninit -= &range;
        self.public -= &range;
        self.private -= &range;
    }

    /// Returns an iterator over the public slices.
    pub fn iter_public(&self) -> impl Iterator<Item = Range> + '_ {
        self.public.iter_ranges()
    }

    /// Returns an iterator over the private slices.
    pub fn iter_private(&self) -> impl Iterator<Item = Range> + '_ {
        self.private.iter_ranges()
    }

    /// Returns an iterator over the blind slices.
    pub fn iter_blind(&self) -> impl Iterator<Item = Range> + '_ {
        self.blind.iter_ranges()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_view() {
        let mut view = View::new();
        view.alloc(30);

        let slice = Slice::from_range_unchecked(0..10);
        assert!(!view.is_set(slice));
        assert!(!view.is_set_any(slice));

        view.set_public(Slice::from_range_unchecked(0..10));
        view.set_private(Slice::from_range_unchecked(10..20));
        view.set_blind(Slice::from_range_unchecked(20..30));

        assert!(view.is_public(Slice::from_range_unchecked(0..10)));
        assert!(view.is_private(Slice::from_range_unchecked(10..20)));
        assert!(view.is_blind(Slice::from_range_unchecked(20..30)));
    }

    #[test]
    fn test_mutually_exclusive() {
        let mut view = View::new();

        view.set_public(Slice::from_range_unchecked(0..10));
        view.set_private(Slice::from_range_unchecked(5..15));

        assert!(view.is_public(Slice::from_range_unchecked(0..5)));
        assert!(view.is_private(Slice::from_range_unchecked(5..15)));

        view.set_blind(Slice::from_range_unchecked(5..10));

        assert!(view.is_blind(Slice::from_range_unchecked(5..10)));
        assert!(!view.is_public(Slice::from_range_unchecked(0..10)));
        assert!(!view.is_private(Slice::from_range_unchecked(5..15)));
    }
}
