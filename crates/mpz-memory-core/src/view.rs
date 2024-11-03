use serde::{Deserialize, Serialize};
use utils::range::{Difference, Disjoint, Subset};

use crate::{Range, RangeSet};

/// Visibility of memory.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VisibilityView {
    len: usize,
    uninit: RangeSet,
    public: RangeSet,
    private: RangeSet,
    blind: RangeSet,
    visible: RangeSet,
}

impl VisibilityView {
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

    /// Returns `true` if all data in the range is set.
    pub fn is_set(&self, range: Range) -> bool {
        range.is_disjoint(&self.uninit)
    }

    /// Returns `true` if any data in the range is set.
    pub fn is_set_any(&self, range: Range) -> bool {
        !range.difference(&self.uninit).is_empty()
    }

    /// Returns `true` if all data in the range is visible.
    pub fn is_visible(&self, range: Range) -> bool {
        range.is_subset(&self.visible)
    }

    /// Returns `true` if any data in the range is visible.
    pub fn is_visible_any(&self, range: Range) -> bool {
        !range.is_disjoint(&self.visible)
    }

    /// Returns `true` if all data in the range is public.
    pub fn is_public(&self, range: Range) -> bool {
        range.is_subset(&self.public)
    }

    /// Returns `true` if any data in the range is public.
    pub fn is_public_any(&self, range: Range) -> bool {
        !range.is_disjoint(&self.public)
    }

    /// Returns `true` if all data in the range is private.
    pub fn is_private(&self, range: Range) -> bool {
        range.is_subset(&self.private)
    }

    /// Returns `true` if any data in the range is private.
    pub fn is_private_any(&self, range: Range) -> bool {
        !range.is_disjoint(&self.private)
    }

    /// Returns `true` if all data in the range is blind.
    pub fn is_blind(&self, range: Range) -> bool {
        range.is_subset(&self.blind)
    }

    /// Returns `true` if any data in the range is blind.
    pub fn is_blind_any(&self, range: Range) -> bool {
        !range.is_disjoint(&self.blind)
    }

    /// Sets the range as public.
    pub fn set_public(&mut self, range: Range) {
        let range = range;
        self.public |= &range;
        self.visible |= &range;
        self.uninit -= &range;
        self.private -= &range;
        self.blind -= &range;
    }

    /// Sets the range as private.
    pub fn set_private(&mut self, range: Range) {
        let range = range;
        self.private |= &range;
        self.visible |= &range;
        self.uninit -= &range;
        self.public -= &range;
        self.blind -= &range;
    }

    /// Sets the range as blind.
    pub fn set_blind(&mut self, range: Range) {
        let range = range;
        self.blind |= &range;
        self.visible -= &range;
        self.uninit -= &range;
        self.public -= &range;
        self.private -= &range;
    }

    /// Returns an iterator over the public ranges.
    pub fn iter_public(&self) -> impl Iterator<Item = Range> + '_ {
        self.public.iter_ranges()
    }

    /// Returns an iterator over the private ranges.
    pub fn iter_private(&self) -> impl Iterator<Item = Range> + '_ {
        self.private.iter_ranges()
    }

    /// Returns an iterator over the blind ranges.
    pub fn iter_blind(&self) -> impl Iterator<Item = Range> + '_ {
        self.blind.iter_ranges()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_view() {
        let mut view = VisibilityView::new();
        view.alloc(30);

        assert!(!view.is_set(0..10));
        assert!(!view.is_set_any(0..10));

        view.set_public(0..10);
        view.set_private(10..20);
        view.set_blind(20..30);

        assert!(view.is_public(0..10));
        assert!(view.is_private(10..20));
        assert!(view.is_blind(20..30));
    }

    #[test]
    fn test_mutually_exclusive() {
        let mut view = VisibilityView::new();

        view.set_public(0..10);
        view.set_private(5..15);

        assert!(view.is_public(0..5));
        assert!(view.is_private(5..15));

        view.set_blind(5..10);

        assert!(view.is_blind(5..10));
        assert!(!view.is_public(0..10));
        assert!(!view.is_private(5..15));
    }
}
