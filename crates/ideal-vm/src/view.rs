use mpz_memory_core::{Slice, View as ViewTrait, binary::Binary, view::VisibilityView};
use rangeset::{Disjoint, Intersection, Subset};
use serde::{Deserialize, Serialize};

type Range = std::ops::Range<usize>;
type RangeSet = rangeset::RangeSet<usize>;
type Result<T, E = ViewError> = core::result::Result<T, E>;

#[derive(Debug, Default)]
struct InputView {
    /// Ranges which have been assigned.
    assigned: RangeSet,
    /// Ranges which are fully committed in both parties views.
    complete: RangeSet,
    /// All input ranges.
    all: RangeSet,
}

#[derive(Debug, Default)]
struct OutputView {
    /// Output ranges which are executed.
    complete: RangeSet,
    /// All output ranges.
    all: RangeSet,
}

/// Information on the content of the expected flushes.
#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
pub struct FlushView {
    /// Ranger for which the peer is to send their inputs.
    pub(crate) peer_input: RangeSet,
    /// Ranger for which this party is to send their inputs.
    pub(crate) input: RangeSet,
}

impl FlushView {
    /// Returns the expected flush size in bytes for this party.
    pub fn flush_size(&self) -> usize {
        self.input.len().div_ceil(8) + 1024
    }

    /// Returns the expected flush size in bytes for the peer.
    pub fn peer_flush_size(&self) -> usize {
        self.peer_input.len().div_ceil(8) + 1024
    }

    /// Returns `true` if the flush state is empty.
    pub(crate) fn is_empty(&self) -> bool {
        self.peer_input.is_empty() && self.input.is_empty()
    }

    /// Clears the flush state.
    fn clear(&mut self) {
        self.peer_input.clear();
        self.input.clear();
    }
}

#[derive(Debug)]
pub(crate) struct View {
    len: usize,
    input: InputView,
    output: OutputView,
    vis: VisibilityView,
    flush: FlushView,
}

impl View {
    pub(crate) fn new() -> Self {
        Self {
            len: 0,
            input: InputView::default(),
            output: OutputView::default(),
            vis: VisibilityView::new(),
            flush: FlushView::default(),
        }
    }

    pub(crate) fn is_alloc(&self, range: Range) -> bool {
        range.end <= self.len
    }

    fn alloc(&mut self, size: usize) -> Range {
        let range = self.len..self.len + size;
        self.len += size;
        self.vis.alloc(size);
        range
    }

    pub(crate) fn wants_flush(&self) -> bool {
        !self.flush.is_empty()
    }

    pub(crate) fn flush(&self) -> &FlushView {
        &self.flush
    }

    pub(crate) fn alloc_input(&mut self, size: usize) {
        let range = self.alloc(size);

        self.input.all |= &range;
    }

    pub(crate) fn alloc_output(&mut self, size: usize) {
        let range = self.alloc(size);

        self.output.all |= &range;
    }

    fn mark_public(&mut self, range: Range) -> Result<()> {
        if self.vis.is_set_any(range.clone()) {
            return Err(ErrorRepr::VisibilityAlreadySet { range }.into());
        } else if !range.is_disjoint(&self.output.all) {
            return Err(ErrorRepr::VisibilityOutput { range }.into());
        }

        self.vis.set_public(range);

        Ok(())
    }

    fn mark_private(&mut self, range: Range) -> Result<()> {
        if self.vis.is_set_any(range.clone()) {
            return Err(ErrorRepr::VisibilityAlreadySet { range }.into());
        } else if !range.is_disjoint(&self.output.all) {
            return Err(ErrorRepr::VisibilityOutput { range }.into());
        }

        self.vis.set_private(range);

        Ok(())
    }

    fn mark_blind(&mut self, range: Range) -> Result<()> {
        if self.vis.is_set_any(range.clone()) {
            return Err(ErrorRepr::VisibilityAlreadySet { range }.into());
        } else if !range.is_disjoint(&self.output.all) {
            return Err(ErrorRepr::VisibilityOutput { range }.into());
        }

        self.vis.set_blind(range);

        Ok(())
    }

    pub(crate) fn assign(&mut self, range: Range) -> Result<()> {
        if !self.vis.is_visible(range.clone()) {
            return Err(ErrorRepr::VisibilityAssign { range }.into());
        } else if !range.is_disjoint(&self.output.all) {
            return Err(ErrorRepr::OutputAssign { range }.into());
        }

        self.input.assigned |= range;

        Ok(())
    }

    /// Marks an output range as complete.
    pub(crate) fn set_output(&mut self, range: Range) -> Result<()> {
        // Assert is output.
        if !range.is_subset(&self.output.all) {
            return Err(ErrorRepr::NotOutput { range }.into());
        }

        self.output.complete |= &range;

        Ok(())
    }

    pub(crate) fn is_committed(&self, range: Range) -> bool {
        range.is_subset(&self.input.complete) || range.is_subset(&self.output.complete)
    }

    pub(crate) fn commit(&mut self, range: Range) -> Result<()> {
        // Assert visibility is set.
        if !self.vis.is_set(range.clone()) {
            return Err(ErrorRepr::VisibilityNotSet { range }.into());
        }

        // Assert not output data.
        if !range.is_disjoint(&self.output.all) {
            return Err(ErrorRepr::OutputCommit { range }.into());
        }

        // Assert not committed.
        if !range.is_disjoint(&self.input.complete) {
            return Err(ErrorRepr::AlreadyCommitted { range }.into());
        }

        let blind = range.intersection(self.vis.blind());
        let private = range.intersection(self.vis.private());
        let public = range.intersection(self.vis.public());

        // Assert visible data is assigned.
        if !public.is_subset(&self.input.assigned) || !private.is_subset(&self.input.assigned) {
            return Err(ErrorRepr::NotAssigned { range }.into());
        }

        // Public data is complete immediately.
        self.input.complete |= public;

        self.flush.peer_input |= blind;
        self.flush.input |= private;

        Ok(())
    }

    pub(crate) fn complete_flush(&mut self) {
        self.input.complete |= &self.flush.peer_input;
        self.input.complete |= &self.flush.input;

        self.flush.clear();
    }
}

impl ViewTrait<Binary> for View {
    type Error = ViewError;

    fn mark_public_raw(&mut self, slice: Slice) -> Result<(), Self::Error> {
        self.mark_public(slice.to_range())
    }

    fn mark_private_raw(&mut self, slice: Slice) -> Result<(), Self::Error> {
        self.mark_private(slice.to_range())
    }

    fn mark_blind_raw(&mut self, slice: Slice) -> Result<(), Self::Error> {
        self.mark_blind(slice.to_range())
    }
}

#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub(crate) struct ViewError(#[from] ErrorRepr);

#[derive(Debug, thiserror::Error)]
enum ErrorRepr {
    #[error("visibility not set: {range:?}")]
    VisibilityNotSet { range: Range },
    #[error("visibility already set: {range:?}")]
    VisibilityAlreadySet { range: Range },
    #[error("assigning blind data is not allowed: {range:?}")]
    VisibilityAssign { range: Range },
    #[error("setting visibility of output is not allowed: {range:?}")]
    VisibilityOutput { range: Range },
    #[error("must assign visible data: {range:?}")]
    NotAssigned { range: Range },
    #[error("already committed: {range:?}")]
    AlreadyCommitted { range: Range },
    #[error("assigning to output is not allowed: {range:?}")]
    OutputAssign { range: Range },
    #[error("committing output is not allowed: {range:?}")]
    OutputCommit { range: Range },
    #[error("attempted to treat input as output: {range:?}")]
    NotOutput { range: Range },
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::*;

    #[rstest]
    fn test_assign_blind() {
        let mut view = View::new();

        view.alloc_input(10);
        view.mark_blind(0..10).unwrap();
        let err = view.assign(0..10).unwrap_err().0;

        assert!(matches!(err, ErrorRepr::VisibilityAssign { .. }));
    }

    #[rstest]
    fn test_assign_output() {
        let mut view = View::new();

        view.alloc_output(10);
        // Bypass the visibility guard.
        view.vis.set_public(0..10);

        let err = view.assign(0..10).unwrap_err().0;

        assert!(matches!(err, ErrorRepr::OutputAssign { .. }));
    }

    #[rstest]
    fn test_commit_before_visibility() {
        let mut view = View::new();

        view.alloc_input(10);
        let err = view.commit(0..10).unwrap_err().0;

        assert!(matches!(err, ErrorRepr::VisibilityNotSet { .. }));
    }

    #[rstest]
    fn test_commit_output() {
        let mut view = View::new();

        view.alloc_output(10);
        // Bypass the visibility guard.
        view.vis.set_public(0..10);

        let err = view.commit(0..10).unwrap_err().0;

        assert!(matches!(err, ErrorRepr::OutputCommit { .. }));
    }

    #[rstest]
    fn test_public_commit_not_wants_flush() {
        let mut view = View::new();

        view.alloc_input(10);
        view.mark_public(0..10).unwrap();
        view.assign(0..10).unwrap();
        view.commit(0..10).unwrap();

        assert!(!view.wants_flush());
    }

    #[rstest]
    fn test_private_commit_wants_flush() {
        let mut view = View::new();

        view.alloc_input(10);
        view.mark_private(0..10).unwrap();
        view.assign(0..10).unwrap();
        view.commit(0..10).unwrap();

        assert!(view.wants_flush());
    }

    #[rstest]
    fn test_blind_commit_wants_flush() {
        let mut view = View::new();

        view.alloc_input(10);
        view.mark_blind(0..10).unwrap();
        view.commit(0..10).unwrap();

        assert!(view.wants_flush());
    }
}
