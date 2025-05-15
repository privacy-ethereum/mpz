use mpz_memory_core::{Slice, View as ViewTrait, binary::Binary, view::VisibilityView};
use serde::{Deserialize, Serialize};
use utils::range::{Difference, Disjoint, Intersection, Subset};

type Range = std::ops::Range<usize>;
type RangeSet = utils::range::RangeSet<usize>;
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
struct AuthInputView {
    /// Ranges which have been assigned.
    assigned: RangeSet,
    /// Ranges which are fully committed in both parties views.
    complete: RangeSet,
    /// All input ranges.
    all: RangeSet,
}

#[derive(Debug, Default)]
struct OutputView {
    /// Output ranges which are preprocessed but not executed.
    preprocessed: RangeSet,
    /// Output ranges which are executed.
    complete: RangeSet,
    /// All output ranges.
    all: RangeSet,
}

#[derive(Debug, Default)]
struct DecodeView {
    /// Ranges which have decode info sent.
    decode_info: RangeSet,
    /// Ranges which have already been decoded.
    complete: RangeSet,
    /// All ranges which are to be decoded.
    all: RangeSet,
}

#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct FlushView {
    /// Ranges for which the garbler is to send MACs.
    pub(crate) macs: RangeSet,
    /// Ranges for which the garbler is to send MACs using oblivious
    /// transfer.
    pub(crate) ot: RangeSet,
    /// Ranges for which the garbler is to send key bits for decoding.
    pub(crate) decode_info: RangeSet,
    /// Ranges for which the evaluator is to prove MACs for decoding.
    pub(crate) decode: RangeSet,
}

impl FlushView {
    /// Returns `true` if the flush state is empty.
    pub(crate) fn is_empty(&self) -> bool {
        self.macs.is_empty()
            && self.ot.is_empty()
            && self.decode_info.is_empty()
            && self.decode.is_empty()
    }

    /// Clears the flush state.
    fn clear(&mut self) {
        self.macs.clear();
        self.ot.clear();
        self.decode_info.clear();
        self.decode.clear();
    }
}

#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct AuthFlushView {

    /// Both send public input masks via COTs. 
    pub(crate) public: RangeSet,
    /// Both send Gen input masks via COTs. 
    pub(crate) gen_masks: RangeSet,
    /// Both send Eval input masks via COTs. 
    pub(crate) eval_masks: RangeSet,
    /// Eval sends share and MACs for gen's inputs.
    pub(crate) gen_reveal: RangeSet,
    /// Gen sends share and MACs for eval's inputs.
    pub(crate) eval_reveal: RangeSet,
    /// Both reveal shares of public inputs, which is then verified by the other party. 
    pub(crate) public_decode: RangeSet,
    /// Gen sends masked input labels to Eval.
    pub(crate) labels: RangeSet,
    /// Eval sends output labels to Gen to authenticate masked output
    pub(crate) decode_info: RangeSet,
    /// Both send MACs for decoding gen input/output
    pub(crate) gen_decode: RangeSet,
    /// Both send MACs for decoding eval input/output
    pub(crate) eval_decode: RangeSet,
}

impl AuthFlushView {
    /// Returns `true` if the flush state is empty.
    pub(crate) fn is_empty(&self) -> bool {
        self.public.is_empty()
            && self.gen_masks.is_empty()
            && self.eval_masks.is_empty()
            && self.gen_reveal.is_empty()
            && self.eval_reveal.is_empty()
            && self.public_decode.is_empty()
            && self.labels.is_empty()
            && self.decode_info.is_empty()
            && self.gen_decode.is_empty()
            && self.eval_decode.is_empty()
    }

    /// Clears the flush state.
    fn clear(&mut self) {
        self.public.clear();
        self.gen_masks.clear();
        self.eval_masks.clear();
        self.gen_reveal.clear();
        self.eval_reveal.clear();
        self.public_decode.clear();
        self.labels.clear();
        self.decode_info.clear();
        self.gen_decode.clear();
        self.eval_decode.clear();
    }
}

#[derive(Debug, Clone, Copy)]
enum Role {
    Garbler,
    Evaluator,
}

#[derive(Debug)]
pub(crate) struct View {
    role: Role,
    len: usize,
    input: InputView,
    output: OutputView,
    vis: VisibilityView,
    decode: DecodeView,
    flush: FlushView,
}

impl View {
    pub(crate) fn new_garbler() -> Self {
        Self {
            role: Role::Garbler,
            len: 0,
            input: InputView::default(),
            output: OutputView::default(),
            vis: VisibilityView::new(),
            decode: DecodeView::default(),
            flush: FlushView::default(),
        }
    }

    pub(crate) fn new_evaluator() -> Self {
        Self {
            role: Role::Evaluator,
            len: 0,
            input: InputView::default(),
            output: OutputView::default(),
            vis: VisibilityView::new(),
            decode: DecodeView::default(),
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

    /// Marks an output range as preprocessed.
    pub(crate) fn set_preprocessed(&mut self, range: Range) -> Result<()> {
        // Assert is output.
        if !range.is_subset(&self.output.all) {
            return Err(ErrorRepr::NotOutput { range }.into());
        }

        self.output.preprocessed |= &range;
        // If marked for decoding, transfer decode info.
        self.flush.decode_info |= range.intersection(&self.decode.all) - &self.decode.complete;

        Ok(())
    }

    /// Marks an output range as complete.
    pub(crate) fn set_output(&mut self, range: Range) -> Result<()> {
        // Assert is output.
        if !range.is_subset(&self.output.all) {
            return Err(ErrorRepr::NotOutput { range }.into());
        }

        self.output.preprocessed |= &range;
        self.output.complete |= &range;
        // If marked for decoding, transfer decode info.
        self.flush.decode_info |= range.intersection(&self.decode.all) - &self.decode.decode_info;
        // If decoding info transferred, prove MACs.
        self.flush.decode |= range.intersection(&self.decode.decode_info) - &self.decode.complete;

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

        match self.role {
            Role::Garbler => {
                // Send MACs for visible data.
                self.flush.macs |= public | private;
                // Send MACs with OT for blind data.
                self.flush.ot |= blind;
            }
            Role::Evaluator => {
                // Receive MACs for public and blind data.
                self.flush.macs |= public | blind;
                // Receive MACs with OT for private data.
                self.flush.ot |= private;
            }
        }

        Ok(())
    }

    pub(crate) fn decode(&mut self, range: Range) -> Result<()> {
        // Ignore already decoded data.
        let undecoded = range.difference(&self.decode.complete);
        if undecoded.is_empty() {
            return Ok(());
        }

        self.decode.all |= &undecoded;

        let input = range.intersection(&self.input.all);
        let output = range.intersection(&self.output.all);

        // Transfer decode info.
        //
        // Only send decode info for output data and garbler's inputs.
        let decodable_input = match self.role {
            Role::Garbler => input.intersection(self.vis.private()),
            Role::Evaluator => input.intersection(self.vis.blind()),
        };

        self.flush.decode_info |= decodable_input | output.intersection(&self.output.preprocessed);

        // Prove MACs.
        //
        // Only prove MACs for output data and evaluator's inputs.
        let provable_input = match self.role {
            Role::Garbler => input - self.vis.visible(),
            Role::Evaluator => input.intersection(self.vis.private()),
        };

        self.flush.decode |= provable_input.intersection(&self.input.complete)
            | output.intersection(&self.output.complete);

        Ok(())
    }

    pub(crate) fn complete_flush(&mut self, view: FlushView) {
        self.input.complete |= view.macs;
        self.input.complete |= &view.ot;
        self.decode.decode_info |= &view.decode_info;
        self.decode.complete |= view.decode;

        self.flush.clear();

        // Decode evaluator inputs if they are ready.
        self.flush.decode |= view.ot.intersection(&self.decode.all);
        // Decode outputs if they are ready.
        self.flush.decode |= view
            .decode_info
            .intersection(&self.output.complete)
            .difference(&self.decode.complete);
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

#[derive(Debug)]
pub(crate) struct AuthView {
    role: Role,
    len: usize,
    input: AuthInputView,
    output: OutputView,
    vis: VisibilityView,
    decode: DecodeView,
    flush: AuthFlushView,
}

impl AuthView {
    pub(crate) fn new_generator() -> Self {
        Self {
            role: Role::Garbler,
            len: 0,
            input: AuthInputView::default(),
            output: OutputView::default(),
            vis: VisibilityView::new(),
            decode: DecodeView::default(),
            flush: AuthFlushView::default(),
        }
    }

    pub(crate) fn new_evaluator() -> Self {
        Self {
            role: Role::Evaluator,
            len: 0,
            input: AuthInputView::default(),
            output: OutputView::default(),
            vis: VisibilityView::new(),
            decode: DecodeView::default(),
            flush: AuthFlushView::default(),
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

    pub(crate) fn flush(&self) -> &AuthFlushView {
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

    /// Marks an output range as preprocessed.
    pub(crate) fn set_preprocessed(&mut self, range: Range) -> Result<()> {
        // Assert is output.
        if !range.is_subset(&self.output.all) {
            return Err(ErrorRepr::NotOutput { range }.into());
        }

        self.output.preprocessed |= &range;

        Ok(())
    }

    /// Marks an output range as complete.
    pub(crate) fn set_output(&mut self, range: Range) -> Result<()> {
        // Assert is output.
        if !range.is_subset(&self.output.all) {
            return Err(ErrorRepr::NotOutput { range }.into());
        }

        self.output.preprocessed |= &range;
        self.output.complete |= &range;
        
        // Eval sends labels to gen to authenticate masked outputs, flush handles sending decode (bit,mac) afterwards 
        self.flush.decode_info |= range.intersection(&self.decode.all) - &self.decode.decode_info;

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
        if !public.is_subset(&self.input.assigned) {
            return Err(ErrorRepr::NotAssigned { range }.into());
        } else if !private.is_subset(&self.input.assigned) {
            return Err(ErrorRepr::NotAssigned { range }.into());
        }

        match self.role {
            Role::Garbler => {
                self.flush.public |= public;
                self.flush.gen_masks |= private;
                self.flush.eval_masks |= blind;
            }
            Role::Evaluator => {
                self.flush.public |= public;
                self.flush.gen_masks |= blind;
                self.flush.eval_masks |= private;
            }
        }

        Ok(())
    }

    pub(crate) fn decode(&mut self, range: Range) -> Result<()> {
        // Ignore already decoded data.
        let undecoded = range.difference(&self.decode.complete);
        if undecoded.is_empty() {
            return Ok(());
        }

        self.decode.all |= &undecoded;


        // CHECK: This seems redundant.
        // Just adding everything to undecoded works fine.
        // All other ranges are set in complete_flush as and when they are ready, and you would never call decode after flushing.

        let input = range.intersection(&self.input.complete);
        let gen_decode_input = match self.role {
            Role::Garbler => input.intersection(self.vis.private()),
            Role::Evaluator => input.intersection(self.vis.blind()),
        };
        let eval_decode_input = match self.role {
            Role::Garbler => input.intersection(self.vis.blind()),
            Role::Evaluator => input.intersection(self.vis.private()),
        };

        let output = range.intersection(&self.output.complete);
        self.flush.decode_info |= &output;
        self.flush.gen_decode |= gen_decode_input;
        self.flush.eval_decode |= eval_decode_input;

        Ok(())
    }

    pub(crate) fn complete_flush(&mut self, view: AuthFlushView) {
        self.input.complete |= &view.gen_reveal;
        self.input.complete |= &view.eval_reveal;
        self.input.complete |= &view.public_decode;

        self.decode.decode_info |= view.decode_info.clone();
        self.decode.complete |= view.gen_decode.clone() | view.eval_decode.clone();

        self.flush.clear();

        // Reveal opposite shares for inputs whose auth bits have been set, send own half masked inputs, check opposite shares.
        self.flush.gen_reveal |= view.gen_masks;
        self.flush.eval_reveal |= view.eval_masks;
        self.flush.public_decode |= view.public;

        // send masked labels, can be done in parallel with decode info
        self.flush.labels |= view.gen_reveal.clone() | view.eval_reveal.clone() | view.public_decode.clone();

        // Send decode info for inputs / outputs
        self.flush.gen_decode |= (view.gen_reveal | view.decode_info.clone()).intersection(&self.decode.all) - &self.decode.complete;
        self.flush.eval_decode |= (view.eval_reveal | view.decode_info.clone()).intersection(&self.decode.all) - &self.decode.complete;
    }
}

impl ViewTrait<Binary> for AuthView {
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

    fn new(role: Role) -> View {
        match role {
            Role::Garbler => View::new_garbler(),
            Role::Evaluator => View::new_evaluator(),
        }
    }

    #[rstest]
    #[case::garbler(Role::Garbler)]
    #[case::evaluator(Role::Evaluator)]
    fn test_assign_blind(#[case] role: Role) {
        let mut view = new(role);

        view.alloc_input(10);
        view.mark_blind(0..10).unwrap();
        let err = view.assign(0..10).unwrap_err().0;

        assert!(matches!(err, ErrorRepr::VisibilityAssign { .. }));
    }

    #[rstest]
    #[case::garbler(Role::Garbler)]
    #[case::evaluator(Role::Evaluator)]
    fn test_assign_output(#[case] role: Role) {
        let mut view = new(role);

        view.alloc_output(10);
        // Bypass the visibility guard.
        view.vis.set_public(0..10);

        let err = view.assign(0..10).unwrap_err().0;

        assert!(matches!(err, ErrorRepr::OutputAssign { .. }));
    }

    #[rstest]
    #[case::garbler(Role::Garbler)]
    #[case::evaluator(Role::Evaluator)]
    fn test_commit_before_visibility(#[case] role: Role) {
        let mut view = new(role);

        view.alloc_input(10);
        let err = view.commit(0..10).unwrap_err().0;

        assert!(matches!(err, ErrorRepr::VisibilityNotSet { .. }));
    }

    #[rstest]
    #[case::garbler(Role::Garbler)]
    #[case::evaluator(Role::Evaluator)]
    fn test_commit_output(#[case] role: Role) {
        let mut view = new(role);

        view.alloc_output(10);
        // Bypass the visibility guard.
        view.vis.set_public(0..10);

        let err = view.commit(0..10).unwrap_err().0;

        assert!(matches!(err, ErrorRepr::OutputCommit { .. }));
    }

    #[rstest]
    #[case::garbler(Role::Garbler)]
    #[case::evaluator(Role::Evaluator)]
    fn test_public_commit_wants_flush(#[case] role: Role) {
        let mut view = new(role);

        view.alloc_input(10);
        view.mark_public(0..10).unwrap();
        view.assign(0..10).unwrap();
        view.commit(0..10).unwrap();

        assert!(view.wants_flush());
    }

    #[rstest]
    #[case::garbler(Role::Garbler)]
    #[case::evaluator(Role::Evaluator)]
    fn test_private_commit_wants_flush(#[case] role: Role) {
        let mut view = new(role);

        view.alloc_input(10);
        view.mark_private(0..10).unwrap();
        view.assign(0..10).unwrap();
        view.commit(0..10).unwrap();

        assert!(view.wants_flush());
    }

    #[rstest]
    #[case::garbler(Role::Garbler)]
    #[case::evaluator(Role::Evaluator)]
    fn test_blind_commit_wants_flush(#[case] role: Role) {
        let mut view = new(role);

        view.alloc_input(10);
        view.mark_blind(0..10).unwrap();
        view.commit(0..10).unwrap();

        assert!(view.wants_flush());
    }
}
