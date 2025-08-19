use mpz_vm_core::{Call, memory::Slice};
use std::{ops::RangeBounds, slice::Iter, vec::IntoIter};

#[derive(Debug, Default)]
pub(crate) struct CallStack {
    inner: Vec<(Call, Slice)>,
    /// The total number of AND gates currently in the callstack.
    and_count: usize,
}

impl CallStack {
    pub(crate) fn iter(&self) -> Iter<'_, (Call, Slice)> {
        self.inner.iter()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    pub(crate) fn extract_if<F, R>(&mut self, range: R, filter: F) -> IntoIter<(Call, Slice)>
    where
        F: FnMut(&mut (Call, Slice)) -> bool,
        R: RangeBounds<usize>,
    {
        let extracted = self.inner.extract_if(range, filter).collect::<Vec<_>>();

        let and_gates: usize = extracted.iter().map(|(c, _)| c.circ().and_count()).sum();
        self.and_count -= and_gates;

        extracted.into_iter()
    }

    pub(crate) fn push(&mut self, value: (Call, Slice)) {
        self.and_count += value.0.circ().and_count();
        self.inner.push(value);
    }

    pub(crate) fn and_count(&self) -> usize {
        self.and_count
    }
}
