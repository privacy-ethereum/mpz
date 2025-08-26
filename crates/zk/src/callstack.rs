use mpz_vm_core::{Call, memory::Slice};
use std::slice::Iter;

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

    /// Returns the ready calls based on the provided predicate.
    ///
    /// # Arguments
    ///
    /// * `soft_limit` - Calls will stop being yielded after this limit of AND
    ///   gates is met or exceeded.
    /// * `f` - Predicate determining whether a call is ready.
    pub(crate) fn extract_if<F>(
        &mut self,
        soft_limit: usize,
        mut f: F,
    ) -> impl Iterator<Item = (Call, Slice)>
    where
        F: FnMut(&Call) -> bool,
    {
        let mut total = 0;
        let mut limit = false;

        let (inner, and_count) = (&mut self.inner, &mut self.and_count);

        inner.extract_if(.., move |(call, _)| {
            if !limit && f(call) {
                let andc = call.circ().and_count();
                *and_count -= andc;
                total += andc;
                limit = total >= soft_limit;

                true
            } else {
                false
            }
        })
    }

    pub(crate) fn push(&mut self, value: (Call, Slice)) {
        self.and_count += value.0.circ().and_count();
        self.inner.push(value);
    }

    pub(crate) fn and_count(&self) -> usize {
        self.and_count
    }
}
