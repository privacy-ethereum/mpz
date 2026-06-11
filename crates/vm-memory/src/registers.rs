//! Sparse register file. Generic over the cell type so it can be
//! reused for non-authenticated state and unit-tested with
//! primitives.

use std::collections::HashMap;

use mpz_vm_core::Reg;

/// Sparse register file keyed by absolute [`Reg`] index. Frame
/// layout is the caller's concern; this type is a typed key/value
/// store, nothing more.
#[derive(Debug, Clone)]
pub struct Registers<T> {
    inner: HashMap<Reg, T>,
}

impl<T> Default for Registers<T> {
    fn default() -> Self {
        Self {
            inner: HashMap::new(),
        }
    }
}

impl<T> Registers<T> {
    pub fn new() -> Self {
        Self::default()
    }

    /// Set (or overwrite) the value at `reg`.
    pub fn set(&mut self, reg: Reg, value: T) {
        self.inner.insert(reg, value);
    }

    /// Borrow the value at `reg`, if any.
    pub fn get(&self, reg: Reg) -> Option<&T> {
        self.inner.get(&reg)
    }

    /// Drop every register whose absolute index falls in
    /// `[base, base + count)`.
    pub fn drop_range(&mut self, base: Reg, count: u32) {
        let end = base.saturating_add(count);
        self.inner.retain(|&r, _| r < base || r >= end);
    }
}

impl<T: Clone> Registers<T> {
    /// Copy `src`'s value to `dst`. No-op if `src` has no value.
    pub fn copy(&mut self, dst: Reg, src: Reg) {
        if let Some(v) = self.inner.get(&src).cloned() {
            self.inner.insert(dst, v);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_and_get() {
        let mut r: Registers<u32> = Registers::new();
        assert!(r.get(Reg(7)).is_none());
        r.set(Reg(7), 42);
        assert_eq!(r.get(Reg(7)), Some(&42));
        r.set(Reg(7), 99);
        assert_eq!(r.get(Reg(7)), Some(&99));
    }

    #[test]
    fn copy_from_missing_is_noop() {
        let mut r: Registers<u32> = Registers::new();
        r.set(Reg(2), 5);
        r.copy(Reg(2), Reg(1)); // src missing
        assert_eq!(r.get(Reg(2)), Some(&5));
        assert!(r.get(Reg(1)).is_none());
    }

    #[test]
    fn drop_range_is_half_open() {
        let mut r: Registers<u32> = Registers::new();
        for i in 0..10 {
            r.set(Reg(i), i * 10);
        }
        r.drop_range(Reg(3), 4); // drops 3,4,5,6
        for i in 0..3 {
            assert_eq!(r.get(Reg(i)), Some(&(i * 10)), "kept {i}");
        }
        for i in 3..7 {
            assert!(r.get(Reg(i)).is_none(), "dropped {i}");
        }
        for i in 7..10 {
            assert_eq!(r.get(Reg(i)), Some(&(i * 10)), "kept {i}");
        }
    }

    #[test]
    fn drop_range_zero_count() {
        let mut r: Registers<u32> = Registers::new();
        r.set(Reg(5), 50);
        r.drop_range(Reg(5), 0);
        assert_eq!(r.get(Reg(5)), Some(&50));
    }
}
