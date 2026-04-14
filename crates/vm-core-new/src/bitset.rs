use rangeset::prelude::*;

/// Tracks which byte ranges in linear memory are symbolic.
#[derive(Debug, Default, Clone)]
pub(crate) struct BitSet(RangeSet<u32>);

impl BitSet {
    pub fn new() -> Self {
        Self(RangeSet::default())
    }

    /// Copies `len` bits from `src` to `dest`.
    pub fn copy(&mut self, src: u32, dest: u32, len: usize) {
        let mut copy = self.0.intersection(src..src + len as u32).into_set();
        if dest >= src {
            copy.shift_right(&(dest - src));
        } else {
            copy.shift_left(&(src - dest));
        }
        self.0.difference_mut(dest..dest + len as u32);
        self.0.union_mut(copy);
    }

    pub fn insert(&mut self, addr: u32) {
        self.0.union_mut(addr..addr + 1);
    }

    pub fn insert_range(&mut self, addr: u32, len: usize) {
        self.0.union_mut(addr..addr + len as u32);
    }

    pub fn remove(&mut self, addr: u32) {
        self.0.difference_mut(addr..addr + 1);
    }

    pub fn remove_range(&mut self, addr: u32, len: usize) {
        self.0.difference_mut(addr..addr + len as u32);
    }

    pub fn contains(&self, addr: u32) -> bool {
        self.0.contains(&addr)
    }

    /// Returns `true` if any of the range is set.
    pub fn contains_any(&self, addr: u32, len: usize) -> bool {
        !self.0.is_disjoint(addr..addr + len as u32)
    }

    pub fn compute_mask(&self, addr: u32, len: u32) -> u8 {
        let mut mask = 0u8;
        for i in 0..len {
            if self.contains(addr + i) {
                mask |= 1 << i;
            }
        }
        mask
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_copy() {
        let mut a = BitSet(RangeSet::from([0..4, 6..8]));
        a.copy(0, 10, 10);
        assert_eq!(a.0, RangeSet::from([0..4, 6..8, 10..14, 16..18]));

        let mut a = BitSet(RangeSet::from([0..4, 6..8]));
        a.copy(0, 5, 10);
        assert_eq!(a.0, RangeSet::from([0..4, 5..9, 6..8, 11..13]));

        let mut a = BitSet(RangeSet::from([10..14, 16..18]));
        a.copy(10, 0, 10);
        assert_eq!(a.0, RangeSet::from([0..4, 6..8, 10..14, 16..18]));
    }
}
