//! Utilities for MPC protocols

/// Returns the blake3 hash of the given data.
pub fn blake3(data: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Returns non-overlapping slices of the given lengths.
pub fn slices_from_lengths<'a, T>(mut src: &'a [T], lengths: &[usize]) -> Vec<&'a [T]> {
    let mut slices = Vec::with_capacity(lengths.len());
    for &length in lengths {
        let (head, tail) = src.split_at(length);
        slices.push(head);
        src = tail;
    }
    slices
}

/// Returns non-overlapping mutable slices of the given lengths.
pub fn slices_from_lengths_mut<'a, T>(mut src: &'a mut [T], lengths: &[usize]) -> Vec<&'a mut [T]> {
    let mut slices = Vec::with_capacity(lengths.len());
    for &length in lengths {
        let (head, tail) = src.split_at_mut(length);
        slices.push(head);
        src = tail;
    }
    slices
}
