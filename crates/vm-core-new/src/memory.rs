use rangeset::{ops::Set, set::RangeSet};

use crate::{Trap, VmError};

/// Maximum memory size in pages (64 KiB each).
/// 65536 pages = 4 GiB, which is the WebAssembly 32-bit address space limit.
const MAX_MEMORY_PAGES: u64 = 65536;

/// Linear memory that tracks clear (plaintext) bytes and which regions are
/// symbolic.
///
/// Clear values are stored in a Vec<u8>. Symbolic value storage is handled
/// externally. This structure tracks which byte ranges are symbolic vs clear.
#[derive(Debug, Clone)]
pub struct Memory {
    max_size: Option<u64>,
    /// Storage for clear (plaintext) bytes
    data: Vec<u8>,
    /// Ranges of addresses that contain symbolic values
    symbol_ranges: RangeSet<u32>,
}

impl Memory {
    /// Create a new memory with the specified initial size in pages (64 KiB
    /// each). Returns an error if the requested size exceeds the 4 GiB limit.
    pub fn new(initial_pages: u64, max_size: Option<u64>) -> Result<Self, VmError> {
        // Enforce hard limit of 4 GiB
        if initial_pages > MAX_MEMORY_PAGES {
            return Err(VmError::Unsupported(
                "memory size exceeds 4 GiB limit".to_string(),
            ));
        }
        let size = (initial_pages as usize) * 65536; // 64 KiB per page
        Ok(Self {
            max_size,
            data: vec![0; size],
            symbol_ranges: RangeSet::default(),
        })
    }

    /// Get the size of memory in bytes
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Check if memory is empty
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Get a slice of the memory data
    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }

    /// Get a mutable slice of the memory data
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data
    }

    /// Write clear bytes to memory
    pub fn write_clear(&mut self, addr: u32, data: &[u8]) -> Result<(), VmError> {
        let start = addr as usize;
        let end = start + data.len();

        if end > self.data.len() {
            return Err(Trap::MemoryOutOfBounds.into());
        }

        self.data[start..end].copy_from_slice(data);

        // Mark this range as clear (remove from symbolic)
        let range_end = addr + data.len() as u32;
        self.symbol_ranges.difference_mut(addr..range_end);

        Ok(())
    }

    /// Read clear bytes from memory
    pub fn read_clear(&self, addr: u32, len: usize) -> Result<&[u8], VmError> {
        let start = addr as usize;
        let end = start + len;

        if end > self.data.len() {
            return Err(Trap::MemoryOutOfBounds.into());
        }

        // Check if there are any symbolic values in this range
        let range_end = addr + len as u32;
        if !self.symbol_ranges.is_disjoint(addr..range_end) {
            return Err(VmError::SymbolicOperation);
        }

        Ok(&self.data[start..end])
    }

    /// Check if a byte at the given address is symbolic
    pub fn is_symbol(&self, addr: u32) -> bool {
        self.symbol_ranges.contains(&addr)
    }

    /// Check if any bytes in a range are symbolic
    pub fn has_symbol_in_range(&self, addr: u32, len: usize) -> bool {
        let range_end = addr + len as u32;
        !self.symbol_ranges.is_disjoint(addr..range_end)
    }

    /// Mark a range of bytes as symbolic
    pub fn mark_symbol(&mut self, addr: u32, len: usize) -> Result<(), VmError> {
        let start = addr as usize;
        if start + len > self.data.len() {
            return Err(Trap::MemoryOutOfBounds.into());
        }

        let range_end = addr + len as u32;
        self.symbol_ranges.union_mut(addr..range_end);

        Ok(())
    }

    /// Mark a range of bytes as clear
    pub fn mark_clear(&mut self, addr: u32, len: usize) -> Result<(), VmError> {
        let start = addr as usize;
        if start + len > self.data.len() {
            return Err(Trap::MemoryOutOfBounds.into());
        }

        let range_end = addr + len as u32;
        self.symbol_ranges.difference_mut(addr..range_end);

        Ok(())
    }

    /// Grow memory by the specified number of pages
    /// Returns the previous size in pages, or an error if growth fails
    pub fn grow(&mut self, delta_pages: u32) -> Result<u32, VmError> {
        let current_pages = (self.data.len() / 65536) as u32;
        let new_size = self.data.len() + (delta_pages as usize * 65536);

        // WebAssembly spec: memory can grow up to 2^16 pages (4 GiB)
        if new_size > (1 << 16) * 65536 {
            return Err(Trap::MemoryOutOfBounds.into());
        }

        if let Some(max) = self.max_size {
            if new_size as u64 > max * 65536 {
                return Err(Trap::MemoryOutOfBounds.into());
            }
        }

        self.data.resize(new_size, 0);
        Ok(current_pages)
    }

    /// Get the current size in pages (64 KiB each)
    pub fn size_pages(&self) -> u32 {
        (self.data.len() / 65536) as u32
    }

    /// Fill a region of memory with a byte value.
    pub fn fill(&mut self, dest: usize, val: u8, size: usize) -> Result<(), VmError> {
        let end = dest.checked_add(size).ok_or(Trap::MemoryOutOfBounds)?;
        if end > self.data.len() {
            return Err(Trap::MemoryOutOfBounds.into());
        }
        self.data[dest..end].fill(val);
        // Mark range as clear
        self.symbol_ranges
            .difference_mut(dest as u32..(dest + size) as u32);
        Ok(())
    }

    /// Copy a region of memory to another location.
    pub fn copy(&mut self, dest: usize, src: usize, size: usize) -> Result<(), VmError> {
        let src_end = src.checked_add(size).ok_or(Trap::MemoryOutOfBounds)?;
        let dest_end = dest.checked_add(size).ok_or(Trap::MemoryOutOfBounds)?;
        if src_end > self.data.len() || dest_end > self.data.len() {
            return Err(Trap::MemoryOutOfBounds.into());
        }
        self.data.copy_within(src..src_end, dest);
        // TODO: properly track symbolic regions through copy
        Ok(())
    }

    /// Write bytes to memory at the given address.
    pub fn write(&mut self, addr: usize, data: &[u8]) -> Result<(), VmError> {
        let end = addr
            .checked_add(data.len())
            .ok_or(Trap::MemoryOutOfBounds)?;
        if end > self.data.len() {
            return Err(Trap::MemoryOutOfBounds.into());
        }
        self.data[addr..end].copy_from_slice(data);
        // Mark range as clear
        self.symbol_ranges
            .difference_mut(addr as u32..(addr + data.len()) as u32);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memory_creation() {
        let mem = Memory::new(1, None).unwrap();
        assert_eq!(mem.len(), 65536); // 1 page = 64 KiB
        assert_eq!(mem.size_pages(), 1);
    }

    #[test]
    fn test_clear_write_read() {
        let mut mem = Memory::new(1, None).unwrap();

        mem.write_clear(0, &[1, 2, 3, 4]).unwrap();
        let bytes = mem.read_clear(0, 4).unwrap();
        assert_eq!(bytes, &[1, 2, 3, 4]);
    }

    #[test]
    fn test_symbol_tracking() {
        let mut mem = Memory::new(1, None).unwrap();

        assert!(!mem.is_symbol(0));

        mem.mark_symbol(0, 4).unwrap();
        assert!(mem.is_symbol(0));
        assert!(mem.is_symbol(1));
        assert!(mem.is_symbol(2));
        assert!(mem.is_symbol(3));
        assert!(!mem.is_symbol(4));
    }

    #[test]
    fn test_clear_overwrites_symbol() {
        let mut mem = Memory::new(1, None).unwrap();

        mem.mark_symbol(0, 4).unwrap();
        assert!(mem.is_symbol(0));

        mem.write_clear(0, &[1, 2, 3, 4]).unwrap();
        assert!(!mem.is_symbol(0));
    }

    #[test]
    fn test_read_clear_with_symbol_fails() {
        let mut mem = Memory::new(1, None).unwrap();

        mem.write_clear(0, &[1, 2, 3, 4, 5, 6, 7, 8]).unwrap();
        mem.mark_symbol(4, 1).unwrap();

        let result = mem.read_clear(0, 8);
        assert!(result.is_err());
    }

    #[test]
    fn test_has_symbol_in_range() {
        let mut mem = Memory::new(1, None).unwrap();

        mem.mark_symbol(10, 4).unwrap();

        assert!(!mem.has_symbol_in_range(0, 10));
        assert!(mem.has_symbol_in_range(0, 11));
        assert!(mem.has_symbol_in_range(10, 4));
        assert!(mem.has_symbol_in_range(12, 10));
        assert!(!mem.has_symbol_in_range(14, 10));
    }

    #[test]
    fn test_memory_grow() {
        let mut mem = Memory::new(1, None).unwrap();
        assert_eq!(mem.size_pages(), 1);

        let prev_size = mem.grow(2).unwrap();
        assert_eq!(prev_size, 1);
        assert_eq!(mem.size_pages(), 3);
        assert_eq!(mem.len(), 3 * 65536);
    }

    #[test]
    fn test_memory_too_large() {
        // Trying to create memory larger than 4 GiB should fail
        assert!(Memory::new(65537, None).is_err());
    }
}
