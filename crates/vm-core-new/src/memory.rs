use crate::{Trap, VmError};

/// Maximum memory size in pages (64 KiB each).
/// 65536 pages = 4 GiB, which is the WebAssembly 32-bit address space limit.
const MAX_MEMORY_PAGES: u64 = 65536;

/// Linear memory for clear (plaintext) bytes.
///
/// Symbolic value tracking is handled by HostState, not here.
#[derive(Debug, Clone)]
pub struct Memory {
    max_size: Option<u64>,
    /// Storage for clear (plaintext) bytes
    data: Vec<u8>,
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

    /// Write bytes to memory.
    pub fn write_bytes(&mut self, addr: u32, data: &[u8]) -> Result<(), VmError> {
        let start = addr as usize;
        let end = start
            .checked_add(data.len())
            .ok_or(Trap::MemoryOutOfBounds)?;

        if end > self.data.len() {
            return Err(Trap::MemoryOutOfBounds.into());
        }

        self.data[start..end].copy_from_slice(data);
        Ok(())
    }

    /// Read bytes from memory.
    pub fn read_bytes(&self, addr: u32, len: usize) -> Result<&[u8], VmError> {
        let start = addr as usize;
        let end = start.checked_add(len).ok_or(Trap::MemoryOutOfBounds)?;

        if end > self.data.len() {
            return Err(Trap::MemoryOutOfBounds.into());
        }

        Ok(&self.data[start..end])
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
    /// Note: Caller must update HostState.symbol_ranges if needed.
    pub fn fill(&mut self, dest: usize, val: u8, size: usize) -> Result<(), VmError> {
        let end = dest.checked_add(size).ok_or(Trap::MemoryOutOfBounds)?;
        if end > self.data.len() {
            return Err(Trap::MemoryOutOfBounds.into());
        }
        self.data[dest..end].fill(val);
        Ok(())
    }

    /// Copy a region of memory to another location.
    /// Note: Caller must update HostState.symbol_ranges if needed.
    pub fn copy(&mut self, dest: usize, src: usize, size: usize) -> Result<(), VmError> {
        let src_end = src.checked_add(size).ok_or(Trap::MemoryOutOfBounds)?;
        let dest_end = dest.checked_add(size).ok_or(Trap::MemoryOutOfBounds)?;
        if src_end > self.data.len() || dest_end > self.data.len() {
            return Err(Trap::MemoryOutOfBounds.into());
        }
        self.data.copy_within(src..src_end, dest);
        Ok(())
    }

    /// Read an i32 from memory.
    pub fn read_i32(&self, addr: u32) -> Result<i32, VmError> {
        let start = addr as usize;
        let end = start + 4;
        if end > self.data.len() {
            return Err(Trap::MemoryOutOfBounds.into());
        }
        Ok(i32::from_le_bytes([
            self.data[start],
            self.data[start + 1],
            self.data[start + 2],
            self.data[start + 3],
        ]))
    }

    /// Read an i64 from memory.
    pub fn read_i64(&self, addr: u32) -> Result<i64, VmError> {
        let start = addr as usize;
        let end = start + 8;
        if end > self.data.len() {
            return Err(Trap::MemoryOutOfBounds.into());
        }
        Ok(i64::from_le_bytes([
            self.data[start],
            self.data[start + 1],
            self.data[start + 2],
            self.data[start + 3],
            self.data[start + 4],
            self.data[start + 5],
            self.data[start + 6],
            self.data[start + 7],
        ]))
    }

    /// Read an f32 from memory.
    pub fn read_f32(&self, addr: u32) -> Result<f32, VmError> {
        self.read_i32(addr).map(|v| f32::from_bits(v as u32))
    }

    /// Read an f64 from memory.
    pub fn read_f64(&self, addr: u32) -> Result<f64, VmError> {
        self.read_i64(addr).map(|v| f64::from_bits(v as u64))
    }

    /// Read a partial i32 (1 or 2 bytes) with sign/zero extension.
    pub fn read_i32_partial(&self, addr: u32, len: usize, signed: bool) -> Result<i32, VmError> {
        let start = addr as usize;
        let end = start + len;
        if end > self.data.len() {
            return Err(Trap::MemoryOutOfBounds.into());
        }
        let val = match (len, signed) {
            (1, true) => self.data[start] as i8 as i32,
            (1, false) => self.data[start] as i32,
            (2, true) => i16::from_le_bytes([self.data[start], self.data[start + 1]]) as i32,
            (2, false) => u16::from_le_bytes([self.data[start], self.data[start + 1]]) as i32,
            _ => unreachable!(),
        };
        Ok(val)
    }

    /// Read a partial i64 (1, 2, or 4 bytes) with sign/zero extension.
    pub fn read_i64_partial(&self, addr: u32, len: usize, signed: bool) -> Result<i64, VmError> {
        let start = addr as usize;
        let end = start + len;
        if end > self.data.len() {
            return Err(Trap::MemoryOutOfBounds.into());
        }
        let val = match (len, signed) {
            (1, true) => self.data[start] as i8 as i64,
            (1, false) => self.data[start] as i64,
            (2, true) => i16::from_le_bytes([self.data[start], self.data[start + 1]]) as i64,
            (2, false) => u16::from_le_bytes([self.data[start], self.data[start + 1]]) as i64,
            (4, true) => i32::from_le_bytes([
                self.data[start],
                self.data[start + 1],
                self.data[start + 2],
                self.data[start + 3],
            ]) as i64,
            (4, false) => u32::from_le_bytes([
                self.data[start],
                self.data[start + 1],
                self.data[start + 2],
                self.data[start + 3],
            ]) as i64,
            _ => unreachable!(),
        };
        Ok(val)
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
    fn test_write_read_bytes() {
        let mut mem = Memory::new(1, None).unwrap();

        mem.write_bytes(0, &[1, 2, 3, 4]).unwrap();
        let bytes = mem.read_bytes(0, 4).unwrap();
        assert_eq!(bytes, &[1, 2, 3, 4]);
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

    #[test]
    fn test_read_i32() {
        let mut mem = Memory::new(1, None).unwrap();
        mem.write_bytes(0, &[0x01, 0x02, 0x03, 0x04]).unwrap();
        assert_eq!(mem.read_i32(0).unwrap(), 0x04030201);
    }

    #[test]
    fn test_read_i64() {
        let mut mem = Memory::new(1, None).unwrap();
        mem.write_bytes(0, &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08])
            .unwrap();
        assert_eq!(mem.read_i64(0).unwrap(), 0x0807060504030201);
    }

    #[test]
    fn test_read_f32() {
        let mut mem = Memory::new(1, None).unwrap();
        let val: f32 = 1.5;
        mem.write_bytes(0, &val.to_le_bytes()).unwrap();
        assert_eq!(mem.read_f32(0).unwrap(), 1.5);
    }

    #[test]
    fn test_read_f64() {
        let mut mem = Memory::new(1, None).unwrap();
        let val: f64 = 1.5;
        mem.write_bytes(0, &val.to_le_bytes()).unwrap();
        assert_eq!(mem.read_f64(0).unwrap(), 1.5);
    }

    #[test]
    fn test_read_i32_partial_8bit() {
        let mut mem = Memory::new(1, None).unwrap();
        mem.write_bytes(0, &[0xFF]).unwrap();
        // Signed: 0xFF as i8 = -1, extended to i32
        assert_eq!(mem.read_i32_partial(0, 1, true).unwrap(), -1);
        // Unsigned: 0xFF as u8 = 255
        assert_eq!(mem.read_i32_partial(0, 1, false).unwrap(), 255);
    }

    #[test]
    fn test_read_i32_partial_16bit() {
        let mut mem = Memory::new(1, None).unwrap();
        mem.write_bytes(0, &[0xFF, 0xFF]).unwrap();
        // Signed: 0xFFFF as i16 = -1
        assert_eq!(mem.read_i32_partial(0, 2, true).unwrap(), -1);
        // Unsigned: 0xFFFF as u16 = 65535
        assert_eq!(mem.read_i32_partial(0, 2, false).unwrap(), 65535);
    }

    #[test]
    fn test_read_i64_partial() {
        let mut mem = Memory::new(1, None).unwrap();
        mem.write_bytes(0, &[0xFF, 0xFF, 0xFF, 0xFF]).unwrap();
        // Signed: 0xFFFFFFFF as i32 = -1, extended to i64
        assert_eq!(mem.read_i64_partial(0, 4, true).unwrap(), -1);
        // Unsigned: 0xFFFFFFFF as u32 = 4294967295
        assert_eq!(mem.read_i64_partial(0, 4, false).unwrap(), 4294967295);
    }

    #[test]
    fn test_read_out_of_bounds() {
        let mem = Memory::new(1, None).unwrap(); // 64KB

        // Reading past end should fail
        assert!(mem.read_i32(65536).is_err());
        assert!(mem.read_i64(65536).is_err());
    }
}
