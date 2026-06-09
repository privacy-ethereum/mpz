use crate::{Error, MaybeTrap, Trap};

const MAX_MEMORY_PAGES: u64 = 65536;

/// A linear memory, a contiguous, byte-addressable array of bytes.
///
/// The memory is organized in 64 KiB pages and may grow up to a hard limit of
/// 4 GiB (2^16 pages), optionally further constrained by a maximum size.
/// Accesses are bounds-checked and signal a [`Trap::MemoryOutOfBounds`] on
/// out-of-bounds access.
#[derive(Debug, Clone)]
pub struct Memory {
    max_size: Option<u64>,
    data: Vec<u8>,
}

impl Memory {
    pub(crate) fn new(initial_pages: u64, max_size: Option<u64>) -> Result<Self, Error> {
        if initial_pages > MAX_MEMORY_PAGES {
            return Err(Error::Unimplemented("memory size exceeds 4 GiB limit"));
        }
        let size = (initial_pages as usize) * 65536;
        Ok(Self {
            max_size,
            data: vec![0; size],
        })
    }

    pub(crate) fn len(&self) -> usize {
        self.data.len()
    }

    /// Writes `data` into this memory starting at byte offset `addr`.
    ///
    /// # Errors
    ///
    /// Returns [`Trap::MemoryOutOfBounds`] if `addr + data.len()` overflows or
    /// the write would extend past the end of this memory.
    pub fn write_bytes(&mut self, addr: u32, data: &[u8]) -> MaybeTrap<()> {
        let start = addr as usize;
        let end = start
            .checked_add(data.len())
            .ok_or(Trap::MemoryOutOfBounds)?;

        if end > self.data.len() {
            return Err(Trap::MemoryOutOfBounds);
        }

        self.data[start..end].copy_from_slice(data);
        Ok(())
    }

    /// Returns a slice of `len` bytes from this memory starting at byte offset
    /// `addr`.
    ///
    /// # Errors
    ///
    /// Returns [`Trap::MemoryOutOfBounds`] if `addr + len` overflows or the
    /// read would extend past the end of this memory.
    pub fn read_bytes(&self, addr: u32, len: usize) -> MaybeTrap<&[u8]> {
        let start = addr as usize;
        let end = start.checked_add(len).ok_or(Trap::MemoryOutOfBounds)?;

        if end > self.data.len() {
            return Err(Trap::MemoryOutOfBounds);
        }

        Ok(&self.data[start..end])
    }

    pub(crate) fn grow(&mut self, delta_pages: u32) -> MaybeTrap<u32> {
        let current_pages = (self.data.len() / 65536) as u32;
        let new_size = self.data.len() + (delta_pages as usize * 65536);

        // WebAssembly spec: memory can grow up to 2^16 pages (4 GiB)
        if new_size as u64 > (1u64 << 16) * 65536 {
            return Err(Trap::MemoryOutOfBounds);
        }

        if let Some(max) = self.max_size {
            if new_size as u64 > max * 65536 {
                return Err(Trap::MemoryOutOfBounds);
            }
        }

        self.data.resize(new_size, 0);
        Ok(current_pages)
    }

    pub(crate) fn size_pages(&self) -> u32 {
        (self.data.len() / 65536) as u32
    }

    pub(crate) fn fill(&mut self, dest: usize, val: u8, size: usize) -> MaybeTrap<()> {
        let end = dest.checked_add(size).ok_or(Trap::MemoryOutOfBounds)?;
        if end > self.data.len() {
            return Err(Trap::MemoryOutOfBounds);
        }
        self.data[dest..end].fill(val);
        Ok(())
    }

    pub(crate) fn copy(&mut self, dest: usize, src: usize, size: usize) -> MaybeTrap<()> {
        let src_end = src.checked_add(size).ok_or(Trap::MemoryOutOfBounds)?;
        let dest_end = dest.checked_add(size).ok_or(Trap::MemoryOutOfBounds)?;
        if src_end > self.data.len() || dest_end > self.data.len() {
            return Err(Trap::MemoryOutOfBounds);
        }
        self.data.copy_within(src..src_end, dest);
        Ok(())
    }

    pub(crate) fn read_i32(&self, addr: u32) -> MaybeTrap<i32> {
        let start = addr as usize;
        let end = start + 4;
        if end > self.data.len() {
            return Err(Trap::MemoryOutOfBounds);
        }
        Ok(i32::from_le_bytes([
            self.data[start],
            self.data[start + 1],
            self.data[start + 2],
            self.data[start + 3],
        ]))
    }

    pub(crate) fn read_i64(&self, addr: u32) -> MaybeTrap<i64> {
        let start = addr as usize;
        let end = start + 8;
        if end > self.data.len() {
            return Err(Trap::MemoryOutOfBounds);
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

    pub(crate) fn read_f32(&self, addr: u32) -> MaybeTrap<f32> {
        self.read_i32(addr).map(|v| f32::from_bits(v as u32))
    }

    pub(crate) fn read_f64(&self, addr: u32) -> MaybeTrap<f64> {
        self.read_i64(addr).map(|v| f64::from_bits(v as u64))
    }

    pub(crate) fn read_i32_partial(&self, addr: u32, len: usize, signed: bool) -> MaybeTrap<i32> {
        let start = addr as usize;
        let end = start + len;
        if end > self.data.len() {
            return Err(Trap::MemoryOutOfBounds);
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

    pub(crate) fn read_i64_partial(&self, addr: u32, len: usize, signed: bool) -> MaybeTrap<i64> {
        let start = addr as usize;
        let end = start + len;
        if end > self.data.len() {
            return Err(Trap::MemoryOutOfBounds);
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
