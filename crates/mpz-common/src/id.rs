use core::fmt;

/// A logical thread identifier.
///
/// Every thread is assigned a unique identifier, which can be forked to create a child thread.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ThreadId(Box<[u8]>);

impl Default for ThreadId {
    fn default() -> Self {
        Self(vec![0].into())
    }
}

impl ThreadId {
    /// Creates a new thread ID with the provided ID.
    #[inline]
    pub fn new(id: u8) -> Self {
        Self(vec![id].into())
    }

    /// Returns the thread ID as a byte slice.
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Increments the thread ID, returning `None` if the ID overflows.
    #[inline]
    pub fn increment(&self) -> Option<Self> {
        let mut next = self.clone();

        let id = next.0.last_mut()?;
        *id = id.checked_add(1)?;

        Some(next)
    }

    /// Increments the thread ID in place, returning the original ID if it doesn't overflow.
    #[inline]
    pub fn increment_in_place(&mut self) -> Option<Self> {
        let prev = self.clone();

        let id = self.0.last_mut()?;
        *id = id.checked_add(1)?;

        Some(prev)
    }

    /// Forks the thread ID.
    #[inline]
    pub fn fork(&self) -> Self {
        let mut id = vec![0; self.0.len() + 1];
        id[0..self.0.len()].copy_from_slice(&self.0);

        Self(id.into())
    }
}

impl AsRef<[u8]> for ThreadId {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

/// A simple counter.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Counter(u32);

impl Counter {
    /// Increments the counter in place, returning the previous value.
    pub fn next(&mut self) -> Self {
        let prev = self.0;
        self.0 += 1;
        Self(prev)
    }

    /// Returns the next value without incrementing the counter.
    pub fn peek(&self) -> Self {
        Self(self.0 + 1)
    }
}

impl fmt::Display for Counter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_thread_id() {
        let mut id = ThreadId::new(0);

        assert_eq!(id.as_bytes(), &[0]);
        assert_eq!(id.increment_in_place().unwrap().as_bytes(), &[0]);
        assert_eq!(id.as_bytes(), &[1]);
        assert_eq!(id.increment().unwrap().as_bytes(), &[2]);
        assert_eq!(id.fork().as_bytes(), &[1, 0]);
    }
}
