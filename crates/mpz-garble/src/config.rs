//! Various configuration used in the protocol

/// Role in 2PC.
#[derive(Debug, Clone, Copy, PartialEq)]
#[allow(missing_docs)]
pub enum Role {
    Leader,
    Follower,
}

/// Visibility of a value
#[derive(Debug, Clone, Copy)]
pub enum Visibility {
    /// A value known to all parties
    Public,
    /// A private value known to this party.
    Private,
    /// A private value not known to this party.
    Blind,
}
