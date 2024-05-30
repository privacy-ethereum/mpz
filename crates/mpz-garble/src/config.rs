//! Various configuration used in the protocol

use core::fmt;

/// Role in 2PC.
#[derive(Debug, Clone, Copy, PartialEq)]
#[allow(missing_docs)]
pub enum Role {
    Leader,
    Follower,
}

impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Role::Leader => write!(f, "Leader"),
            Role::Follower => write!(f, "Follower"),
        }
    }
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
