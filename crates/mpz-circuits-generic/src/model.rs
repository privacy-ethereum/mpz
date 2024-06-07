//! Model module.
//!
//! This module contains the main traits and structures used to represent the circuits.

/// A `Component` defines a block with inputs and outputs.
pub trait Component {
    /// Returns an iterator over the input node indices.
    fn get_inputs(&self) -> impl Iterator<Item = &Node>;

    /// Returns an iterator over the output node indices.
    fn get_outputs(&self) -> impl Iterator<Item = &Node>;
}

/// A circuit node, holds a generic type identifier.
#[derive(Debug, Eq, PartialEq)]
pub struct Node {
    pub(crate) id: u32,
}

impl Node {
    /// Creates a new node with the given identifier.
    pub fn new(id: u32) -> Self {
        Self { id }
    }
}
