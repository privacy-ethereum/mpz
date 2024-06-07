//! Model module.
//!
//! This module contains the main traits and structures used to represent the circuits.

/// A `Component` defines a block with inputs and outputs.
pub trait Component {
    /// Returns an iterator over the input node indices.
    fn get_inputs(&self) -> impl Iterator<Item = &Node<u32>>;

    /// Returns an iterator over the output node indices.
    fn get_outputs(&self) -> impl Iterator<Item = &Node<u32>>;
}

/// A circuit node, holds a generic type identifier.
#[derive(Debug, Eq, PartialEq)]
pub struct Node<T> {
    pub(crate) id: T,
}

impl<T> Node<T> {
    /// Creates a new node with the given identifier.
    pub fn new(id: T) -> Self {
        Self { id }
    }
}
