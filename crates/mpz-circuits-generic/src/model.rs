//! Model module.
//!
//! This module contains the main traits and structures used to represent the circuits.

/// A `Component` trait that represents a block with inputs and outputs.
pub trait Component {
    /// Returns the input node indices.
    fn get_inputs(&self) -> Vec<usize>;

    /// Returns the output node indices.
    fn get_outputs(&self) -> Vec<usize>;
}
