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

/// A `Executable` trait that represents an object that can execute a given function over a memory array.
pub trait Executable<T> {
    type Error;

    /// Executes the given function on memory.
    fn execute<F>(&self, memory: &mut [T], function: F) -> Result<(), Self::Error>
    where
        F: Fn(&Self, &mut [T]) -> Result<(), Self::Error>,
    {
        function(self, memory)
    }
}

/// A `Executor` trait that represents an object that performs a custom execution over an `Executable` object.
pub trait Executor<T, U>
where
    U: Executable<T>,
{
    /// User defined custom execution.
    fn custom_execution(&self, executable: &U, memory: &mut [T]) -> Result<(), U::Error>;

    /// Runs the custom execution in the `Executable`.
    fn run_executable(&self, memory: &mut [T], executable: U) -> Result<(), U::Error> {
        executable.execute(memory, |object: &U, memory: &mut [T]| {
            self.custom_execution(object, memory)
        })
    }
}
